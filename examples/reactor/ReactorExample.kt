package io.axiam.sdk.examples.reactor

import io.axiam.sdk.Sensitive
import io.axiam.sdk.reactor.RabbitMqReactorTransport
import io.axiam.sdk.reactor.ReactorDecision
import io.axiam.sdk.reactor.ReactorEvent
import io.axiam.sdk.reactor.ReactorEvents
import io.axiam.sdk.reactor.ReactorHandler
import io.axiam.sdk.reactor.ReactorLog
import io.axiam.sdk.reactor.ReactorServeOptions
import io.axiam.sdk.reactor.reactorConnectionFactory
import io.axiam.sdk.reactor.reactorServe
import kotlinx.serialization.json.JsonPrimitive
import java.io.File
import java.util.UUID

/**
 * A working reactor (CONTRACT.md §22): subscribe to hook events on the AMQP bus,
 * decide, and answer allow / deny / mutate under a signed, timeout-bounded,
 * field-allow-listed protocol.
 *
 * This one does two jobs, one per event:
 *
 * - `token.pre_issue` — **enrich**. Adds a cost centre and a department claim
 *   under the `ext.` namespace, which is the entire allow-list for this event.
 *   Nothing outside `ext.` is reachable: a reply setting `sub` is refused by the
 *   server exactly as a forged one is.
 * - `login.post_auth` — **veto or step up**. Denies an embargoed region
 *   outright, and demands MFA for an administrative sign-in. This event is
 *   veto-only, so no patch is possible here at all.
 *
 * What the runtime does for you, before this handler ever runs: rejects
 * `key_version < 2`, verifies the HMAC over the canonical bytes, checks
 * freshness in both directions, and checks the nonce. What it does after: signs
 * the reply with the same tenant subkey and publishes it to the delivery's
 * `reply_to`, with `correlation_id` inside the signed body — which is the field
 * the server actually authenticates.
 *
 * **Throwing is a supported answer.** If your backing service is down, let the
 * exception out: the runtime publishes *nothing*, and the registration's
 * `failure_policy` (`fail_open` for `token.pre_issue`, `fail_closed` for
 * `login.post_auth`) decides what that costs. Returning `allow` because you
 * could not reach your fraud service is how a `fail_closed` setting gets
 * defeated from inside the process that was supposed to honour it.
 *
 * **Register first.** The queue this consumes is declared by the *server*, from
 * a registration made through `POST /api/v1/reactors`. This process never
 * declares or binds anything:
 *
 * ```json
 * POST /api/v1/reactors
 * {
 *   "name": "claims-enricher",
 *   "events": ["token.pre_issue", "login.post_auth"],
 *   "mode": "intercept",
 *   "priority": 10,
 *   "timeout_ms": 500
 * }
 * ```
 *
 * Omitting `failure_policy` there gives the strictest default among the events
 * named — `fail_closed`, because this registration can veto a login.
 *
 * Run:
 * ```
 * AXIAM_AMQP_URI=amqps://broker:5671 \
 * AXIAM_TENANT_ID=... AXIAM_REACTOR_ID=... AXIAM_AMQP_SUBKEY_HEX=... \
 * ./gradlew runReactorExample
 * ```
 */
object ReactorExample {

    private const val EMBARGOED_REGION = "KP"

    @JvmStatic
    fun main(args: Array<String>) {
        // §8b: amqps:// only, and `reactorConnectionFactory` enforces that rather
        // than documenting it. HMAC gives authenticity across broker hops; it
        // does not give confidentiality, and a reactor reply is an instruction to
        // change a token. There is no verification-skip switch in this SDK and no
        // plaintext fallback — a failed amqps:// connection is an error to
        // surface, not a condition to work around.
        val amqpUri = required("AXIAM_AMQP_URI")
        val tenantId = UUID.fromString(required("AXIAM_TENANT_ID"))
        val reactorId = UUID.fromString(required("AXIAM_REACTOR_ID"))

        // An in-cluster broker's certificate is not issued by a public CA, which
        // is the whole reason nobody needs a bypass switch.
        val customCa = System.getenv("AXIAM_AMQP_CA_PEM")?.let { File(it).readBytes() }

        // §22.12: the tenant AMQP signing key is a credential. Wrapped in
        // Sensitive so it cannot leak through toString() or a reconnect
        // diagnostic. Fetch it from the management API — never hardcode it, and
        // never log it at any level.
        val subkey = Sensitive.of(hexToBytes(required("AXIAM_AMQP_SUBKEY_HEX")))

        val connection = reactorConnectionFactory(amqpUri, customCaPem = customCa).newConnection()
        connection.use {
            val channel = connection.createChannel()
            val options = ReactorServeOptions(
                transport = RabbitMqReactorTransport(channel),
                tenantId = tenantId,
                signingKey = subkey,
                // The queue belongs to THIS registration. The runtime derives it
                // from our own reactor id and consumes it; it declares nothing
                // and binds nothing (§22.1).
                reactorId = reactorId,
                handler = ReactorHandler { event -> decide(event) },
                log = ReactorLog { line -> System.err.println(line) },
            )

            reactorServe(options).use { server ->
                println("axiam reactor serving ${server.queue} — Ctrl+C to stop")
                Runtime.getRuntime().addShutdownHook(Thread { server.close() })
                Thread.currentThread().join()
            }
        }
    }

    /** The decision function. One event in, one of three answers out. */
    private fun decide(event: ReactorEvent): ReactorDecision = when (event.event) {
        ReactorEvents.TOKEN_PRE_ISSUE -> enrichToken(event)
        ReactorEvents.LOGIN_POST_AUTH -> screenLogin(event)
        // A reactor is only ever dispatched events it registered for, so this arm
        // means the registration and the code have drifted. Allow rather than
        // deny: refusing an operation because our own `when` is stale would be an
        // outage caused by a typo.
        else -> ReactorDecision.allow()
    }

    private fun enrichToken(event: ReactorEvent): ReactorDecision {
        val subject = text(event, "sub") ?: return ReactorDecision.allow()

        // An earlier reactor in the chain may already have set claims. This is
        // read-only context: the server merges, later priority winning a
        // contested key, so echoing these back is not how a field is preserved.
        val alreadySet = event.priorPatch()

        val patch = buildMap {
            if (!alreadySet.containsKey("ext.cost_center")) {
                put("ext.cost_center", costCentreFor(subject))
            }
            put("ext.department", "engineering")
        }

        // `ext.` is the whole allow-list here — `sub`, `aud`, `exp`, `scope` and
        // every other standard claim are unreachable, which is the point. Note
        // this SDK never trims a patch for you: a forbidden key is sent as
        // written and refused by the server, so you find out.
        return if (patch.isEmpty()) ReactorDecision.allow() else ReactorDecision.mutate(patch)
    }

    private fun screenLogin(event: ReactorEvent): ReactorDecision {
        if (text(event, "region") == EMBARGOED_REGION) {
            // The reason is audited. A deny with no reason still denies; the
            // reason is for the audit trail, not for the decision.
            return ReactorDecision.deny("sign-in from an embargoed region")
        }

        if (text(event, "is_admin") == "true") {
            // allow + require_mfa: proceed only after step-up. Valid on
            // login.post_auth ONLY — the server refuses it anywhere else before it
            // even looks at the decision. Sticky across the chain: once any
            // reactor demands step-up, no later one can clear it.
            //
            // A SAML or OIDC sign-in has no step-up branch, so this answer FAILS
            // those logins rather than being silently dropped. If your tenant
            // federates, deny here and drive enrolment out of band instead.
            return ReactorDecision.allowRequiringStepUp()
        }

        return ReactorDecision.allow()
    }

    private fun costCentreFor(subject: String): String = (subject.hashCode().mod(100)).toString()

    /**
     * Reads a payload field as text. The payload is a plain JSON object — never a
     * credential, a token or a signing key, because a reactor is told what is
     * being decided, not handed the means to act on it elsewhere.
     */
    private fun text(event: ReactorEvent, field: String): String? =
        (event.payload[field] as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun required(key: String): String =
        System.getenv(key)?.takeIf { it.isNotBlank() }
            ?: error("$key must be set")

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
