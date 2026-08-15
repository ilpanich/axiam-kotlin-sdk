package io.axiam.sdk.reactor

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.Duration.Companion.ZERO
import kotlin.time.toKotlinDuration

/**
 * One hook firing, delivered to a reactor (CONTRACT.md §22.3).
 *
 * An instance only ever reaches a handler *after* [ReactorServer] has rejected
 * `key_version < 2`, verified the MAC, checked freshness and checked the nonce,
 * in that order. A runtime that hands an unverified payload to user code has
 * already lost, so this type is not constructible from an unverified body
 * outside this module.
 *
 * The [payload] never carries a credential, a token or a signing key: a reactor
 * is told what is being decided, not handed the means to act on it elsewhere. It
 * is not sensitive in the §7 sense and must remain readable — a handler that
 * cannot inspect the event cannot decide anything — but it is tenant business
 * data, so this SDK never logs it, and neither should you at `info` level.
 *
 * @property tenantId the tenant this event belongs to; always the tenant this
 *   runtime was configured for.
 * @property event the registry event name, e.g. `token.pre_issue`. Also the
 *   second half of the routing key.
 * @property correlationId the single-use handle for this dispatch, copied into
 *   the reply body by the runtime. Copying it only into the AMQP property
 *   produces a reply the server discards.
 * @property payload the event-specific body.
 * @property timeoutMs how long the server will actually wait for *this*
 *   dispatch. It is inside the signed body, so it cannot be widened in transit.
 * @property keyVersion the §8 envelope version; always at least 2, because a
 *   lower one is refused before anything else about the message is considered.
 * @property nonce the per-message nonce, inside the signed bytes. Not a secret,
 *   and safe to log for correlation.
 * @property issuedAt when the server signed this event, already checked to lie
 *   within the freshness window.
 * @property deadline when this dispatch's window closes. Measured from the
 *   moment the delivery arrived plus [timeoutMs], *not* from [issuedAt]: broker
 *   latency and clock skew both sit between the two, and a deadline derived from
 *   a remote clock would read as already-expired on a reactor whose clock runs
 *   slightly fast.
 */
public class ReactorEvent internal constructor(
    public val tenantId: UUID,
    public val event: String,
    public val correlationId: UUID,
    public val payload: JsonObject,
    public val timeoutMs: Int,
    public val keyVersion: Int,
    public val nonce: UUID,
    public val issuedAt: Instant,
    public val deadline: Instant,
) {

    /**
     * How much of the window is left.
     *
     * @param now the current instant
     * @return the remaining time, or [Duration.ZERO] when the window has already
     *   closed. A handler doing expensive work SHOULD consult this and shed load
     *   rather than answer into a closed window.
     */
    public fun remaining(now: Instant): Duration {
        val left = java.time.Duration.between(now, deadline)
        return if (left.isNegative) ZERO else left.toKotlinDuration()
    }

    /**
     * The accumulated patch from earlier reactors in the chain (§22.3).
     *
     * When an earlier reactor returned a mutation, the server inserts the merged
     * patch into the payload under [REACTOR_PATCH_KEY] before dispatching here,
     * so this reactor decides against the state that will actually be committed.
     *
     * **Read-only context.** Echoing these keys back inside your own patch is
     * not how a field is preserved — the server merges, with later priority
     * winning a contested key.
     *
     * @return the prior patch, or an empty map when this is the first reactor in
     *   the chain (or the only one).
     */
    public fun priorPatch(): Map<String, String> {
        val node = payload[REACTOR_PATCH_KEY] as? JsonObject ?: return emptyMap()
        return node.entries
            .mapNotNull { (key, value) ->
                (value as? JsonPrimitive)?.takeIf { it.isString }?.let { key to it.content }
            }
            .toMap()
    }

    /**
     * The registry spec for [event].
     *
     * @return the spec, or `null` for an event this SDK's registry does not know
     *   — which cannot happen for a server-dispatched event, since an
     *   unregistered event dispatches to nothing.
     */
    public fun spec(): ReactorEventSpec? = ReactorEvents.spec(event)

    /**
     * A short, secret-free description for logs.
     *
     * Deliberately omits [payload]: the nonce and correlation id are not secrets
     * and may be logged for correlation, but the payload is tenant business data.
     */
    override fun toString(): String =
        "ReactorEvent(event=$event, tenant=$tenantId, correlation=$correlationId, " +
            "nonce=$nonce, timeoutMs=$timeoutMs)"

    public companion object {
        /**
         * Payload key under which the server inserts the accumulated patch from
         * earlier reactors in the chain (§22.3).
         */
        public const val REACTOR_PATCH_KEY: String = "_reactor_patch"
    }
}
