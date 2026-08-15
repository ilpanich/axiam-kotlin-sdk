package io.axiam.sdk.reactor

import io.axiam.sdk.Sensitive
import io.axiam.sdk.telemetry.TelemetryEvent
import io.axiam.sdk.telemetry.TelemetryHook
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

/**
 * A reactor's decision function: one event in, one of three answers out
 * (CONTRACT.md §22.10).
 *
 * Invoked only after the runtime has verified the event under §8 v2, so an
 * implementation never sees an unauthenticated payload. It is a `suspend`
 * function so a handler can call the rest of this SDK — a fraud lookup, a
 * `checkAccess` — without blocking a thread by hand.
 *
 * **Throwing produces no reply.** The runtime will not synthesize an `allow` on
 * your behalf — that would override the operator's `fail_closed` setting from
 * inside the library. A handler that throws is a reactor that did not answer,
 * and the registration's `failure_policy` decides what that costs.
 *
 * **Answer inside the window.** [ReactorEvent.timeoutMs] is how long the server
 * will actually wait. A late reply is discarded and the CPU spent producing it
 * was spent for nothing, so a handler doing expensive work should consult
 * [ReactorEvent.remaining] and shed load rather than push on.
 */
public fun interface ReactorHandler {
    /**
     * Decides one event.
     *
     * @param event the verified event
     * @return the decision to sign and publish
     */
    public suspend fun handle(event: ReactorEvent): ReactorDecision
}

/**
 * A fire-and-forget observer of reactor events (`mode: "listen"`, CONTRACT.md
 * §22.5).
 *
 * The server never waits for a listener and never reads a reply, so a listener
 * cannot affect any outcome. That is why this returns `Unit` rather than a
 * [ReactorDecision]: an SDK listener handler MUST NOT publish a reply, and a
 * type that cannot express one is a stronger guarantee than a paragraph saying
 * so.
 *
 * **Write it idempotently.** A redelivery after a broker hiccup is normal. A
 * listener that double-counts is a listener that was assuming exactly-once
 * delivery it was never promised.
 */
public fun interface ReactorListener {
    /**
     * Observes one verified event.
     *
     * @param event the verified event
     */
    public suspend fun observe(event: ReactorEvent)
}

/**
 * Where rejection diagnostics go.
 *
 * A one-method sink rather than a logging-framework dependency, matching the
 * SDK's policy of never choosing a logger for its consumers. Every line handed
 * here is secret-free by construction: the runtime passes the reason and the
 * routing context, never the signing key, never the MAC, and never the payload.
 */
public fun interface ReactorLog {
    /**
     * Records one diagnostic line.
     *
     * @param message the line; already redacted
     */
    public fun warn(message: String)
}

/**
 * Configuration for [reactorServe].
 *
 * Exactly one of [handler] (intercept) or [listener] (observe) must be supplied,
 * and exactly one of [queue] or [reactorId] must name the queue to consume.
 *
 * **The queue is the server's, not yours.** Whichever you use, the runtime only
 * ever *consumes* it. [reactorId] derives `axiam.reactor.q.<tenant>.<id>` from
 * the tenant and reactor id this runtime is configured as, and nothing else.
 *
 * @property transport the broker seam; [RabbitMqReactorTransport] wraps the
 *   RabbitMQ Java client. Its connection MUST have been opened over `amqps://`
 *   with a trusted CA (§8b) — a reactor reply is an instruction to change a
 *   token, and HMAC gives authenticity, not confidentiality.
 * @property tenantId the tenant this reactor is registered in. An event naming
 *   any other tenant is discarded.
 * @property signingKey the tenant's HKDF-derived AMQP subkey — the same key the
 *   server signed the event with. Wrapped in [Sensitive] because it is a
 *   credential (§22.12): it is never logged at any level and never appears in a
 *   reconnect diagnostic. Derive it with [ReactorProtocol.deriveTenantKey] or
 *   fetch it from the management API.
 * @property handler the intercept decision function, or `null` for a listener.
 * @property listener the observe callback, or `null` for an interceptor.
 * @property queue an explicitly named server-declared queue, or `null` to derive
 *   it from [reactorId].
 * @property reactorId this reactor's own registration id, or `null` when [queue]
 *   is given. The runtime will not name a queue for any other reactor.
 * @property log where refusals are reported.
 * @property freshnessSkew the §8 v2 acceptance window applied to `issued_at` in
 *   both directions.
 * @property shutdownGrace how long [ReactorServer.close] waits for in-flight
 *   events to drain.
 * @property clock the clock used for freshness, deadlines and reply timestamps.
 * @property telemetryHook the §19 sink; one `RequestStart`/`RequestEnd` pair per
 *   dispatched event.
 */
public class ReactorServeOptions(
    public val transport: ReactorTransport,
    public val tenantId: UUID,
    public val signingKey: Sensitive<ByteArray>,
    public val handler: ReactorHandler? = null,
    public val listener: ReactorListener? = null,
    public val queue: String? = null,
    public val reactorId: UUID? = null,
    public val log: ReactorLog = ReactorLog { },
    public val freshnessSkew: Duration = ReactorProtocol.DEFAULT_FRESHNESS_SKEW,
    public val shutdownGrace: Duration = 10.seconds,
    public val clock: Clock = Clock.systemUTC(),
    public val telemetryHook: TelemetryHook? = null,
) {
    init {
        require((handler == null) != (listener == null)) {
            "supply exactly one of handler (mode: intercept) or listener (mode: listen)"
        }
        require((queue == null) != (reactorId == null)) {
            "supply exactly one of queue or reactorId"
        }
        require(freshnessSkew.isPositive()) { "freshnessSkew must be positive" }
        require(shutdownGrace.isPositive()) { "shutdownGrace must be positive" }
    }

    /** The server-declared queue this runtime will consume. */
    public val resolvedQueue: String =
        queue ?: ReactorProtocol.queueName(tenantId, requireNotNull(reactorId))
}

/**
 * The §22 reactor runtime: consume the server-declared queue, verify, decide,
 * sign, reply.
 *
 * Start one with [reactorServe]. Per delivery it:
 *
 * 1. rejects `key_version < 2` — before the signature is even computed;
 * 2. verifies the HMAC over the canonical bytes (§22.2: `hmac_signature` present
 *    and `null`);
 * 3. checks `issued_at` against the freshness window, in both directions;
 * 4. checks `nonce` against a seen-set;
 * 5. *then* decodes the payload and calls the handler;
 * 6. signs the reply with the same tenant subkey and publishes it to the
 *    delivery's `reply_to` queue, echoing `correlation_id` both as an AMQP
 *    property and — the one the server authenticates — inside the signed body.
 *
 * A runtime that hands an unverified payload to user code has already lost: the
 * handler will act on it, and "we checked afterwards" is not a check. The
 * handler call site here is unreachable until every gate above has passed.
 *
 * ## Four rules this class holds to
 *
 * 1. **It declares no topology.** [ReactorTransport] has no declare or bind
 *    method at all, so this is a property of the type rather than a discipline.
 * 2. **It fails closed on its own errors.** A handler that throws, or a body it
 *    cannot decode, produces *no reply* — never a synthesized `allow`.
 * 3. **It does not filter a patch.** A handler's patch goes on the wire exactly
 *    as returned, forbidden keys included.
 * 4. **It honours `timeout_ms`.** When the handler returns after the window
 *    closed, the reply is abandoned rather than published late.
 *
 * ## Interaction with §16, §18 and §19
 *
 * **§16 does not apply to a reply.** A correlation is single-use and a late
 * reply is discarded, so re-sending one could only add load to a server that has
 * already moved on. The recovery mechanism for an unanswered dispatch is the
 * registration's `failure_policy`, on the server, not a retry here.
 *
 * **§18:** [close] is idempotent, cancels the consumer so no new delivery
 * starts, and drains what is in flight up to the configured grace period.
 *
 * **§19:** one `RequestStart`/`RequestEnd` pair per dispatched event, with the
 * event name as the path template — a closed set of five values, so it cannot
 * become a cardinality bomb.
 */
public class ReactorServer private constructor(private val options: ReactorServeOptions) : AutoCloseable {

    private val signingKey: ByteArray = options.signingKey.expose()
    private val nonceStore = ReactorNonceStore(options.freshnessSkew * 2)
    private val inFlight = AtomicInteger()
    private val drainLock = Object()

    @Volatile
    private var closed: Boolean = false

    @Volatile
    private var consumerTag: String? = null

    /** The server-declared queue this runtime consumes. */
    public val queue: String get() = options.resolvedQueue

    /** How many events are being handled right now; drains to zero during [close]. */
    public val inFlightCount: Int get() = inFlight.get()

    /** Whether [close] has run. */
    public val isClosed: Boolean get() = closed

    /**
     * Stops serving, deterministically (§18).
     *
     * Cancels the consumer first so no new delivery can start, then waits for
     * in-flight handlers up to [ReactorServeOptions.shutdownGrace]. Idempotent: a
     * concurrent double-close does the work once. It does not close the
     * transport's connection — the caller owns that.
     */
    override fun close() {
        synchronized(drainLock) {
            if (closed) return
            closed = true
        }

        consumerTag?.let { tag ->
            try {
                options.transport.cancel(tag)
            } catch (e: RuntimeException) {
                // A channel already torn down by the broker cannot be cancelled,
                // and failing close() over that would turn a clean shutdown into
                // an exception on the way out.
                options.log.warn("axiam_sdk_reactor: consumer cancel failed during close (${e.javaClass.simpleName})")
            }
        }

        // Wall clock via nanoTime, deliberately not the configured Clock: a test
        // pinning the clock to a fixed instant must not turn the drain into an
        // unbounded wait.
        val deadlineNanos = System.nanoTime() + options.shutdownGrace.inWholeNanoseconds
        synchronized(drainLock) {
            while (inFlight.get() > 0 && System.nanoTime() < deadlineNanos) {
                @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                (drainLock as java.lang.Object).wait(20)
            }
        }
    }

    /**
     * The §22 delivery pipeline.
     *
     * Internal so tests can drive it against synthesized deliveries and a fake
     * transport — every branch below is provable without a broker.
     */
    internal fun onDelivery(delivery: ReactorDelivery) {
        inFlight.incrementAndGet()
        try {
            handle(delivery)
        } finally {
            inFlight.decrementAndGet()
            synchronized(drainLock) {
                @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                (drainLock as java.lang.Object).notifyAll()
            }
        }
    }

    private fun handle(delivery: ReactorDelivery) {
        val transport = options.transport
        if (closed) {
            // Cancelled, but the broker had already pushed this one. Requeue it:
            // the next runtime to attach is entitled to it, and answering after
            // shutdown began would be a reply nobody is waiting on.
            transport.nack(delivery.deliveryTag, requeue = true)
            return
        }

        val received = options.clock.instant()
        val event = verifyAndDecode(delivery, received)
        if (event == null) {
            // Every rejection path has already reported. Nack without requeue: a
            // body that failed §8 v2 will fail it again on redelivery, and its
            // window is closing either way.
            transport.nack(delivery.deliveryTag, requeue = false)
            return
        }

        emit(TelemetryEvent.RequestStart(TELEMETRY_OPERATION, TELEMETRY_METHOD, event.event, 1))
        val started = options.clock.instant()

        val listener = options.listener
        if (listener != null) {
            // §22.5: a listener never publishes a reply, and the server never
            // reads one. Observe and ack.
            val observed = runCatching { runBlocking { listener.observe(event) } }
            if (observed.isFailure) {
                reportHandlerFailure(event, observed.exceptionOrNull())
                emitEnd(event, started, TelemetryEvent.Outcome.FAILURE)
                transport.nack(delivery.deliveryTag, requeue = false)
                return
            }
            emitEnd(event, started, TelemetryEvent.Outcome.SUCCESS)
            transport.ack(delivery.deliveryTag)
            return
        }

        val decided = runCatching { runBlocking { requireNotNull(options.handler).handle(event) } }
        val decision = decided.getOrNull()
        if (decision == null) {
            // §22.10 rule 2: no reply. The operator's failure_policy decides what
            // a crashed handler costs — an SDK that answers `allow` here has
            // overridden a fail_closed setting from inside the library.
            reportHandlerFailure(event, decided.exceptionOrNull())
            emitEnd(event, started, TelemetryEvent.Outcome.FAILURE)
            transport.nack(delivery.deliveryTag, requeue = false)
            return
        }

        // §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent
        // producing it was spent for nothing. Abandon rather than answer into a
        // closed window.
        if (!options.clock.instant().isBefore(event.deadline)) {
            options.log.warn(
                "axiam_sdk_reactor: handler finished after the ${event.timeoutMs} ms window closed " +
                    "for event=${event.event} correlation=${event.correlationId}; abandoning the reply",
            )
            emitEnd(event, started, TelemetryEvent.Outcome.FAILURE)
            transport.ack(delivery.deliveryTag)
            return
        }

        val replyTo = delivery.replyTo
        if (replyTo.isNullOrBlank()) {
            options.log.warn(
                "axiam_sdk_reactor: delivery for event=${event.event} correlation=${event.correlationId} " +
                    "carried no reply_to; publishing NO reply",
            )
            emitEnd(event, started, TelemetryEvent.Outcome.FAILURE)
            transport.ack(delivery.deliveryTag)
            return
        }

        val reply = ReactorProtocol.signedReply(
            signingKey = signingKey,
            correlationId = event.correlationId,
            tenantId = event.tenantId,
            event = event.event,
            decision = decision,
            nonce = UUID.randomUUID(),
            issuedAt = options.clock.instant(),
        )
        transport.publishReply(replyTo, event.correlationId.toString(), reply)
        emitEnd(event, started, TelemetryEvent.Outcome.SUCCESS)
        transport.ack(delivery.deliveryTag)
    }

    /**
     * The §22.3 gate, in order: key version, MAC, freshness, nonce, then decode.
     * Returns `null` — never a partially-trusted event — when any gate refuses.
     */
    private fun verifyAndDecode(delivery: ReactorDelivery, now: Instant): ReactorEvent? {
        val body = delivery.body
        val root: JsonObject = try {
            Json.parseToJsonElement(body.decodeToString()) as? JsonObject
                ?: return reject(delivery, "body is not a JSON object")
        } catch (_: Exception) {
            return reject(delivery, "body is not valid JSON")
        }

        val keyVersion = ReactorProtocol.intField(root, "key_version")
        if (keyVersion == null || keyVersion < ReactorProtocol.MIN_ACCEPTED_KEY_VERSION) {
            return reject(delivery, "key_version below the accepted floor")
        }

        if (!ReactorProtocol.verifyEvent(signingKey, body)) {
            // §8.4: the fact of failure and the routing context, never the
            // received or expected MAC and never the key.
            return reject(delivery, "signature missing or invalid")
        }

        val issuedAtText = ReactorProtocol.stringField(root, "issued_at")
            ?: return reject(delivery, "issued_at missing")
        val issuedAt = try {
            OffsetDateTime.parse(issuedAtText).toInstant()
        } catch (_: DateTimeParseException) {
            return reject(delivery, "issued_at unparseable")
        }
        if (!ReactorProtocol.isFresh(issuedAt, now, options.freshnessSkew)) {
            return reject(delivery, "issued_at outside the freshness window")
        }

        val nonce = ReactorProtocol.parseUuid(ReactorProtocol.stringField(root, "nonce"))
            ?: return reject(delivery, "nonce missing or malformed")
        if (!nonceStore.observe(nonce.toString(), now)) {
            return reject(delivery, "nonce replay")
        }

        val tenantId = ReactorProtocol.parseUuid(ReactorProtocol.stringField(root, "tenant_id"))
            ?: return reject(delivery, "tenant_id missing or malformed")
        if (tenantId != options.tenantId) {
            // Cannot happen through a correctly declared queue, and is exactly
            // the thing worth refusing anyway if it ever does.
            return reject(delivery, "event names a different tenant")
        }

        val correlationId = ReactorProtocol.parseUuid(ReactorProtocol.stringField(root, "correlation_id"))
            ?: return reject(delivery, "correlation_id missing or malformed")

        val event = ReactorProtocol.stringField(root, "event")
        if (event.isNullOrBlank()) {
            return reject(delivery, "event missing")
        }

        val payload = root["payload"] as? JsonObject
            ?: return reject(delivery, "payload missing or not an object")

        val timeoutMs = ReactorProtocol.intField(root, "timeout_ms")
        if (timeoutMs == null || timeoutMs <= 0) {
            return reject(delivery, "timeout_ms missing or out of range")
        }
        val effectiveTimeout = minOf(timeoutMs, ReactorProtocol.CHAIN_CEILING_MS)

        return ReactorEvent(
            tenantId = tenantId,
            event = event,
            correlationId = correlationId,
            payload = payload,
            timeoutMs = effectiveTimeout,
            keyVersion = keyVersion,
            nonce = nonce,
            issuedAt = issuedAt,
            deadline = now.plusMillis(effectiveTimeout.toLong()),
        )
    }

    private fun reject(delivery: ReactorDelivery, reason: String): ReactorEvent? {
        options.log.warn(
            "axiam_sdk_security: reactor event rejected ($reason); no reply will be sent " +
                "(exchange=${ReactorProtocol.EXCHANGE}, routingKey=${delivery.routingKey})",
        )
        return null
    }

    private fun reportHandlerFailure(event: ReactorEvent, cause: Throwable?) {
        options.log.warn(
            "axiam_sdk_reactor: handler threw for event=${event.event} correlation=${event.correlationId}; " +
                "publishing NO reply, the registration's failure_policy applies " +
                "(${cause?.javaClass?.simpleName ?: "no decision"})",
        )
    }

    private fun emitEnd(event: ReactorEvent, started: Instant, outcome: TelemetryEvent.Outcome) {
        val took = java.time.Duration.between(started, options.clock.instant()).toKotlinDuration()
        emit(
            TelemetryEvent.RequestEnd(
                operation = TELEMETRY_OPERATION,
                method = TELEMETRY_METHOD,
                pathTemplate = event.event,
                attempt = 1,
                status = null,
                duration = took,
                outcome = outcome,
            ),
        )
    }

    private fun emit(telemetryEvent: TelemetryEvent) {
        val hook = options.telemetryHook ?: return
        try {
            hook.onEvent(telemetryEvent)
        } catch (e: RuntimeException) {
            // §19.2 rule 2: telemetry is not permitted to fail the dispatch that
            // fired it.
            options.log.warn("axiam_sdk_reactor: telemetry hook threw (${e.javaClass.simpleName})")
        }
    }

    public companion object {
        /** The §19 operation name every reactor telemetry event carries. */
        public const val TELEMETRY_OPERATION: String = "reactorServe"

        /** The §19 "method" label for an AMQP dispatch. */
        public const val TELEMETRY_METHOD: String = "AMQP"

        /**
         * Starts serving reactor events (CONTRACT.md §22.10 — `reactorServe`).
         *
         * Registers a manual-ack consumer on the **server-declared** queue.
         * Nothing is declared and nothing is bound: [ReactorTransport] has no
         * method that could.
         *
         * @param options the configuration
         * @return a running server; close it to stop, ideally with `use { }`
         */
        public fun reactorServe(options: ReactorServeOptions): ReactorServer {
            val server = ReactorServer(options)
            server.consumerTag = options.transport.consume(options.resolvedQueue, server::onDelivery)
            return server
        }
    }
}

/**
 * Starts serving reactor events — the §22.6 entry point, spelled the way the
 * per-language name table spells it for Kotlin.
 *
 * @param options the configuration
 * @return a running server; close it to stop
 */
public fun reactorServe(options: ReactorServeOptions): ReactorServer =
    ReactorServer.reactorServe(options)
