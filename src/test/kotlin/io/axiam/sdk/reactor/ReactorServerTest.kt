package io.axiam.sdk.reactor

import io.axiam.sdk.Sensitive
import io.axiam.sdk.telemetry.TelemetryEvent
import io.axiam.sdk.telemetry.TelemetryHook
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * CONTRACT.md §22.10 and §22.13's "Runtime" group: the verify-before-handler
 * gate, the no-topology rule, fail-closed-on-our-own-errors, the unfiltered
 * patch, the timeout window, §18 shutdown, §19 telemetry, and the guarantee that
 * the signing key never reaches a log line.
 */
class ReactorServerTest {

    /** The fixture's own `verified_at`; every event vector is fresh at this instant. */
    private val now: Instant = Instant.parse("2026-07-10T12:00:00Z")
    private val fixed: Clock = Clock.fixed(now, ZoneOffset.UTC)
    private val replyQueue = "amq.rabbitmq.reply-to.abc"

    private lateinit var fixture: JsonObject
    private lateinit var subkey: ByteArray
    private lateinit var subkeyHex: String
    private lateinit var tenantId: UUID
    private lateinit var reactorId: UUID
    private lateinit var transport: FakeReactorTransport
    private lateinit var logLines: MutableList<String>

    @BeforeEach
    fun setUp() {
        fixture = ReactorVectors.load()
        subkey = ReactorVectors.subkey(fixture)
        subkeyHex = ReactorVectors.toHex(subkey)
        tenantId = ReactorVectors.tenantId(fixture)
        reactorId = UUID.fromString(ReactorVectors.text(fixture, "reactor_id"))
        transport = FakeReactorTransport()
        logLines = Collections.synchronizedList(mutableListOf())
    }

    // ---- happy path --------------------------------------------------------

    @Test
    fun `a verified event reaches the handler and its reply is signed and correlated`() {
        val seen = AtomicReference<ReactorEvent>()
        serve({ event ->
            seen.set(event)
            ReactorDecision.mutate(mapOf("ext.department" to "eng"))
        }).use { deliver(eventBody("token_pre_issue")) }

        val event = requireNotNull(seen.get())
        assertEquals(ReactorEvents.TOKEN_PRE_ISSUE, event.event)
        assertEquals(tenantId, event.tenantId)
        assertEquals(ReactorVectors.correlationId(fixture), event.correlationId)
        assertEquals(500, event.timeoutMs)
        assertEquals(2, event.keyVersion)
        assertEquals(now, event.issuedAt)
        assertEquals("alice", event.payload["sub"]!!.jsonPrimitive.content)
        assertEquals(emptyMap<String, String>(), event.priorPatch())
        assertEquals(ReactorEvents.TOKEN_PRE_ISSUE, event.spec()!!.name)

        assertEquals(1, transport.published.size, "exactly one reply")
        val reply = transport.published.single()
        assertTrue(
            ReactorProtocol.verifyEvent(subkey, reply.body),
            "the reply must be signed with the same tenant subkey",
        )
        val parsed = ReactorVectors.json.parseToJsonElement(reply.body.decodeToString()).jsonObject
        assertEquals(
            event.correlationId.toString(),
            parsed["correlation_id"]!!.jsonPrimitive.content,
            "the correlation the server authenticates lives inside the signed body",
        )
        assertEquals("mutate", parsed["decision"]!!.jsonPrimitive.content)
        assertEquals("eng", parsed["patch"]!!.jsonObject["ext.department"]!!.jsonPrimitive.content)
        assertEquals(2, parsed["key_version"]!!.jsonPrimitive.content.toInt())

        // The AMQP property is echoed too — standard RPC — but it is not what
        // the server authenticates.
        assertEquals(event.correlationId.toString(), reply.correlationId)
        assertEquals(replyQueue, reply.replyTo)
        assertTrue(transport.settled.single().acked)
    }

    // ---- §22.10 rule 1: no topology ----------------------------------------

    @Test
    fun `the runtime consumes only the queue it is registered as, and declares nothing`() {
        serve({ ReactorDecision.allow() }).use { server ->
            assertEquals(ReactorProtocol.queueName(tenantId, reactorId), server.queue)
            assertEquals(listOf(ReactorProtocol.queueName(tenantId, reactorId)), transport.consumed)
        }

        // ReactorTransport has no declare or bind method at all — asserted on the
        // type, so the capability is absent rather than merely unused.
        val methods = ReactorTransport::class.java.declaredMethods.map { it.name }.toSet()
        assertEquals(setOf("consume", "publishReply", "ack", "nack", "cancel"), methods)
    }

    // ---- §22.10 rule 2: fail closed on our own errors ----------------------

    @Test
    fun `a handler that throws produces no reply rather than a synthesized allow`() {
        serve({ throw IllegalStateException("fraud backend unreachable") })
            .use { deliver(eventBody("login_post_auth")) }

        assertEquals(
            0,
            transport.published.size,
            "zero published messages — an SDK that answers `allow` for a crashed handler has " +
                "overridden the operator's fail_closed setting from inside the library",
        )
        assertFalse(transport.settled.single().acked)
        assertFalse(transport.settled.single().requeue)
    }

    @Test
    fun `an event that fails any section 8 gate never reaches the handler`() {
        // (a) wrong signature — payload rewritten after signing
        assertRefused(tampered { it + ("payload" to buildJsonObject { put("sub", JsonPrimitive("root")) }) })
        // (b) key_version downgraded after signing — refused before the MAC is computed
        assertRefused(tampered { it + ("key_version" to JsonPrimitive(1)) })
        // (c) stale, and (d) future
        assertRefused(signedEvent(issuedAt = now.minusSeconds(301)))
        assertRefused(signedEvent(issuedAt = now.plusSeconds(301)))
        // (e) an event correctly signed with our key but naming another tenant
        assertRefused(
            EventFactory.signEvent(
                subkey, UUID.randomUUID(), ReactorEvents.TOKEN_PRE_ISSUE, issuedAt = now,
            ),
        )
        // (f) bodies that are not reactor bodies at all
        assertRefused("not json".toByteArray())
        assertRefused("[1,2,3]".toByteArray())
    }

    @Test
    fun `every malformed field is refused with a security event and no reply`() {
        assertRefused(resigned { it - "issued_at" })
        assertRefused(resigned { it + ("issued_at" to JsonPrimitive("the day before yesterday")) })
        assertRefused(resigned { it - "nonce" })
        assertRefused(resigned { it + ("nonce" to JsonPrimitive("not-a-uuid")) })
        assertRefused(resigned { it + ("tenant_id" to JsonPrimitive("not-a-uuid")) })
        assertRefused(resigned { it + ("correlation_id" to JsonPrimitive("not-a-uuid")) })
        assertRefused(resigned { it + ("event" to JsonPrimitive("")) })
        assertRefused(resigned { it - "event" })
        assertRefused(resigned { it + ("payload" to JsonPrimitive("a string is not a payload")) })
        assertRefused(resigned { it - "payload" })
        assertRefused(resigned { it + ("timeout_ms" to JsonPrimitive(0)) })
        assertRefused(resigned { it - "timeout_ms" })
        assertRefused(resigned { it - "key_version" })
        assertRefused(resigned { it + ("key_version" to JsonPrimitive("two")) })

        assertTrue(logLines.isNotEmpty(), "every refusal is reported")
        for (line in logLines) {
            assertTrue(line.contains("axiam_sdk_security"), "as a security event: $line")
            assertFalse(line.contains(subkeyHex), "and never carrying the key")
        }
    }

    @Test
    fun `a replayed nonce is refused on the second delivery`() {
        val handled = AtomicInteger()
        val body = eventBody("token_pre_issue")
        serve({ handled.incrementAndGet(); ReactorDecision.allow() }).use {
            deliver(body)
            deliver(body)
        }
        assertEquals(1, handled.get(), "the second delivery of one nonce is a replay")
        assertEquals(1, transport.published.size)
    }

    // ---- §22.10 rule 3: never filter a patch -------------------------------

    /**
     * §22.4 rule 1 / §22.13: a handler returning a patch containing a forbidden
     * key sends it **unfiltered**. Silently dropping `sub` would leave the
     * reactor author believing it was set.
     */
    @Test
    fun `a forbidden patch key is sent unfiltered rather than quietly dropped`() {
        serve({ ReactorDecision.mutate(mapOf("ext.department" to "eng", "sub" to "root")) })
            .use { deliver(eventBody("token_pre_issue")) }

        val patch = ReactorVectors.json
            .parseToJsonElement(transport.published.single().body.decodeToString())
            .jsonObject["patch"]!!.jsonObject
        assertEquals(
            "root",
            patch["sub"]!!.jsonPrimitive.content,
            "the SDK must NOT drop `sub` — one forbidden key rejects the whole patch, server-side, " +
                "and the author finds out",
        )
        assertEquals("eng", patch["ext.department"]!!.jsonPrimitive.content)
        assertFalse(
            ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE)!!.patchFieldAllowed("sub"),
            "and the SDK knows perfectly well that the server will refuse it",
        )
    }

    // ---- §22.3 / rule 4: the window ----------------------------------------

    @Test
    fun `a reply is abandoned rather than published after the window closed`() {
        val clock = MovingClock(now)
        serve({ clock.advance(2_000); ReactorDecision.allow() }, clock).use {
            deliver(eventBody("token_pre_issue"))
        }

        assertEquals(0, transport.published.size, "a late reply is discarded by the server anyway")
        assertTrue(transport.settled.single().acked, "the delivery is still settled")
    }

    @Test
    fun `an event carries its window to the handler`() {
        val remaining = AtomicReference<kotlin.time.Duration>()
        serve({ event -> remaining.set(event.remaining(now)); ReactorDecision.allow() })
            .use { deliver(eventBody("login_post_auth")) }
        assertEquals(1000.milliseconds, remaining.get(), "login.post_auth's vector declares a 1000 ms window")

        val closed = AtomicReference<kotlin.time.Duration>()
        transport = FakeReactorTransport()
        serve({ event -> closed.set(event.remaining(now.plusSeconds(10))); ReactorDecision.allow() })
            .use { deliver(eventBody("login_post_auth")) }
        assertEquals(
            kotlin.time.Duration.ZERO,
            closed.get(),
            "a closed window reports zero remaining, never a negative duration",
        )
    }

    @Test
    fun `the timeout is clamped to the chain ceiling`() {
        val seen = AtomicInteger()
        val body = EventFactory.signEvent(
            subkey, tenantId, ReactorEvents.TOKEN_PRE_ISSUE, issuedAt = now, timeoutMs = 60_000,
        )
        serve({ event -> seen.set(event.timeoutMs); ReactorDecision.allow() }).use { deliver(body) }
        assertEquals(
            ReactorProtocol.CHAIN_CEILING_MS,
            seen.get(),
            "no dispatch outlives the chain's 5 000 ms wall-clock ceiling",
        )
    }

    @Test
    fun `a delivery with no reply_to publishes nothing`() {
        serve({ ReactorDecision.allow() }).use { deliver(eventBody("token_pre_issue"), replyTo = null) }
        assertEquals(0, transport.published.size, "there is nowhere to answer")
        assertTrue(transport.settled.single().acked, "and the delivery is still settled")
    }

    // ---- §22.5 listeners ---------------------------------------------------

    @Test
    fun `a listener observes and publishes nothing`() {
        val observed = AtomicInteger()
        reactorServe(
            baseOptions().let { base ->
                ReactorServeOptions(
                    transport = transport,
                    tenantId = tenantId,
                    signingKey = Sensitive.of(subkey),
                    listener = { observed.incrementAndGet() },
                    reactorId = reactorId,
                    log = base.log,
                    clock = fixed,
                    shutdownGrace = 2.seconds,
                )
            },
        ).use { deliver(eventBody("token_pre_issue")) }

        assertEquals(1, observed.get())
        assertEquals(0, transport.published.size, "a listener MUST NOT publish a reply")
        assertTrue(transport.settled.single().acked)
    }

    @Test
    fun `a listener that throws also publishes nothing`() {
        reactorServe(
            ReactorServeOptions(
                transport = transport,
                tenantId = tenantId,
                signingKey = Sensitive.of(subkey),
                listener = { throw IllegalStateException("sink down") },
                reactorId = reactorId,
                log = ReactorLog { logLines += it },
                clock = fixed,
            ),
        ).use { deliver(eventBody("token_pre_issue")) }

        assertEquals(0, transport.published.size)
        assertFalse(transport.settled.single().acked)
    }

    @Test
    fun `handler and listener are mutually exclusive and one is required`() {
        val noAnswer = runCatching {
            ReactorServeOptions(transport, tenantId, Sensitive.of(subkey), reactorId = reactorId)
        }.exceptionOrNull()
        assertTrue(noAnswer is IllegalArgumentException)

        val bothAnswers = runCatching {
            ReactorServeOptions(
                transport, tenantId, Sensitive.of(subkey),
                handler = { ReactorDecision.allow() },
                listener = { },
                reactorId = reactorId,
            )
        }.exceptionOrNull()
        assertTrue(bothAnswers is IllegalArgumentException)

        val noQueue = runCatching {
            ReactorServeOptions(transport, tenantId, Sensitive.of(subkey), handler = { ReactorDecision.allow() })
        }.exceptionOrNull()
        assertTrue(noQueue is IllegalArgumentException)

        val bothQueues = runCatching {
            ReactorServeOptions(
                transport, tenantId, Sensitive.of(subkey),
                handler = { ReactorDecision.allow() }, queue = "q", reactorId = reactorId,
            )
        }.exceptionOrNull()
        assertTrue(bothQueues is IllegalArgumentException)

        val badSkew = runCatching {
            ReactorServeOptions(
                transport, tenantId, Sensitive.of(subkey),
                handler = { ReactorDecision.allow() }, reactorId = reactorId,
                freshnessSkew = kotlin.time.Duration.ZERO,
            )
        }.exceptionOrNull()
        assertTrue(badSkew is IllegalArgumentException)

        val badGrace = runCatching {
            ReactorServeOptions(
                transport, tenantId, Sensitive.of(subkey),
                handler = { ReactorDecision.allow() }, reactorId = reactorId,
                shutdownGrace = kotlin.time.Duration.ZERO,
            )
        }.exceptionOrNull()
        assertTrue(badGrace is IllegalArgumentException)
    }

    @Test
    fun `an explicitly named queue is consumed verbatim`() {
        val options = ReactorServeOptions(
            transport = transport,
            tenantId = tenantId,
            signingKey = Sensitive.of(subkey),
            handler = { ReactorDecision.allow() },
            queue = "axiam.reactor.q.explicit",
            log = ReactorLog { logLines += it },
            clock = fixed,
            freshnessSkew = 60.seconds,
            shutdownGrace = 1.seconds,
            telemetryHook = TelemetryHook { },
        )
        assertEquals("axiam.reactor.q.explicit", options.resolvedQueue)
        assertNull(options.reactorId)
        assertNotNull(options.handler)
        assertNull(options.listener)
        assertEquals(tenantId, options.tenantId)
        assertEquals(60.seconds, options.freshnessSkew)
        assertEquals(1.seconds, options.shutdownGrace)
        assertEquals(fixed, options.clock)
        assertNotNull(options.telemetryHook)
        assertNotNull(options.transport)

        reactorServe(options).use { server -> assertEquals("axiam.reactor.q.explicit", server.queue) }
        assertEquals(listOf("axiam.reactor.q.explicit"), transport.consumed)
    }

    // ---- §18 deterministic shutdown ----------------------------------------

    @Test
    fun `close cancels the consumer, drains in-flight work, and is idempotent`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val server = serve({
            entered.countDown()
            release.await(5, TimeUnit.SECONDS)
            ReactorDecision.allow()
        })

        val body = eventBody("login_post_auth")
        val worker = Thread { deliver(body) }
        worker.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertEquals(1, server.inFlightCount)
        assertFalse(server.isClosed)

        val closer = Thread { server.close() }
        closer.start()
        Thread.sleep(50)
        release.countDown()
        closer.join(5_000)
        worker.join(5_000)

        assertTrue(server.isClosed)
        assertEquals(0, server.inFlightCount, "close() drains in-flight events (§18)")
        assertEquals(1, transport.published.size, "the in-flight event still got its reply")
        assertEquals(listOf("consumer-tag"), transport.cancelled)

        server.close()
        assertEquals(listOf("consumer-tag"), transport.cancelled, "close() is idempotent")
    }

    @Test
    fun `a delivery arriving after close is requeued rather than answered`() {
        val server = serve({ ReactorDecision.allow() })
        server.close()
        deliver(eventBody("login_post_auth"))

        assertEquals(0, transport.published.size)
        assertTrue(transport.settled.single().requeue, "the next runtime to attach is entitled to it")
    }

    @Test
    fun `closing over a torn-down channel still completes`() {
        val exploding = FakeReactorTransport(cancelFails = true)
        val server = reactorServe(
            ReactorServeOptions(
                transport = exploding,
                tenantId = tenantId,
                signingKey = Sensitive.of(subkey),
                handler = { ReactorDecision.allow() },
                reactorId = reactorId,
                log = ReactorLog { logLines += it },
                clock = fixed,
                shutdownGrace = 1.seconds,
            ),
        )
        server.close()
        assertTrue(server.isClosed, "a broker that tore the channel down first is not a close failure")
        assertTrue(logLines.any { it.contains("cancel failed") })
    }

    // ---- §19 telemetry -----------------------------------------------------

    @Test
    fun `one pair of telemetry events is emitted per dispatch`() {
        val events = Collections.synchronizedList(mutableListOf<TelemetryEvent>())
        reactorServe(
            ReactorServeOptions(
                transport = transport,
                tenantId = tenantId,
                signingKey = Sensitive.of(subkey),
                handler = { ReactorDecision.allow() },
                reactorId = reactorId,
                log = ReactorLog { logLines += it },
                clock = fixed,
                telemetryHook = { events += it },
            ),
        ).use { deliver(eventBody("login_post_auth")) }

        assertEquals(2, events.size)
        val start = events[0] as TelemetryEvent.RequestStart
        assertEquals("reactorServe", start.operation)
        assertEquals("AMQP", start.method)
        assertEquals(
            ReactorEvents.LOGIN_POST_AUTH,
            start.pathTemplate,
            "the path template is the event name — a closed set of five, never a UUID",
        )
        assertEquals(1, start.attempt)
        val end = events[1] as TelemetryEvent.RequestEnd
        assertEquals(TelemetryEvent.Outcome.SUCCESS, end.outcome)
        assertNull(end.status, "an AMQP dispatch has no HTTP status")
    }

    @Test
    fun `a telemetry hook that throws cannot fail the dispatch`() {
        reactorServe(
            ReactorServeOptions(
                transport = transport,
                tenantId = tenantId,
                signingKey = Sensitive.of(subkey),
                handler = { ReactorDecision.allow() },
                reactorId = reactorId,
                log = ReactorLog { logLines += it },
                clock = fixed,
                telemetryHook = { throw IllegalStateException("metrics backend down") },
            ),
        ).use { deliver(eventBody("login_post_auth")) }

        assertEquals(1, transport.published.size, "telemetry is not permitted to fail a dispatch")
        assertTrue(logLines.any { it.contains("telemetry hook threw") })
    }

    // ---- §22.12 the signing key is never logged ----------------------------

    @Test
    fun `the signing key never appears in any log line, and neither does the payload`() {
        serve({ throw IllegalStateException("boom") }).use {
            deliver(eventBody("login_post_auth"))
            deliver(tampered { it + ("key_version" to JsonPrimitive(1)) })
            deliver("not json".toByteArray())
        }

        assertTrue(logLines.isNotEmpty(), "the failures above must be reported")
        for (line in logLines) {
            assertFalse(line.contains(subkeyHex), "a log line leaked the signing key: $line")
            assertFalse(
                line.lowercase().contains("alice"),
                "the payload is tenant business data and is never logged: $line",
            )
        }
        assertEquals("[SENSITIVE]", Sensitive.of(subkey).toString())
    }

    @Test
    fun `an event's toString carries no payload`() {
        val rendered = AtomicReference<String>()
        serve({ event -> rendered.set(event.toString()); ReactorDecision.allow() })
            .use { deliver(eventBody("token_pre_issue")) }
        assertFalse(rendered.get().contains("alice"))
        assertTrue(rendered.get().contains(ReactorEvents.TOKEN_PRE_ISSUE))
    }

    // ---- chained events ----------------------------------------------------

    @Test
    fun `an earlier reactor's patch is surfaced as read-only context`() {
        val payload = buildJsonObject {
            put("sub", JsonPrimitive("alice"))
            put(
                ReactorEvent.REACTOR_PATCH_KEY,
                buildJsonObject {
                    put("ext.department", JsonPrimitive("eng"))
                    // Not a string, so not a patch entry: the patch is string→string.
                    put("ext.headcount", JsonPrimitive(12))
                },
            )
        }
        val body = EventFactory.signEvent(
            subkey, tenantId, ReactorEvents.TOKEN_PRE_ISSUE, issuedAt = now, payload = payload,
        )

        val prior = AtomicReference<Map<String, String>>()
        serve({ event -> prior.set(event.priorPatch()); ReactorDecision.allow() }).use { deliver(body) }
        assertEquals(mapOf("ext.department" to "eng"), prior.get())
    }

    // ---- helpers -----------------------------------------------------------

    private fun assertRefused(body: ByteArray) {
        transport = FakeReactorTransport()
        val ran = AtomicInteger()
        serve({ ran.incrementAndGet(); ReactorDecision.allow() }).use { deliver(body) }
        assertEquals(0, ran.get(), "the handler must be unreachable for a refused event")
        assertEquals(0, transport.published.size, "and nothing is published")
        assertFalse(transport.settled.single().acked)
        assertFalse(transport.settled.single().requeue, "a body that failed §8 v2 will fail it again")
    }

    private fun serve(handler: ReactorHandler, clock: Clock = fixed): ReactorServer =
        reactorServe(baseOptions(handler, clock))

    private fun baseOptions(
        handler: ReactorHandler = ReactorHandler { ReactorDecision.allow() },
        clock: Clock = fixed,
    ) = ReactorServeOptions(
        transport = transport,
        tenantId = tenantId,
        signingKey = Sensitive.of(subkey),
        handler = handler,
        reactorId = reactorId,
        log = ReactorLog { logLines += it },
        clock = clock,
        shutdownGrace = 2.seconds,
    )

    private fun deliver(body: ByteArray, replyTo: String? = replyQueue) {
        val onDelivery = requireNotNull(transport.onDelivery) { "the runtime never started consuming" }
        onDelivery(
            ReactorDelivery(
                deliveryTag = 1L,
                routingKey = ReactorProtocol.routingKey(tenantId, ReactorEvents.TOKEN_PRE_ISSUE),
                replyTo = replyTo,
                body = body,
            ),
        )
    }

    private fun eventBody(vectorName: String): ByteArray =
        ReactorVectors.wireBody(fixture["server_to_reactor"]!!.jsonObject[vectorName]!!.jsonObject)

    private fun signedEvent(issuedAt: Instant): ByteArray =
        EventFactory.signEvent(subkey, tenantId, ReactorEvents.TOKEN_PRE_ISSUE, issuedAt = issuedAt)

    /** Mutates the signed body without re-signing — the signature no longer matches. */
    private fun tampered(mutation: (JsonObject) -> Map<String, kotlinx.serialization.json.JsonElement>): ByteArray {
        val vector = fixture["server_to_reactor"]!!.jsonObject["token_pre_issue"]!!.jsonObject
        val signed = ReactorVectors.withSignature(
            ReactorVectors.canonicalObject(vector),
            ReactorVectors.text(vector, "hmac_signature_hex"),
        )
        return ReactorVectors.encode(JsonObject(mutation(signed)))
    }

    /**
     * Mutates the body and re-signs it, so the refusal can only come from the
     * field check rather than from a broken MAC.
     */
    private fun resigned(mutation: (JsonObject) -> Map<String, kotlinx.serialization.json.JsonElement>): ByteArray {
        val vector = fixture["server_to_reactor"]!!.jsonObject["token_pre_issue"]!!.jsonObject
        val canonical = JsonObject(mutation(ReactorVectors.canonicalObject(vector)))
        return EventFactory.sign(subkey, JsonObject(canonical + ("hmac_signature" to kotlinx.serialization.json.JsonNull)))
    }

    /** A clock a handler can move forward, to close a window without sleeping. */
    private class MovingClock(private var current: Instant) : Clock() {
        fun advance(millis: Long) {
            current = current.plusMillis(millis)
        }

        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = current
    }
}
