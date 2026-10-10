package io.axiam.sdk.ssf

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.telemetry.TelemetryEvent
import io.axiam.sdk.telemetry.TelemetryHook
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * The SSF receiver helper — CONTRACT.md §32.8's eight receiver tests, plus the
 * poll retry rule, discovery and the replay store.
 *
 * Every signing key is an Ed25519 key generated here; no key literal.
 */
class SsfReceiverTest {

    private val issuer = "https://iam.example.test/t/22222222-2222-4222-8222-222222222222"
    private val audience = "https://rp.example.test"

    private lateinit var server: MockWebServer
    private val jwksHits = AtomicInteger()
    private var jwksKeys: List<OctetKeyPair> = emptyList()
    private val polls = Collections.synchronizedList(mutableListOf<RecordedRequest>())
    private var pollAnswer: () -> MockResponse = { MockResponse().setResponseCode(501) }
    private var discovery: String? = null

    /** When set, every JWKS fetch after the first [jwksFailAfter] answers `503`. */
    private var jwksFailAfter: Int? = null

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.requestUrl?.encodedPath ?: ""
                return when {
                    path == "/oauth2/jwks" -> {
                        val hit = jwksHits.incrementAndGet()
                        val failAfter = jwksFailAfter
                        if (failAfter != null && hit > failAfter) {
                            MockResponse().setResponseCode(503)
                        } else {
                            json(200, JWKSet(jwksKeys.map { it.toPublicJWK() }).toString())
                        }
                    }
                    path == "/.well-known/ssf-configuration" && discovery != null -> json(200, discovery!!)
                    path.startsWith("/ssf/v1/poll/") -> {
                        polls += request
                        pollAnswer()
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun json(code: Int, body: String) =
        MockResponse().setResponseCode(code).addHeader("Content-Type", "application/json").setBody(body)

    private fun key(kid: String = "k-" + UUID.randomUUID()): OctetKeyPair =
        OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate()

    private fun b64(text: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray())

    /** Signs [claims] under [header] with [key] — the raw form, so any header can be tested. */
    private fun sign(key: OctetKeyPair, header: JsonObject, claims: JsonObject): String {
        val input = b64(header.toString()) + "." + b64(claims.toString())
        val signature = Ed25519Signer(key).sign(JWSHeader(JWSAlgorithm.EdDSA), input.toByteArray())
        return "$input.$signature"
    }

    private fun setHeader(key: OctetKeyPair, typ: String? = "secevent+jwt") = buildJsonObject {
        put("alg", "EdDSA")
        typ?.let { put("typ", it) }
        put("kid", key.keyID)
    }

    private fun signSet(key: OctetKeyPair, claims: JsonObject) = sign(key, setHeader(key), claims)

    private fun claims(): JsonObject = buildJsonObject {
        put("iss", issuer)
        put("aud", audience)
        put("iat", 1_791_500_000)
        put("jti", UUID.randomUUID().toString().replace("-", ""))
        put("txn", "t-1")
        put("sub_id", buildJsonObject {
            put("format", "iss_sub")
            put("iss", issuer)
            put("sub", UUID.randomUUID().toString())
        })
        put("events", buildJsonObject {
            put(SsfEventTypes.SESSION_REVOKED, buildJsonObject { put("event_timestamp", 1_791_500_000) })
        })
    }

    private fun JsonObject.with(name: String, value: JsonElement) = JsonObject(this + (name to value))
    private fun JsonObject.without(name: String) = JsonObject(this - name)

    /** A [ReplayStore] the test can read back, failing on the jtis in [failOn]. */
    private class RecordingStore(private val failOn: Set<String> = emptySet()) : ReplayStore {
        val recorded: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

        /** While set, the store cannot answer for any jti (its backend is down). */
        @Volatile
        var down = false
        override fun checkAndRecord(jti: String, window: Duration): Boolean {
            if (down || jti in failOn) throw IllegalStateException("the replay store cannot answer")
            return recorded.add(jti)
        }
    }

    private fun receiverWith(store: ReplayStore, hook: TelemetryHook? = null): SsfReceiver {
        val token = "cc-" + UUID.randomUUID().toString().replace("-", "")
        val builder = AxiamClient.builder(server.url("/").toString(), UUID.randomUUID().toString())
        if (hook != null) builder.telemetryHook(hook)
        return SsfReceiver(
            builder.build(),
            SsfReceiverConfig(
                issuer,
                audience,
                SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString()),
                accessTokenProvider = { Sensitive.of(token) },
                replayStore = store,
            ),
        )
    }

    private fun jtiOf(c: JsonObject) = (c["jti"] as JsonPrimitive).content

    private fun client(): AxiamClient = AxiamClient.builder(server.url("/").toString(), UUID.randomUUID().toString()).build()

    private fun receiver(
        keys: SsfKeySource = SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString()),
        issuer: String = this.issuer,
    ): SsfReceiver {
        val token = "cc-" + UUID.randomUUID().toString().replace("-", "")
        return SsfReceiver(
            client(),
            SsfReceiverConfig(issuer, audience, keys, accessTokenProvider = { Sensitive.of(token) }),
        )
    }

    private fun reason(receiver: SsfReceiver, set: String): SetFailureReason {
        val e = assertThrows<SetVerificationError> { runBlocking { receiver.verifySet(set) } }
        assertTrue(AuthError::class.java.isAssignableFrom(e.javaClass), "a refusal is an AuthError")
        assertEquals(e.failureReason.code, e.reason)
        return e.failureReason
    }

    // -- 1 ---------------------------------------------------------------------------

    @Test
    fun `a SET signed by the JWKS key verifies into its claims`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val c = claims()
        val event = receiver().verifySet(signSet(k, c))
        assertEquals((c["jti"] as JsonPrimitive).content, event.jti)
        assertEquals(1_791_500_000L, event.iat)
        assertEquals(issuer, event.iss)
        assertEquals(JsonPrimitive(audience), event.aud)
        assertEquals("t-1", event.txn)
        assertEquals(SsfEventTypes.SESSION_REVOKED, event.eventType)
        assertEquals(c["events"]!!.jsonObject[SsfEventTypes.SESSION_REVOKED], event.event)
        assertEquals(c["sub_id"], event.subId)

        val arrayAud = claims().with("aud", JsonArray(listOf(JsonPrimitive("other"), JsonPrimitive(audience))))
        val set = sign(k, setHeader(k, typ = "Application/SecEvent+JWT"), arrayAud)
        assertEquals(JsonArray(listOf(JsonPrimitive("other"), JsonPrimitive(audience))), receiver().verifySet(set).aud)
    }

    // -- 2 ---------------------------------------------------------------------------

    @Test
    fun `a wrong typ or alg is refused in that order`() {
        val k = key()
        jwksKeys = listOf(k)
        val r = receiver()
        val c = claims()
        assertEquals(SetFailureReason.INVALID_TYPE, reason(r, sign(k, setHeader(k, typ = null), c)))
        assertEquals(SetFailureReason.INVALID_TYPE, reason(r, sign(k, setHeader(k, typ = "JWT"), c)))
        val none = b64("""{"alg":"none","typ":"secevent+jwt"}""") + "." + b64(c.toString()) + "."
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, none))
        val hsHeader = """{"alg":"HS256","typ":"secevent+jwt","kid":"${k.keyID}"}"""
        val hsInput = b64(hsHeader) + "." + b64(c.toString())
        val macKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val hs = hsInput + "." + MACSigner(macKey).sign(JWSHeader(JWSAlgorithm.HS256), hsInput.toByteArray())
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, hs))
        assertEquals(SetFailureReason.MALFORMED, reason(r, "a.b"))
        assertEquals(SetFailureReason.MALFORMED, reason(r, "!!.@@.##"))
        assertEquals(SetFailureReason.MALFORMED, reason(r, b64("[1]") + "." + b64(c.toString()) + ".c2ln"))
    }

    // -- 3 ---------------------------------------------------------------------------

    @Test
    fun `another key or a tampered payload is invalid_key`() {
        val k = key()
        val rogue = key(kid = k.keyID)
        jwksKeys = listOf(k)
        val r = receiver()
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, signSet(rogue, claims())))
        val parts = signSet(k, claims()).split('.').toMutableList()
        parts[1] = b64(claims().with("txn", JsonPrimitive("x")).toString())
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, parts.joinToString(".")))
    }

    // -- 4 ---------------------------------------------------------------------------

    @Test
    fun `another issuer or audience is refused`() {
        val k = key()
        jwksKeys = listOf(k)
        val r = receiver()
        assertEquals(
            SetFailureReason.INVALID_ISSUER,
            reason(r, signSet(k, claims().with("iss", JsonPrimitive("https://iam.example.test")))),
        )
        assertEquals(
            SetFailureReason.INVALID_AUDIENCE,
            reason(r, signSet(k, claims().with("aud", JsonArray(listOf(JsonPrimitive("https://elsewhere.test")))))),
        )
    }

    // -- 5 ---------------------------------------------------------------------------

    @Test
    fun `exp, sub, two events or a missing jti, iat or sub_id is invalid_request`() {
        val k = key()
        jwksKeys = listOf(k)
        val r = receiver()
        val two = buildJsonObject {
            put(SsfEventTypes.ACCOUNT_DISABLED, JsonObject(emptyMap()))
            put(SsfEventTypes.ACCOUNT_PURGED, JsonObject(emptyMap()))
        }
        for ((label, c) in listOf(
            "exp" to claims().with("exp", JsonPrimitive(1_891_500_000)),
            "sub" to claims().with("sub", JsonPrimitive("u")),
            "two events" to claims().with("events", two),
            "no jti" to claims().without("jti"),
            "no iat" to claims().without("iat"),
            "no sub_id" to claims().without("sub_id"),
        )) {
            assertEquals(SetFailureReason.INVALID_REQUEST, reason(r, signSet(k, c)), label)
        }
    }

    // -- 6 ---------------------------------------------------------------------------

    @Test
    fun `a replay is refused and a short window is refused at configuration`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val r = receiver()
        val set = signSet(k, claims())
        r.verifySet(set)
        assertEquals(SetFailureReason.REPLAYED, reason(r, set))

        assertThrows<ValidationError> {
            SsfReceiver(
                client(),
                SsfReceiverConfig(
                    issuer,
                    audience,
                    SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString()),
                    replayWindow = Duration.ofDays(6),
                ),
            )
        }
        Unit
    }

    // -- 7 ---------------------------------------------------------------------------

    @Test
    fun `an unknown kid costs one refetch and a second one none`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val r = receiver()
        r.verifySet(signSet(k, claims()))
        assertEquals(1, jwksHits.get(), "primes the cache")
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, signSet(key(), claims())))
        assertEquals(2, jwksHits.get(), "exactly one refetch")
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, signSet(key(), claims())))
        assertEquals(2, jwksHits.get(), "no refetch within the minute")
    }

    /**
     * §32.7 step 4 (contract 1.59, §34.2 P6): the key cache expires as §10's
     * JWKS cache does, so a key the transmitter removed stops verifying.
     */
    @Test
    fun `the JWKS cache expires and a removed key stops verifying`() = runBlocking {
        val old = key()
        jwksKeys = listOf(old)
        var now = 0L
        val r = SsfReceiver(
            client(),
            SsfReceiverConfig(issuer, audience, SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString())),
            nanoTime = { now },
        )
        r.verifySet(signSet(old, claims()))
        assertEquals(1, jwksHits.get(), "primes the cache")

        jwksKeys = listOf(key()) // the transmitter rotates and removes the old key
        now += Duration.ofSeconds(299).toNanos()
        r.verifySet(signSet(old, claims()))
        assertEquals(1, jwksHits.get(), "within its lifetime the cache is used")

        now += Duration.ofSeconds(2).toNanos()
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, signSet(old, claims())))
        assertTrue(jwksHits.get() >= 2, "the expired cache was fetched again")
        // P6 (contract 1.60): no later than 10 minutes after the fill that started it.
        assertTrue(SsfReceiver.JWKS_CACHE_LIFETIME <= Duration.ofMinutes(10))
    }

    /**
     * P6 (contract 1.60, §34.4 C-5): a failed refresh of an expired cache counts toward the
     * once-a-minute limit like a failed fill, so the next SET within the minute makes no fetch
     * and gets no verdict.
     */
    @Test
    fun `a failed refresh of the expired cache counts toward the once-a-minute limit`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        var now = 0L
        val r = SsfReceiver(
            client(),
            SsfReceiverConfig(issuer, audience, SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString())),
            nanoTime = { now },
        )
        r.verifySet(signSet(k, claims()))
        assertEquals(1, jwksHits.get(), "the fill")

        jwksFailAfter = 1 // the refresh after expiry answers 503
        now += SsfReceiver.JWKS_CACHE_LIFETIME.toNanos() + 1
        val failed = assertThrows<NetworkError> { runBlocking { r.verifySet(signSet(k, claims())) } }
        assertFalse(SetVerificationError::class.isInstance(failed), "a failed refresh is no verdict")
        assertEquals(2, jwksHits.get(), "the expired cache was refreshed")

        now += Duration.ofSeconds(30).toNanos()
        assertThrows<NetworkError> { runBlocking { r.verifySet(signSet(k, claims())) } }
        assertEquals(2, jwksHits.get(), "inside the minute: no fetch")

        jwksFailAfter = null
        now += Duration.ofSeconds(31).toNanos()
        r.verifySet(signSet(k, claims()))
        assertEquals(3, jwksHits.get(), "a minute later the refresh is made again")
    }

    // -- 8 ---------------------------------------------------------------------------

    @Test
    fun `poll passes ack and set_errs through and sorts the answer`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val stream = UUID.randomUUID().toString()
        val good = claims()
        val bad = claims().with("iss", JsonPrimitive("https://impostor.test"))
        val goodJti = (good["jti"] as JsonPrimitive).content
        val badJti = (bad["jti"] as JsonPrimitive).content
        val reply = buildJsonObject {
            put("sets", buildJsonObject {
                put(goodJti, signSet(k, good))
                put(badJti, signSet(k, bad))
                put("not-a-string", 42)
            })
            put("moreAvailable", true)
        }.toString()
        pollAnswer = { json(200, reply) }

        val r = receiver()
        val result = r.poll(
            stream,
            SsfPollOptions(
                maxEvents = 10,
                returnImmediately = true,
                ack = listOf("done-1", "done-2"),
                setErrs = mapOf("old-1" to SetErr.fromReason(SetFailureReason.REPLAYED)),
            ),
        )
        assertTrue(result.moreAvailable)
        assertEquals(listOf(goodJti), result.events.map { it.jti })
        assertEquals(
            listOf(RefusedSet(badJti, SetFailureReason.INVALID_ISSUER), RefusedSet("not-a-string", SetFailureReason.MALFORMED)),
            result.refused,
        )
        assertEquals(1, polls.size)
        assertEquals("/ssf/v1/poll/$stream", polls[0].requestUrl?.encodedPath)
        assertEquals(
            Json.parseToJsonElement(
                """{"maxEvents":10,"returnImmediately":true,"ack":["done-1","done-2"],
                    "setErrs":{"old-1":{"err":"invalid_request"}}}""",
            ),
            Json.parseToJsonElement(polls[0].body.readUtf8()),
            "exactly as given, and nothing acknowledged on the caller's behalf",
        )
        assertTrue(polls[0].getHeader("Authorization").orEmpty().startsWith("Bearer cc-"))
        assertNull(polls[0].getHeader("Cookie"))

        // Re-offered unacknowledged, a verified SET is now a replay.
        val again = r.poll(stream)
        assertEquals(JsonObject(emptyMap()), Json.parseToJsonElement(polls[1].body.readUtf8()))
        assertEquals(SetFailureReason.REPLAYED, again.refused.first { it.jti == goodJti }.reason)
    }

    @Test
    fun `poll is not retried on 400 and is retried on 503`() = runBlocking {
        pollAnswer = { json(400, """{"error":"push stream"}""") }
        val r = receiver() // the default client: retry ENABLED
        assertThrows<ValidationError> { runBlocking { r.poll("s-1") } }
        assertEquals(1, polls.size, "a 4xx is decisive")

        val answers = ArrayDeque(listOf(MockResponse().setResponseCode(503), json(200, """{"sets":{}}""")))
        pollAnswer = { answers.removeFirst() }
        val result = r.poll("s-1")
        assertEquals(3, polls.size, "the 503 was retried once")
        assertTrue(result.events.isEmpty() && !result.moreAvailable)
    }

    /**
     * §32.8 helper test 8's two-SET batch (contract 1.59, §34.2 P1): the
     * second SET names an unknown kid while the refetch fails. Afterwards the
     * first SET's jti is not in the store, or the first SET is returned.
     */
    @Test
    fun `a batch whose second SET fails its key fetch loses neither SET`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        jwksFailAfter = 1 // the cold fill succeeds, the unknown kid's refetch answers 503
        val first = claims()
        val second = claims()
        val reply = buildJsonObject {
            put("sets", buildJsonObject {
                put(jtiOf(first), signSet(k, first))
                put(jtiOf(second), signSet(key(), second))
            })
        }.toString()
        pollAnswer = { json(200, reply) }
        val store = RecordingStore()
        val outcome = runCatching { receiverWith(store).poll("s-1") }

        val returned = outcome.getOrNull()?.events.orEmpty().map { it.jti }
        assertTrue(
            jtiOf(first) in returned || jtiOf(first) !in store.recorded,
            "P1: a recorded jti is returned (outcome: ${outcome.exceptionOrNull() ?: "returned $returned"})",
        )
        assertEquals(2, jwksHits.get(), "the cold fill and the one refetch")
        // This SDK's form: what was judged is returned, the unjudged SET is listed and unrecorded.
        val result = outcome.getOrThrow()
        assertEquals(listOf(jtiOf(first)), returned)
        assertTrue(result.refused.isEmpty(), "a failed key fetch is no verdict")
        assertEquals(listOf(jtiOf(second)), result.unjudged)
        assertFalse(jtiOf(second) in store.recorded, "the unjudged SET is not recorded")
        assertEquals(setOf(jtiOf(first)), store.recorded.toSet())
    }

    /**
     * §19.1 `ssf_unjudged` (contract 1.60, SHOULD; §34.4 C-4): a poll that returns leaving SETs
     * unjudged emits one event with their count and the failure category — no jti, no SET.
     */
    @Test
    fun `a poll that leaves SETs unjudged emits ssf_unjudged with the cause`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val sets = List(3) { claims() }
        pollAnswer = {
            json(200, buildJsonObject {
                put("sets", buildJsonObject { for (c in sets) put(jtiOf(c), signSet(k, c)) })
            }.toString())
        }
        val seen = mutableListOf<TelemetryEvent>()
        val hook = TelemetryHook { seen += it }

        receiverWith(RecordingStore(failOn = setOf(jtiOf(sets[1]))), hook).poll("s-1")
        val storeDown = seen.filterIsInstance<TelemetryEvent.SsfUnjudged>()
        assertEquals(listOf(TelemetryEvent.SsfUnjudged("ssf.poll", 2, TelemetryEvent.UnjudgedCause.REPLAY_STORE)), storeDown)
        for (c in sets) assertFalse(jtiOf(c) in storeDown.single().toString(), "no jti in the event")

        // The second SET names a key the JWKS lacks, and its refetch fails.
        seen.clear()
        jwksFailAfter = jwksHits.get() + 1 // the new receiver's cold fill succeeds, its refetch fails
        val other = claims()
        pollAnswer = {
            json(200, buildJsonObject {
                put("sets", buildJsonObject {
                    put(jtiOf(sets[0]), signSet(k, sets[0]))
                    put(jtiOf(other), signSet(key(), other))
                })
            }.toString())
        }
        receiverWith(RecordingStore(), hook).poll("s-1")
        assertEquals(
            listOf(TelemetryEvent.SsfUnjudged("ssf.poll", 1, TelemetryEvent.UnjudgedCause.KEY_FETCH)),
            seen.filterIsInstance<TelemetryEvent.SsfUnjudged>(),
        )

        // A poll that judged every SET emits none.
        seen.clear()
        jwksFailAfter = null
        pollAnswer = {
            json(200, buildJsonObject { put("sets", buildJsonObject { put(jtiOf(other), signSet(k, other)) }) }.toString())
        }
        receiverWith(RecordingStore(), hook).poll("s-1")
        assertTrue(seen.none { it is TelemetryEvent.SsfUnjudged })
    }

    @Test
    fun `a store that cannot answer leaves its SET and the rest unjudged`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val first = claims()
        val second = claims()
        val third = claims()
        val reply = buildJsonObject {
            put("sets", buildJsonObject {
                for (c in listOf(first, second, third)) put(jtiOf(c), signSet(k, c))
            })
        }.toString()
        pollAnswer = { json(200, reply) }
        val store = RecordingStore(failOn = setOf(jtiOf(second)))
        val result = receiverWith(store).poll("s-1")
        assertEquals(listOf(jtiOf(first)), result.events.map { it.jti })
        assertEquals(listOf(jtiOf(second), jtiOf(third)), result.unjudged)
        assertEquals(setOf(jtiOf(first)), store.recorded.toSet())
    }

    /**
     * §32.8 helper test 6, the store-failure case (contract 1.60, §34.2 P4 / B1):
     * a store that cannot answer gives NO verdict. `verify_set` raises the §2 type
     * with no reason code — never `replayed`, never accepted — and records nothing,
     * so the SET, offered again once the store is back, is accepted and not
     * mistaken for a replay.
     */
    @Test
    fun `test 6 - a store that cannot answer gives verifySet no verdict and is never read as replayed`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val store = RecordingStore()
        val r = receiverWith(store)
        val set = signSet(k, claims())

        store.down = true
        val e = assertThrows<NetworkError> { runBlocking { r.verifySet(set) } }
        assertFalse(SetVerificationError::class.isInstance(e), "no reason code: it is not a verdict on the SET")
        assertFalse(AuthError::class.isInstance(e), "and it is not a refusal, least of all `replayed`")
        assertTrue(store.recorded.isEmpty(), "nothing was recorded")

        store.down = false
        val accepted = r.verifySet(set)
        assertEquals(setOf(accepted.jti), store.recorded.toSet(), "once the store answers the SET is new")
        assertEquals(SetFailureReason.REPLAYED, reason(r, set), "and only now a second sighting is a replay")
    }

    /** The same case through `poll`: the SET is in neither list, unrecorded, and not acknowledged by `poll`. */
    @Test
    fun `test 6 - poll returns a SET whose store cannot answer in neither events nor refused`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        val first = claims()
        val second = claims()
        val reply = buildJsonObject {
            put("sets", buildJsonObject {
                put(jtiOf(first), signSet(k, first))
                put(jtiOf(second), signSet(k, second))
            })
        }.toString()
        pollAnswer = { json(200, reply) }
        val store = RecordingStore(failOn = setOf(jtiOf(second)))
        val result = receiverWith(store).poll("s-1")
        assertEquals(listOf(jtiOf(first)), result.events.map { it.jti })
        assertTrue(result.refused.isEmpty(), "unjudged, not refused (and above all not `replayed`)")
        assertEquals(listOf(jtiOf(second)), result.unjudged)
        assertFalse(jtiOf(second) in store.recorded, "its jti is not recorded")
        // poll acknowledges nothing itself: the request it sent carries no `ack`.
        assertFalse("ack" in Json.parseToJsonElement(polls.last().body.readUtf8()).jsonObject)

        // With nothing judged before the failure the failure is raised, never returned as a refusal.
        store.down = true
        assertThrows<NetworkError> { runBlocking { receiverWith(store).poll("s-1") } }
        assertEquals(setOf(jtiOf(first)), store.recorded.toSet())
    }

    /**
     * §32.8 helper test 7 (contract 1.60, §34.2 P6 / A3): a fill that fails counts toward the
     * once-a-minute limit, so the next SET within the minute makes no fetch and is left
     * unjudged; a minute later a fetch is made again. A fill that succeeds is not counted.
     */
    @Test
    fun `test 7 - a failed cold-cache fill counts toward the once-a-minute limit`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        jwksFailAfter = 0 // the JWKS is down
        var now = 0L
        val r = SsfReceiver(
            client(),
            SsfReceiverConfig(issuer, audience, SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString())),
            nanoTime = { now },
        )
        val set = signSet(k, claims())

        val first = assertThrows<NetworkError> { runBlocking { r.verifySet(set) } }
        assertFalse(SetVerificationError::class.isInstance(first), "a failed fill is no verdict")
        assertEquals(1, jwksHits.get(), "the cold fill was attempted")

        now += Duration.ofSeconds(30).toNanos()
        val second = assertThrows<NetworkError> { runBlocking { r.verifySet(signSet(k, claims())) } }
        assertFalse(SetVerificationError::class.isInstance(second), "a second SET within the minute is left unjudged")
        assertEquals(1, jwksHits.get(), "and makes no fetch")

        // A SET refused before step 4 is still a verdict: the limit gates only the key fetch.
        assertEquals(SetFailureReason.INVALID_TYPE, reason(r, sign(k, setHeader(k, typ = "JWT"), claims())))
        assertEquals(1, jwksHits.get())

        // The JWKS recovers; a minute after the failed fill the next SET fetches again.
        jwksFailAfter = null
        now += Duration.ofSeconds(31).toNanos()
        r.verifySet(signSet(k, claims()))
        assertEquals(2, jwksHits.get(), "the limit is a minute, not forever")

        // A fill that succeeded is not a refetch: an unknown kid right after it is refetched once.
        assertEquals(SetFailureReason.INVALID_KEY, reason(r, signSet(key(), claims())))
        assertEquals(3, jwksHits.get(), "exactly one refetch after the successful fill")
    }

    /** The same through `poll`: a SET after a failed fill, inside the minute, is left unjudged without a fetch. */
    @Test
    fun `test 7 - a failed fill leaves the next batch unjudged without a fetch`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        jwksFailAfter = 0
        val c = claims()
        pollAnswer = {
            json(200, buildJsonObject { put("sets", buildJsonObject { put(jtiOf(c), signSet(k, c)) }) }.toString())
        }
        val store = RecordingStore()
        val r = receiverWith(store)
        assertThrows<NetworkError> { runBlocking { r.poll("s-1") } }
        assertThrows<NetworkError> { runBlocking { r.poll("s-1") } }
        assertEquals(1, jwksHits.get(), "the second poll, inside the minute, made no JWKS fetch")
        assertTrue(store.recorded.isEmpty())
    }

    @Test
    fun `a key fetch failure before anything was accepted is raised with nothing recorded`() {
        val k = key()
        jwksKeys = listOf(k)
        jwksFailAfter = 0 // the JWKS is down
        val c = claims()
        val reply = buildJsonObject { put("sets", buildJsonObject { put(jtiOf(c), signSet(k, c)) }) }.toString()
        pollAnswer = { json(200, reply) }
        val store = RecordingStore()
        assertThrows<NetworkError> { runBlocking { receiverWith(store).poll("s-1") } }
        assertTrue(store.recorded.isEmpty())
    }

    @Test
    fun `discovery supplies the jwks_uri and must name the issuer`() = runBlocking {
        val k = key()
        jwksKeys = listOf(k)
        discovery = """{"issuer":"$issuer","jwks_uri":"${server.url("/oauth2/jwks")}"}"""
        val viaDiscovery = receiver(keys = SsfKeySource.DiscoveryUrl(server.url("/.well-known/ssf-configuration").toString()))
        viaDiscovery.verifySet(signSet(k, claims()))

        val wrong = receiver(
            keys = SsfKeySource.DiscoveryUrl(server.url("/.well-known/ssf-configuration").toString()),
            issuer = "https://someone-else.test",
        )
        val e = assertThrows<NetworkError> { runBlocking { wrong.verifySet(signSet(k, claims())) } }
        assertFalse(e.message.orEmpty().startsWith("SET refused"), "a key-source failure is not a verdict")

        val pushOnly = SsfReceiver(
            client(),
            SsfReceiverConfig(issuer, audience, SsfKeySource.JwksUri(server.url("/oauth2/jwks").toString())),
        )
        assertThrows<AuthError> { runBlocking { pushOnly.poll("s") } }
        assertEquals(0, polls.size, "no provider, no request")
    }

    @Test
    fun `a JWKS fetch failure is a NetworkError, not a verdict`() {
        val k = key()
        val r = receiver(keys = SsfKeySource.JwksUri(server.url("/missing/jwks").toString()))
        val e = assertThrows<NetworkError> { runBlocking { r.verifySet(signSet(k, claims())) } }
        assertFalse(e.message.orEmpty().startsWith("SET refused"), "a fetch failure is not a verdict")
    }

    @Test
    fun `a non-https key source is refused at configuration`() {
        for (source in listOf(
            SsfKeySource.JwksUri("http://iam.example.test/oauth2/jwks"),
            SsfKeySource.DiscoveryUrl("not a url"),
        )) {
            assertThrows<ValidationError> { SsfReceiver(client(), SsfReceiverConfig(issuer, audience, source)) }
        }
        assertThrows<ValidationError> {
            SsfReceiver(client(), SsfReceiverConfig("", audience, SsfKeySource.JwksUri("https://x.test/jwks")))
        }
    }

    @Test
    fun `push codes are RFC 8935 codes`() {
        val expected = mapOf(
            SetFailureReason.MALFORMED to "invalid_request",
            SetFailureReason.INVALID_TYPE to "invalid_request",
            SetFailureReason.REPLAYED to "invalid_request",
            SetFailureReason.INVALID_KEY to "invalid_key",
            SetFailureReason.INVALID_ISSUER to "invalid_issuer",
            SetFailureReason.INVALID_AUDIENCE to "invalid_audience",
            SetFailureReason.INVALID_REQUEST to "invalid_request",
        )
        for ((reason, code) in expected) {
            assertEquals(code, reason.pushErrorCode())
            assertEquals(SetErr(code), SetErr.fromReason(reason))
        }
        assertEquals("replayed", SetFailureReason.REPLAYED.toString())
        assertEquals(8, listOf(
            SsfEventTypes.SESSION_REVOKED, SsfEventTypes.CREDENTIAL_CHANGE, SsfEventTypes.ASSURANCE_LEVEL_CHANGE,
            SsfEventTypes.ACCOUNT_DISABLED, SsfEventTypes.ACCOUNT_ENABLED, SsfEventTypes.ACCOUNT_PURGED,
            SsfEventTypes.VERIFICATION, SsfEventTypes.STREAM_UPDATED,
        ).toSet().size)
    }

    @Test
    fun `the memory store refuses a second sighting and forgets after the window`() {
        var now = Instant.parse("2026-10-09T00:00:00Z")
        val clock = object : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId?) = this
            override fun instant() = now
        }
        val store = MemoryReplayStore(clock)
        assertTrue(store.checkAndRecord("a", Duration.ofSeconds(60)))
        assertFalse(store.checkAndRecord("a", Duration.ofSeconds(60)))
        now = now.plusSeconds(61)
        assertTrue(store.checkAndRecord("a", Duration.ofSeconds(60)), "expired, so new again")
    }

    // -- edges ---------------------------------------------------------------------

    @Test
    fun `poll maps 404 and 409 like management, and a key that is not the jti is refused`() = runBlocking {
        val r = receiver()
        pollAnswer = { json(404, """{"message":"no such stream"}""") }
        assertThrows<io.axiam.sdk.errors.NotFoundError> { runBlocking { r.poll("s-1") } }
        pollAnswer = { json(409, """{"error":"conflict"}""") }
        assertThrows<io.axiam.sdk.errors.ConflictError> { runBlocking { r.poll("s-1") } }

        val k = key()
        jwksKeys = listOf(k)
        val reply = buildJsonObject {
            put("sets", buildJsonObject { put("another-key", signSet(k, claims())) })
        }.toString()
        pollAnswer = { json(200, reply) }
        val result = r.poll("s-1")
        assertEquals(listOf(RefusedSet("another-key", SetFailureReason.INVALID_REQUEST)), result.refused)
        assertFalse(result.moreAvailable)
    }

    @Test
    fun `an audience that is neither a string nor an array is invalid_audience`() {
        val k = key()
        jwksKeys = listOf(k)
        assertEquals(
            SetFailureReason.INVALID_AUDIENCE,
            reason(receiver(), signSet(k, claims().with("aud", JsonPrimitive(42)))),
        )
    }

    @Test
    fun `a discovery document that cannot be fetched or names no jwks_uri is a NetworkError`() {
        val k = key()
        jwksKeys = listOf(k)
        val source = SsfKeySource.DiscoveryUrl(server.url("/.well-known/ssf-configuration").toString())
        discovery = null // 404
        assertThrows<NetworkError> { runBlocking { receiver(keys = source).verifySet(signSet(k, claims())) } }
        discovery = """{"issuer":"$issuer"}"""
        assertThrows<NetworkError> { runBlocking { receiver(keys = source).verifySet(signSet(k, claims())) } }
        discovery = """{"issuer":"$issuer","jwks_uri":"http://iam.example.test/oauth2/jwks"}"""
        assertThrows<NetworkError> { runBlocking { receiver(keys = source).verifySet(signSet(k, claims())) } }
    }
}
