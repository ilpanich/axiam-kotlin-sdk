package io.axiam.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Hand-built AXIAM access-token fixtures for the contract 1.68 guard tests
 * (§10.1 rules 10-12, §11.2 rule 11, §3a).
 *
 * The header and the payload are written as raw JSON on purpose: nimbus's
 * claims builder drops a `null`-valued claim, and rule 11 must be tested with
 * `purpose: null`, and with a header that carries no `kid` or no `typ` at all.
 */
object AccessTokenFixtures {

    fun newKey(kid: String = "k1"): OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate()

    /**
     * Signs a compact JWS with [key]. [kid] and [typ] are omitted from the
     * header when `null`. [claims] override and extend the defaults (a valid
     * user token for [TestSupport.TENANT_ID], one hour of life, no `aud`);
     * [omit] removes a default claim.
     */
    fun mint(
        key: OctetKeyPair,
        kid: String? = "k1",
        typ: String? = "at+jwt",
        claims: Map<String, JsonElement> = emptyMap(),
        omit: Set<String> = emptySet(),
    ): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header: JsonObject = buildJsonObject {
            put("alg", "EdDSA")
            if (kid != null) put("kid", kid)
            if (typ != null) put("typ", typ)
        }
        val payload: JsonObject = buildJsonObject {
            put("sub", "user-1")
            put("tenant_id", TestSupport.TENANT_ID)
            put("scope", "openid")
            put("exp", System.currentTimeMillis() / 1000 + 3600)
            claims.forEach { (k, v) -> put(k, v) }
        }.let { built -> JsonObject(built.filterKeys { it !in omit }) }
        val signingInput = enc.encodeToString(header.toString().toByteArray()) + "." +
            enc.encodeToString(payload.toString().toByteArray())
        val signature = Ed25519Signer(key).sign(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).build(),
            signingInput.toByteArray(),
        )
        return "$signingInput.$signature"
    }

    fun str(value: String): JsonElement = JsonPrimitive(value)

    fun strings(vararg values: String): JsonElement =
        kotlinx.serialization.json.JsonArray(values.map { JsonPrimitive(it) })

    /**
     * A JWKS endpoint serving whatever [published] currently holds, counting
     * every `/oauth2/jwks` request in [fetches].
     */
    class Jwks(initial: OctetKeyPair) {
        val published = AtomicReference(listOf(initial))
        val fetches = AtomicInteger()

        /** The status `/oauth2/jwks` answers with; anything but 200 is a failing endpoint. */
        @Volatile
        var status: Int = 200

        /** When true a 200 answers `{"keys":[]}` (the empty set, a failed refresh under §12.4 rule 2). */
        @Volatile
        var emptyKeys: Boolean = false

        /** `Cache-Control` sent with a 200, or null for none. */
        @Volatile
        var cacheControl: String? = null

        /** `ETag` sent with a 200; a request carrying it in `If-None-Match` is answered 304 while [honour304]. */
        @Volatile
        var etag: String? = null

        @Volatile
        var honour304: Boolean = false

        /** When set, a 200 answers exactly this body instead of the published set. */
        @Volatile
        var rawBody: String? = null

        /** `Cache-Control` sent with the 304 answering a conditional request. */
        @Volatile
        var cacheControl304: String? = null

        /** Delay before the response headers, in milliseconds (a stalled endpoint). */
        @Volatile
        var headersDelayMs: Long = 0

        /** When true the 200 body is dripped one byte per 200 ms (a drip-feeding endpoint). */
        @Volatile
        var drip: Boolean = false

        /** Whitespace bytes appended to a 200 body (to reach or pass the size limit). */
        @Volatile
        var padBytes: Int = 0

        /** `Location` sent with a non-200 status. */
        @Volatile
        var location: String? = null

        /** The `If-None-Match` header of every request that carried one. */
        val ifNoneMatches = java.util.concurrent.CopyOnWriteArrayList<String>()
        val server = MockWebServer().also { s ->
            s.dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    if ((request.path ?: "").startsWith("/oauth2/jwks")) {
                        fetches.incrementAndGet()
                        request.getHeader("If-None-Match")?.let { ifNoneMatches.add(it) }
                        if (status != 200) {
                            MockResponse().setResponseCode(status).setBody(if (status == 304) "" else (rawBody ?: "down"))
                                .apply {
                                    cacheControl?.let { addHeader("Cache-Control", it) }
                                    location?.let { addHeader("Location", it) }
                                    setHeadersDelay(headersDelayMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                                }
                        } else if (honour304 && etag != null && request.getHeader("If-None-Match") == etag) {
                            MockResponse().setResponseCode(304).apply {
                                cacheControl304?.let { addHeader("Cache-Control", it) }
                            }
                        } else {
                            MockResponse().setResponseCode(200)
                                .addHeader("Content-Type", "application/json")
                                .apply {
                                    cacheControl?.let { addHeader("Cache-Control", it) }
                                    etag?.let { addHeader("ETag", it) }
                                }
                                .setHeadersDelay(headersDelayMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                                .setBody(
                                    (
                                        if (rawBody != null) rawBody!!
                                        else if (emptyKeys) "{\"keys\":[]}"
                                        else JWKSet(published.get().map { it.toPublicJWK() }).toString()
                                        ) + " ".repeat(padBytes),
                                )
                                .apply {
                                    if (drip) throttleBody(1, 200, java.util.concurrent.TimeUnit.MILLISECONDS)
                                }
                        }
                    } else {
                        MockResponse().setResponseCode(404)
                    }
            }
            s.start()
        }

        fun client(): AxiamClient = TestSupport.clientFor(server)

        fun shutdown() = server.shutdown()
    }
}
