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
        val server = MockWebServer().also { s ->
            s.dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    if ((request.path ?: "").startsWith("/oauth2/jwks")) {
                        fetches.incrementAndGet()
                        if (status != 200) {
                            MockResponse().setResponseCode(status).setBody("down")
                        } else {
                            MockResponse().setResponseCode(200)
                                .addHeader("Content-Type", "application/json")
                                .setBody(JWKSet(published.get().map { it.toPublicJWK() }).toString())
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
