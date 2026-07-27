package io.axiam.sdk.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.AxiamClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.util.Date

/** Shared OIDC test helpers: discovery/JWKS/token JSON builders, a routing [Dispatcher], and ID-token minting. */
object OidcTestKit {

    const val CLIENT_ID = "test-client"
    const val CLIENT_SECRET = "test-secret"

    /** RFC 7636 Appendix B test vector. */
    const val RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const val RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    fun clientFor(
        server: MockWebServer,
        clientId: String? = CLIENT_ID,
        clientSecret: String? = null,
        tenantId: String = "22222222-2222-2222-2222-222222222222",
        discoveryTtlMs: Long? = null,
        clockSkewSec: Int? = null,
    ): AxiamClient {
        val builder = AxiamClient.builder(server.url("/").toString(), tenantId)
        clientId?.let { builder.oidcClientId(it) }
        clientSecret?.let { builder.oidcClientSecret(it) }
        discoveryTtlMs?.let { builder.oidcDiscoveryTtlMillis(it) }
        clockSkewSec?.let { builder.oidcClockSkewSeconds(it) }
        return builder.build()
    }

    fun discoveryJson(base: String): String {
        val origin = base.trimEnd('/')
        return """
            {
              "issuer": "$origin",
              "authorization_endpoint": "$origin/oauth2/authorize",
              "token_endpoint": "$origin/oauth2/token",
              "userinfo_endpoint": "$origin/oauth2/userinfo",
              "jwks_uri": "$origin/oauth2/jwks",
              "revocation_endpoint": "$origin/oauth2/revoke",
              "introspection_endpoint": "$origin/oauth2/introspect",
              "response_types_supported": ["code"],
              "subject_types_supported": ["public"],
              "id_token_signing_alg_values_supported": ["EdDSA"],
              "scopes_supported": ["openid", "profile"],
              "token_endpoint_auth_methods_supported": ["client_secret_post"],
              "claims_supported": ["sub", "iss", "aud"],
              "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"]
            }
        """.trimIndent()
    }

    fun jwksJson(publicKey: OctetKeyPair): String = JWKSet(publicKey).toString()

    fun tokenResponseJson(
        accessToken: String = "access-abc",
        tokenType: String = "Bearer",
        expiresIn: Long = 3600,
        scope: String? = null,
        refreshToken: String? = null,
        idToken: String? = null,
    ): String {
        val fields = mutableListOf(
            "\"access_token\": \"$accessToken\"",
            "\"token_type\": \"$tokenType\"",
            "\"expires_in\": $expiresIn",
        )
        scope?.let { fields.add("\"scope\": \"$it\"") }
        refreshToken?.let { fields.add("\"refresh_token\": \"$it\"") }
        idToken?.let { fields.add("\"id_token\": \"$it\"") }
        return "{ ${fields.joinToString(", ")} }"
    }

    fun oauth2ErrorJson(error: String, description: String): String =
        """{"error": "$error", "error_description": "$description"}"""

    fun generateSigningKey(kid: String = "k1"): OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate()

    /** Signs an ID token, with every claim independently overridable for the §12.4 failure-mode tests. */
    fun signIdToken(
        signingKey: OctetKeyPair,
        issuer: String,
        subject: String = "user-1",
        audience: List<String> = listOf(CLIENT_ID),
        nonce: String? = "nonce-abc",
        expEpochSec: Long = System.currentTimeMillis() / 1000 + 3600,
        iatEpochSec: Long = System.currentTimeMillis() / 1000,
        nbfEpochSec: Long? = null,
        azp: String? = null,
        kid: String? = signingKey.keyID,
        alg: JWSAlgorithm = JWSAlgorithm.EdDSA,
        omitIssuer: Boolean = false,
        omitExp: Boolean = false,
        omitIat: Boolean = false,
        omitNonce: Boolean = false,
    ): String {
        val claimsBuilder = JWTClaimsSet.Builder()
            .subject(subject)
        if (!omitIssuer) claimsBuilder.issuer(issuer)
        if (audience.size == 1) claimsBuilder.audience(audience[0]) else claimsBuilder.audience(audience)
        if (!omitExp) claimsBuilder.expirationTime(Date(expEpochSec * 1000))
        if (!omitIat) claimsBuilder.issueTime(Date(iatEpochSec * 1000))
        nbfEpochSec?.let { claimsBuilder.notBeforeTime(Date(it * 1000)) }
        if (!omitNonce) nonce?.let { claimsBuilder.claim("nonce", it) }
        azp?.let { claimsBuilder.claim("azp", it) }
        claimsBuilder.claim("email", "user@example.com")

        val headerBuilder = JWSHeader.Builder(alg)
        kid?.let { headerBuilder.keyID(it) }
        val jwt = SignedJWT(headerBuilder.build(), claimsBuilder.build())
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    /** Builds a syntactically-valid but unsigned/garbage-signature compact JWS with an explicit (possibly absent) `alg`/`kid` header — for the header-shape failure tests. */
    fun rawTokenWithHeader(headerJson: String, payloadJson: String = """{"sub":"u"}"""): String {
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString(headerJson.toByteArray())
        val payload = enc.encodeToString(payloadJson.toByteArray())
        val sig = enc.encodeToString(ByteArray(8) { 0 })
        return "$header.$payload.$sig"
    }

    /**
     * A routing [Dispatcher] serving `/.well-known/openid-configuration` and
     * `/oauth2/jwks` from the supplied suppliers (call-counted for the
     * discovery cache/single-flight tests), and delegating any other path to
     * a registered handler (404 when none is registered).
     */
    class RoutingDispatcher(
        private val discoveryBody: () -> String,
        private val jwksBody: () -> String,
    ) : Dispatcher() {
        @Volatile var discoveryCallCount: Int = 0
            private set

        @Volatile var jwksCallCount: Int = 0
            private set
        private val handlers = mutableMapOf<String, (RecordedRequest) -> MockResponse>()

        fun on(path: String, handler: (RecordedRequest) -> MockResponse) {
            handlers[path] = handler
        }

        fun onJson(path: String, code: Int, body: String) {
            handlers[path] = {
                MockResponse().setResponseCode(code).addHeader("Content-Type", "application/json").setBody(body)
            }
        }

        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path?.substringBefore('?') ?: ""
            if (path == "/.well-known/openid-configuration") {
                discoveryCallCount++
                return MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(discoveryBody())
            }
            if (path == "/oauth2/jwks") {
                jwksCallCount++
                return MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(jwksBody())
            }
            return handlers[path]?.invoke(request) ?: MockResponse().setResponseCode(404)
        }
    }

    /** Convenience: a [RoutingDispatcher] pre-wired to serve discovery + JWKS for [server]/[signingKey]. */
    fun routingDispatcher(server: MockWebServer, signingKey: OctetKeyPair): RoutingDispatcher =
        RoutingDispatcher(
            discoveryBody = { discoveryJson(server.url("/").toString()) },
            jwksBody = { jwksJson(signingKey.toPublicJWK()) },
        )
}
