package io.axiam.sdk.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.JwksVerifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §12.4 rules 1-2 (algorithm + signature/kid) via
 * [JwksVerifier.verifyForIdToken] — the SAME verifier the §10 middleware
 * uses, extended (never forked) for the OIDC ID-token path.
 */
class JwksVerifierIdTokenTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var verifier: JwksVerifier

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey("k1")
        server = MockWebServer()
        server.dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.start()
        verifier = JwksVerifier.forJwksUri(server.url("/oauth2/jwks").toString())
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `valid EdDSA id_token verifies and returns its claims`() {
        val token = OidcTestKit.signIdToken(signingKey, issuer = "https://issuer.example.com")
        val claims = verifier.verifyForIdToken(token)
        assertEquals("user-1", claims.subject)
    }

    @Test
    fun `invalid_alg - HS256 is rejected before any key lookup`() {
        val secret = ByteArray(32) { 1 }
        val jwt = com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader(JWSAlgorithm.HS256),
            com.nimbusds.jwt.JWTClaimsSet.Builder().subject("u").build(),
        )
        jwt.sign(MACSigner(secret))
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken(jwt.serialize()) }
        assertEquals("invalid_alg", ex.reason)
    }

    @Test
    fun `invalid_alg - alg none is rejected`() {
        val token = OidcTestKit.rawTokenWithHeader("""{"alg":"none","typ":"JWT"}""")
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken(token) }
        assertEquals("invalid_alg", ex.reason)
    }

    @Test
    fun `unknown_kid - a kid absent from the JWKS fails after one re-fetch`() {
        val token = OidcTestKit.signIdToken(signingKey, issuer = "https://issuer.example.com", kid = "no-such-kid")
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken(token) }
        assertEquals("unknown_kid", ex.reason)
    }

    @Test
    fun `unknown_kid - a missing kid header is treated the same as an unknown kid`() {
        val token = OidcTestKit.signIdToken(signingKey, issuer = "https://issuer.example.com", kid = null)
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken(token) }
        assertEquals("unknown_kid", ex.reason)
    }

    @Test
    fun `invalid_signature - a token signed by a different key sharing the same kid is rejected`() {
        val otherKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        val token = OidcTestKit.signIdToken(otherKey, issuer = "https://issuer.example.com", kid = "k1")
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken(token) }
        assertEquals("invalid_signature", ex.reason)
    }

    @Test
    fun `invalid_signature - a malformed token string is rejected`() {
        val ex = assertThrows(AuthError::class.java) { verifier.verifyForIdToken("not-a-jwt") }
        assertEquals("invalid_signature", ex.reason)
    }

    @Test
    fun `unknown_kid - a JWKS endpoint failure during the re-fetch is folded into unknown_kid`() {
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                MockResponse().setResponseCode(500)
        }
        val freshVerifier = JwksVerifier.forJwksUri(server.url("/oauth2/jwks").toString())
        val token = OidcTestKit.signIdToken(signingKey, issuer = "https://issuer.example.com")
        val ex = assertThrows(AuthError::class.java) { freshVerifier.verifyForIdToken(token) }
        assertEquals("unknown_kid", ex.reason)
    }

    @Test
    fun `forJwksUri rejects a malformed URI`() {
        assertThrows(IllegalArgumentException::class.java) { JwksVerifier.forJwksUri("this is not a url") }
    }
}
