package io.axiam.sdk.oidc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.JwksVerifier
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64
import java.util.Date

/**
 * CONTRACT.md §12.7.6, "Contract 1.69 (#880)" — the server-shaped logout token.
 *
 * The header is exactly `{"alg","typ":"logout+jwt","kid"}`, the key set holds two
 * Ed25519 keys with the signing key NOT first (a rotation), and the claims are the
 * server's. A verifier that takes the first or the only key fails these.
 */
class OidcLogoutServerShapedTest {

    private lateinit var server: MockWebServer
    private lateinit var first: OctetKeyPair
    private lateinit var signing: OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        first = OidcTestKit.generateSigningKey("old-key")
        signing = OidcTestKit.generateSigningKey("new-key")
        server = MockWebServer()
        dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = { OidcTestKit.discoveryJson(server.url("/").toString()) },
            // The signing key is NOT first.
            jwksBody = { JWKSet(listOf(first.toPublicJWK(), signing.toPublicJWK())).toString() },
        )
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun issuer() = server.url("/").toString().trimEnd('/')

    private fun client() = OidcTestKit.clientFor(server)

    private fun headerMembers(token: String): Set<String> {
        val json = String(Base64.getUrlDecoder().decode(token.substringBefore('.')))
        return Regex("\"([a-z]+)\"\\s*:").findAll(json).map { it.groupValues[1] }.toSet()
    }

    @Test
    fun `a server-shaped logout token verifies against a two-key JWKS whose signing key is not first`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signing, issuer())

        // The fixture adds nothing the server does not send.
        assertEquals(setOf("alg", "typ", "kid"), headerMembers(token))
        assertEquals("logout+jwt", SignedJWT.parse(token).header.type.type)

        val verified = client().verifyLogoutToken(token)
        assertEquals(OidcTestKit.LOGOUT_SID, verified.sid)
        assertEquals(OidcTestKit.LOGOUT_JTI, verified.jti)
    }

    @Test
    fun `a kid-less logout token is refused as unknown_kid against a one-key JWKS whose key did sign it`(): Unit = runBlocking {
        dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = { OidcTestKit.discoveryJson(server.url("/").toString()) },
            jwksBody = { JWKSet(signing.toPublicJWK()).toString() },
        )
        server.dispatcher = dispatcher
        val token = OidcTestKit.signLogoutToken(signing, issuer(), kid = null)
        assertEquals(setOf("alg", "typ"), headerMembers(token))

        val error = assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
        assertEquals("unknown_kid", error.reason)
    }

    @Test
    fun `a kid-less logout token is refused as unknown_kid against the two-key JWKS`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signing, issuer(), kid = null)

        val error = assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
        assertEquals("unknown_kid", error.reason)
    }

    @Test
    fun `an unknown kid is refused as unknown_kid`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signing, issuer(), kid = "never-published")

        val error = assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
        assertEquals("unknown_kid", error.reason)
    }

    // Rules 10 and 11 of §10.1 stay off the logout and ID-token paths: both tokens verify
    // through the verifier the access-token guard shares, while that guard refuses both.

    private fun idTokenWithTyp(typ: String): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer()).subject("user-1").audience(OidcTestKit.CLIENT_ID)
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
            .issueTime(Date())
            .claim("nonce", "n")
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(signing.keyID).type(JOSEObjectType(typ)).build()
        return SignedJWT(header, claims).also { it.sign(Ed25519Signer(signing)) }.serialize()
    }

    @Test
    fun `rules 10 and 11 stay off the logout path and the ID-token path`() {
        val verifier = JwksVerifier.forJwksUri("${issuer()}/oauth2/jwks")
        val logout = OidcTestKit.signLogoutToken(signing, issuer())
        val idToken = idTokenWithTyp("JWT")

        // The shared verifier accepts both ...
        assertNotNull(verifier.verifyForIdToken(logout))
        assertNotNull(verifier.verifyForIdToken(idToken))
        // ... and the access-token guard's primitive refuses both, by `typ` (rule 10).
        for (token in listOf(logout, idToken)) {
            val error = assertThrows(AuthError::class.java) { verifier.verifyAccessTokenSignature(token) }
            assertTrue(error.message!!.contains("rule 10"), error.message)
        }
    }
}
