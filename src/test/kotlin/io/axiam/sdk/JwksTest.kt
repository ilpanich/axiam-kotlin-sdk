package io.axiam.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date

class JwksTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: OctetKeyPair

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                return if ((request.path ?: "").startsWith("/oauth2/jwks")) {
                    MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(com.nimbusds.jose.jwk.JWKSet(signingKey.toPublicJWK()).toString())
                } else {
                    MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun signEd25519(claims: JWTClaimsSet, kid: String = "k1"): String {
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(kid).build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    private fun claims(tenant: String = TestSupport.TENANT_ID, expOffsetSec: Long = 3600) =
        JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", tenant)
            .claim("scope", "documents:read admin")
            .expirationTime(Date(System.currentTimeMillis() + expOffsetSec * 1000))
            .build()

    @Test
    fun `verifySession accepts a valid EdDSA token and returns the user`() {
        val token = signEd25519(claims())
        TestSupport.clientFor(server).use { client ->
            val user = client.verifySession(token)
            assertEquals("user-1", user.userId)
            assertEquals(TestSupport.TENANT_ID, user.tenantId)
            assertTrue(user.roles.contains("documents:read"))
            assertTrue(user.roles.contains("admin"))
        }
    }

    @Test
    fun `verifySession rejects a non-EdDSA token before any key lookup`() {
        // HS256 token — alg pinning must reject it as AuthError.
        val secret = ByteArray(32) { 1 }
        val jwt = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claims())
        jwt.sign(MACSigner(secret))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { client.verifySession(jwt.serialize()) }
        }
    }

    @Test
    fun `verifySession rejects a token for another tenant`() {
        val token = signEd25519(claims(tenant = "other-tenant"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { client.verifySession(token) }
        }
    }

    @Test
    fun `verifySession rejects an expired token`() {
        val token = signEd25519(claims(expOffsetSec = -10))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { client.verifySession(token) }
        }
    }

    @Test
    fun `verifySession rejects a malformed token`() {
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { client.verifySession("not-a-jwt") }
        }
    }
}
