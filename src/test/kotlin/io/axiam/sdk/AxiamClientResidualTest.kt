package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Residual [AxiamClient] branches not already exercised elsewhere: plain
 * accessors, `login`'s non-2xx/non-202 status mapping, `logout` without a
 * `jti` claim, `buildUser`'s no-cookie/no-claims failure modes, and
 * `batchCheck`'s error-status mapping.
 */
class AxiamClientResidualTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    /** A JWT-shaped string built from a raw JSON payload — no fields beyond what's given. */
    private fun tokenWithPayload(payloadJson: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"EdDSA"}""".toByteArray()) + "." +
            enc.encodeToString(payloadJson.toByteArray()) + ".sig"
    }

    @Test
    fun `okHttpClient and jwksVerifier accessors expose the client's internals`() {
        TestSupport.clientFor(server).use { client ->
            assertNotNull(client.okHttpClient())
            assertNotNull(client.jwksVerifier())
        }
    }

    @Test
    fun `login maps a non-2xx-non-202 status to an error`(): Unit = runBlocking {
        server.enqueue(MockResponse().setResponseCode(400).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
                runBlocking { client.login("a@b.c", "pw") }
            }
        }
    }

    @Test
    fun `logout throws AuthError when the session token has no jti`(): Unit = runBlocking {
        val noJtiToken = tokenWithPayload(
            """{"sub":"u","tenant_id":"${TestSupport.TENANT_UUID}",""" +
                """"exp":${System.currentTimeMillis() / 1000 + 3600}}""",
        )
        server.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=$noJtiToken; Path=/")
                .setBody("{}"),
        )
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID).build().use { client ->
            client.login("a@b.c", "pw")
            server.takeRequest()
            assertThrows(AuthError::class.java) { runBlocking { client.logout() } }
        }
    }

    @Test
    fun `buildUser throws AuthError when login succeeds without setting the access cookie`(): Unit = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { runBlocking { client.login("a@b.c", "pw") } }
        }
    }

    @Test
    fun `buildUser throws AuthError when the access token has no sub or tenant_id`(): Unit = runBlocking {
        val incompleteToken = tokenWithPayload("""{"exp":${System.currentTimeMillis() / 1000 + 3600}}""")
        server.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=$incompleteToken; Path=/")
                .setBody("{}"),
        )
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { runBlocking { client.login("a@b.c", "pw") } }
        }
    }

    @Test
    fun `batchCheck maps a non-2xx status to an error`(): Unit = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("down"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
                runBlocking { client.batchCheck(listOf(AccessCheck("read", "r-1"))) }
            }
        }
    }

    @Test
    fun `verifySession treats a non-string scope claim as no roles`() {
        // Real EdDSA signature so verifySession's JWKS path succeeds; scope is a
        // number, so claims.getStringClaim("scope") throws and is swallowed.
        val signingKey = com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519)
            .keyID("k1").generate()
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                if ((request.path ?: "").startsWith("/oauth2/jwks")) {
                    MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(com.nimbusds.jose.jwk.JWKSet(signingKey.toPublicJWK()).toString())
                } else {
                    MockResponse().setResponseCode(404)
                }
        }
        val claims = com.nimbusds.jwt.JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .claim("scope", 12345L)
            .expirationTime(java.util.Date(System.currentTimeMillis() + 3_600_000))
            .build()
        val jwt = com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.EdDSA).keyID("k1").build(),
            claims,
        )
        jwt.sign(com.nimbusds.jose.crypto.Ed25519Signer(signingKey))
        TestSupport.clientFor(server).use { client ->
            val user = client.verifySession(jwt.serialize())
            assertEquals("user-1", user.userId)
            assertTrue(user.roles.isEmpty())
        }
    }

    @Test
    fun `close is safe to call after issuing a request`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        val client = TestSupport.clientFor(server)
        client.can("read", "r-1")
        client.close()
    }
}
