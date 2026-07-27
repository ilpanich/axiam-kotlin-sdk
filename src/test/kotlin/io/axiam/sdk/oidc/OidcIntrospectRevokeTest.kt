package io.axiam.sdk.oidc

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OidcIntrospectRevokeTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `introspect happy path parses every field`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson(
            "/oauth2/introspect",
            200,
            """{"active": true, "sub": "user-1", "client_id": "c1", "scope": "openid", "token_type": "Bearer", "exp": 111, "iat": 222}""",
        )

        val result = client.introspect(
            IntrospectParams.of("some-token", tenantId = "22222222-2222-2222-2222-222222222222"),
        )
        assertTrue(result.active)
        assertEquals("user-1", result.sub)
        assertEquals("c1", result.clientId)
        assertEquals("openid", result.scope)
        assertEquals("Bearer", result.tokenType)
        assertEquals(111L, result.exp)
        assertEquals(222L, result.iat)
    }

    @Test
    fun `introspect on an inactive token only guarantees active=false`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/introspect", 200, """{"active": false}""")

        val result = client.introspect(IntrospectParams.of("some-token", tenantId = "22222222-2222-2222-2222-222222222222"))
        assertFalse(result.active)
        assertEquals(null, result.sub)
    }

    @Test
    fun `introspect requires a configured client secret`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = null)
        client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            runBlocking { client.introspect(IntrospectParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222")) }
        }
    }

    @Test
    fun `a 401 from introspect maps to OAuthProtocolError and does not touch the auth refresh path`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/introspect", 401, OidcTestKit.oauth2ErrorJson("invalid_client", "bad client_secret"))

        val ex = assertThrows(OAuthProtocolError::class.java) {
            runBlocking { client.introspect(IntrospectParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222")) }
        }
        assertEquals("invalid_client", ex.error)
        assertEquals("invalid_client: bad client_secret", ex.message)
        // The §9 refresh guard's target — the cookie-session refresh endpoint
        // — must never be reached from an introspect/revoke 401 (§12.3 rule 3).
        assertFalse(hitRefreshEndpoint())
    }

    @Test
    fun `revoke is idempotent for an unknown token (any 200 is success)`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/revoke", 200, "")

        client.revoke(RevokeParams.of("never-issued-token", tenantId = "22222222-2222-2222-2222-222222222222"))
        // No exception == success.
    }

    @Test
    fun `revoke requires a configured client secret`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = null)
        client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            runBlocking { client.revoke(RevokeParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222")) }
        }
    }

    @Test
    fun `a 401 from revoke maps to OAuthProtocolError, never touching the auth refresh path`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/revoke", 401, OidcTestKit.oauth2ErrorJson("invalid_client", "bad secret"))

        assertThrows(OAuthProtocolError::class.java) {
            runBlocking { client.revoke(RevokeParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222")) }
        }
        assertFalse(hitRefreshEndpoint())
    }

    @Test
    fun `a 5xx from revoke stays a NetworkError, not success`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/revoke", 500, "")

        assertThrows(NetworkError::class.java) {
            runBlocking { client.revoke(RevokeParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222")) }
        }
    }

    @Test
    fun `revoke forwards the optional token_type_hint`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/revoke", 200, "")

        client.revoke(
            RevokeParams.of("t", tokenTypeHint = "refresh_token", tenantId = "22222222-2222-2222-2222-222222222222"),
        )
        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/revoke")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assertTrue(request.body.readUtf8().contains("token_type_hint=refresh_token"))
    }

    private fun hitRefreshEndpoint(): Boolean {
        var found = false
        while (true) {
            val request = server.takeRequest(200, java.util.concurrent.TimeUnit.MILLISECONDS) ?: break
            if (request.path?.startsWith("/api/v1/auth/refresh") == true) found = true
        }
        return found
    }
}
