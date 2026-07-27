package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.UUID

class OidcSsoTest {

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

    private fun findRequest(pathPrefix: String) = generateSequence { server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) }
        .first { it.path!!.startsWith(pathPrefix) }

    @Test
    fun `ssoStart with a UUID tenant and an explicit orgId posts the tenant_id + org_id form`(): Unit = runBlocking {
        val orgId = UUID.randomUUID()
        val client = AxiamClient.builder(server.url("/").toString(), "22222222-2222-2222-2222-222222222222")
            .orgId(orgId)
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .build()
        dispatcher.onJson(
            "/api/v1/auth/federation/oidc/start",
            200,
            """{"authorize_url": "https://idp.example.com/auth", "state": "s-1", "expires_in_secs": 600}""",
        )

        val result = client.ssoStart(
            SsoStartParams(federationConfigId = "fed-1", redirectUri = "https://app.example.com/sso-cb"),
        )
        assertEquals("https://idp.example.com/auth", result.authorizeUrl)
        assertEquals("s-1", result.state)
        assertEquals(600L, result.expiresInSecs)

        val request = findRequest("/api/v1/auth/federation/oidc/start")
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"tenant_id\""))
        assertTrue(body.contains(orgId.toString()))
        assertTrue(body.contains("fed-1"))
    }

    @Test
    fun `ssoStart with a slug tenant and orgSlug posts the tenant_slug + org_slug form`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant")
            .orgSlug("acme-org")
            .build()
        dispatcher.onJson(
            "/api/v1/auth/federation/oidc/start",
            200,
            """{"authorize_url": "https://idp.example.com/auth", "state": "s-2", "expires_in_secs": 600}""",
        )

        client.ssoStart(SsoStartParams(federationConfigId = "fed-1", redirectUri = "https://app.example.com/sso-cb"))

        val body = findRequest("/api/v1/auth/federation/oidc/start").body.readUtf8()
        assertTrue(body.contains("\"tenant_slug\":\"acme-tenant\""))
        assertTrue(body.contains("\"org_slug\":\"acme-org\""))
    }

    @Test
    fun `ssoStart raises AuthError client-side, no wire call, when no organization context resolves`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant").build()
        assertThrows(AuthError::class.java) {
            runBlocking {
                client.ssoStart(SsoStartParams(federationConfigId = "fed-1", redirectUri = "https://app.example.com/sso-cb"))
            }
        }
        // No wire call: the request queue holds nothing for the federation path.
        assertEquals(null, server.takeRequest(200, java.util.concurrent.TimeUnit.MILLISECONDS))
    }

    @Test
    fun `an explicit org or tenant argument overrides the client's configured context`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant").orgSlug("acme-org").build()
        dispatcher.onJson(
            "/api/v1/auth/federation/oidc/start",
            200,
            """{"authorize_url": "https://idp.example.com/auth", "state": "s-3", "expires_in_secs": 600}""",
        )
        client.ssoStart(
            SsoStartParams(
                federationConfigId = "fed-1",
                redirectUri = "https://app.example.com/sso-cb",
                orgId = "44444444-4444-4444-4444-444444444444",
            ),
        )
        val body = findRequest("/api/v1/auth/federation/oidc/start").body.readUtf8()
        assertTrue(body.contains("44444444-4444-4444-4444-444444444444"))
        assertTrue(!body.contains("acme-org"))
    }

    @Test
    fun `ssoStart does NOT parse a 401 as OAuthProtocolError - federation error shape is undocumented`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant").orgSlug("acme-org").build()
        dispatcher.onJson("/api/v1/auth/federation/oidc/start", 401, OidcTestKit.oauth2ErrorJson("invalid_grant", "whatever"))

        val ex = assertThrows(io.axiam.sdk.errors.AuthError::class.java) {
            runBlocking {
                client.ssoStart(SsoStartParams(federationConfigId = "fed-1", redirectUri = "https://app.example.com/sso-cb"))
            }
        }
        assertTrue(ex !is OAuthProtocolError)
    }

    @Test
    fun `ssoComplete posts state and code, captures the session cookie, and returns no token material`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "22222222-2222-2222-2222-222222222222").build()
        dispatcher.on("/api/v1/auth/federation/oidc/callback") {
            okhttp3.mockwebserver.MockResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .addHeader("Set-Cookie", "axiam_access=some.jwt.value; Path=/")
                .setBody(
                    """{"user_id": "u-1", "session_id": "sess-1", "expires_in": 900, "redirect_uri": "https://app.example.com/home"}""",
                )
        }

        val result = client.ssoComplete(SsoCompleteParams(state = "s-1", code = "the-code"))
        assertEquals("u-1", result.userId)
        assertEquals("sess-1", result.sessionId)
        assertEquals(900L, result.expiresIn)
        assertEquals("https://app.example.com/home", result.redirectUri)

        val request = findRequest("/api/v1/auth/federation/oidc/callback")
        assertTrue(request.body.readUtf8().let { it.contains("s-1") && it.contains("the-code") })

        // §4: the cookie jar captured the Set-Cookie automatically — proven by
        // a subsequent same-host request now carrying the resulting bearer
        // token (AuthHeaderInterceptor reads it straight from the jar).
        client.oidcDiscover()
        val discoveryRequest = findRequest("/.well-known/openid-configuration")
        assertEquals("Bearer some.jwt.value", discoveryRequest.getHeader("Authorization"))
    }

    @Test
    fun `ssoComplete maps a non-200 via the generic taxonomy`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "22222222-2222-2222-2222-222222222222").build()
        dispatcher.onJson("/api/v1/auth/federation/oidc/callback", 401, """{"error":"unauthorized"}""")
        assertThrows(io.axiam.sdk.errors.AuthError::class.java) {
            runBlocking { client.ssoComplete(SsoCompleteParams(state = "s", code = "c")) }
        }
    }
}
