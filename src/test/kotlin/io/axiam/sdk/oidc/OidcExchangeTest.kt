package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OidcExchangeTest {

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
    fun `oidcExchange posts a form-encoded body with the tenant_id query parameter and returns a validated token set`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        val configuration = client.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = "the-nonce")
        dispatcher.onJson(
            "/oauth2/token",
            200,
            OidcTestKit.tokenResponseJson(accessToken = "acc-1", refreshToken = "ref-1", idToken = idToken, scope = "openid"),
        )

        val tokens = client.oidcExchange(
            OidcExchangeParams(
                code = "auth-code",
                codeVerifier = Sensitive.of("verifier-value"),
                redirectUri = "https://app.example.com/cb",
                nonce = "the-nonce",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )

        assertEquals("acc-1", tokens.accessToken.expose())
        assertEquals("ref-1", tokens.refreshToken?.expose())
        assertEquals("Bearer", tokens.tokenType)
        assertEquals(3600L, tokens.expiresIn)
        assertEquals("user-1", tokens.idClaims?.sub)

        val recorded = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)
            ?: error("no request recorded")
        // walk to the /oauth2/token request specifically (discovery is first)
        var tokenRequest = recorded
        while (!tokenRequest.path!!.startsWith("/oauth2/token")) {
            tokenRequest = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) ?: error("token request not found")
        }
        assertTrue(tokenRequest.path!!.contains("tenant_id=22222222-2222-2222-2222-222222222222"))
        assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type")?.substringBefore(';'))
        val body = tokenRequest.body.readUtf8()
        assertTrue(body.contains("grant_type=authorization_code"))
        assertTrue(body.contains("code=auth-code"))
        assertTrue(body.contains("code_verifier=verifier-value"))
        assertTrue(body.contains("client_id=${OidcTestKit.CLIENT_ID}"))
        assertTrue(body.contains("client_secret=${OidcTestKit.CLIENT_SECRET}"))
    }

    @Test
    fun `oidcExchange accepts a bare (unwrapped) codeVerifier via the convenience factory`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "acc-2"))

        val tokens = client.oidcExchange(
            OidcExchangeParams.of(
                code = "code",
                codeVerifier = "bare-verifier",
                redirectUri = "https://app.example.com/cb",
                nonce = "n",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )
        assertEquals("acc-2", tokens.accessToken.expose())
        assertNull(tokens.idClaims)
    }

    @Test
    fun `oidcExchange omits client_secret for a public client`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = null)
        val configuration = client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson())

        client.oidcExchange(
            OidcExchangeParams.of("code", "verifier", "https://app.example.com/cb", "n", tenantId = "22222222-2222-2222-2222-222222222222"),
        )

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assertTrue(!request.body.readUtf8().contains("client_secret"))
    }

    @Test
    fun `oidcExchange defaults tenant_id from the client's configured UUID tenant`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, tenantId = "33333333-3333-3333-3333-333333333333")
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson())

        client.oidcExchange(OidcExchangeParams.of("code", "verifier", "https://app.example.com/cb", "n"))

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assertTrue(request.path!!.contains("tenant_id=33333333-3333-3333-3333-333333333333"))
    }

    @Test
    fun `oidcExchange raises AuthError client-side when no tenant_id UUID can be resolved`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, tenantId = "not-a-uuid-slug")
        client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            runBlocking {
                client.oidcExchange(OidcExchangeParams.of("code", "verifier", "https://app.example.com/cb", "n"))
            }
        }
    }

    @Test
    fun `a slug tenantId argument is rejected rather than substituted for the UUID`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            runBlocking {
                client.oidcExchange(
                    OidcExchangeParams.of("code", "verifier", "https://app.example.com/cb", "n", tenantId = "not-a-uuid"),
                )
            }
        }
    }

    @Test
    fun `a 400 OAuth2ErrorResponse from the token endpoint maps to OAuthProtocolError with the exact message format`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 400, OidcTestKit.oauth2ErrorJson("invalid_grant", "the code was already used"))

        val ex = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                client.oidcExchange(
                    OidcExchangeParams.of(
                        "code", "verifier", "https://app.example.com/cb", "n",
                        tenantId = "22222222-2222-2222-2222-222222222222",
                    ),
                )
            }
        }
        assertEquals("invalid_grant", ex.error)
        assertEquals("the code was already used", ex.errorDescription)
        assertEquals("invalid_grant: the code was already used", ex.message)
        assertTrue(ex is io.axiam.sdk.errors.AuthError)
    }

    @Test
    fun `a 400 without an OAuth2ErrorResponse body falls back to the generic taxonomy, not OAuthProtocolError`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 400, "not an oauth2 error body")

        val ex = assertThrows(NetworkError::class.java) {
            runBlocking {
                client.oidcExchange(
                    OidcExchangeParams.of(
                        "code", "verifier", "https://app.example.com/cb", "n",
                        tenantId = "22222222-2222-2222-2222-222222222222",
                    ),
                )
            }
        }
        // `assertThrows(NetworkError::class.java)` above already carries the
        // claim in this test's name: NetworkError and OAuthProtocolError are
        // unrelated types (OAuthProtocolError extends AuthError), so nothing
        // that satisfies the former can be the latter. `ex !is
        // OAuthProtocolError` was therefore a tautology, which the Kotlin 2.4
        // compiler rejects outright rather than warning about. Assert the
        // concrete runtime type instead — that can actually fail, if the
        // fallback ever starts producing a NetworkError subtype.
        assertEquals(NetworkError::class.java, ex.javaClass)
    }

    @Test
    fun `a transport failure surfaces as NetworkError`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        server.shutdown()
        assertThrows(NetworkError::class.java) {
            runBlocking {
                client.oidcExchange(
                    OidcExchangeParams.of(
                        "code", "verifier", "https://app.example.com/cb", "n",
                        tenantId = "22222222-2222-2222-2222-222222222222",
                    ),
                )
            }
        }
    }
}
