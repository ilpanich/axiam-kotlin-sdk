package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.TestSupport
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
import java.util.UUID

/** Targeted tests closing edge-case gaps not already hit by the scenario-level suites. */
class OidcCoverageGapsTest {

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
    fun `a slug-only client resolves tenant_id from a prior login's access-token claim`(): Unit = runBlocking {
        val resolvedTenant = UUID.randomUUID()
        dispatcher.on("/api/v1/auth/login") {
            TestSupport.loginOkResponse(accessJwt = TestSupport.fakeJwt(tenantId = resolvedTenant.toString()))
        }
        val client = AxiamClient.builder(server.url("/").toString(), "acme-slug")
            .orgSlug("acme-org")
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .oidcClientSecret(OidcTestKit.CLIENT_SECRET)
            .build()
        client.login("alice@example.com", "pw")
        client.oidcDiscover()
        dispatcher.onJson(
            "/oauth2/introspect",
            200,
            """{"active": true}""",
        )

        val result = client.introspect(IntrospectParams.of("some-token"))
        assertTrue(result.active)

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/introspect")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assertTrue(request.path!!.contains("tenant_id=$resolvedTenant"))
    }

    @Test
    fun `loginClientCredentials can be called with no arguments, relying on defaults`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "22222222-2222-2222-2222-222222222222")
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .oidcClientSecret(OidcTestKit.CLIENT_SECRET)
            .build()
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "default-call-access"))

        val result = client.loginClientCredentials()
        assertEquals("default-call-access", result.accessToken.expose())
    }

    @Test
    fun `a configured clock skew of zero rejects a token that the 60s default would tolerate`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "22222222-2222-2222-2222-222222222222")
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .oidcClockSkewSeconds(0)
            .build()
        val configuration = client.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(
            signingKey,
            issuer = configuration.issuer,
            expEpochSec = System.currentTimeMillis() / 1000 - 5,
            nonce = "n",
        )
        // §12.4 rule 7 (F-13): the /oauth2/token response also carries an
        // access_token/refresh_token pair that MUST never reach the caller
        // once id_token validation fails -- mirror the five sibling SDKs
        // (Go, Python, Rust, PHP, TS) by using a sentinel value here and
        // positively asserting it appears nowhere in the outcome or the
        // error, not merely that *an* error was thrown.
        dispatcher.onJson(
            "/oauth2/token",
            200,
            OidcTestKit.tokenResponseJson(
                accessToken = "should-never-be-returned",
                refreshToken = "should-never-be-returned-either",
                idToken = idToken,
            ),
        )

        val ex = assertThrows(AuthError::class.java) {
            runBlocking {
                client.oidcExchange(
                    OidcExchangeParams.of(
                        "code", "verifier", "https://app.example.com/cb", "n",
                        tenantId = "22222222-2222-2222-2222-222222222222",
                    ),
                )
            }
        }
        assertEquals("token_expired", ex.reason)
        // oidcExchange threw rather than returning an OidcTokenSet, so there
        // is no partial object a caller could read a token out of -- the
        // only observable surface is the exception itself. Assert the
        // sentinel tokens are absent from it.
        assertFalse(ex.message?.contains("should-never-be-returned") ?: false)
        assertFalse(ex.toString().contains("should-never-be-returned"))
    }

    @Test
    fun `a malformed endpoint URL in the discovery document surfaces as NetworkError`(): Unit = runBlocking {
        val origin = server.url("/").toString().trimEnd('/')
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse {
                val path = request.path?.substringBefore('?') ?: ""
                return when (path) {
                    "/.well-known/openid-configuration" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            """
                            {
                              "issuer": "$origin",
                              "authorization_endpoint": "$origin/oauth2/authorize",
                              "token_endpoint": "://not a valid url",
                              "userinfo_endpoint": "$origin/oauth2/userinfo",
                              "jwks_uri": "$origin/oauth2/jwks",
                              "revocation_endpoint": "$origin/oauth2/revoke",
                              "introspection_endpoint": "$origin/oauth2/introspect",
                              "response_types_supported": ["code"],
                              "subject_types_supported": ["public"],
                              "id_token_signing_alg_values_supported": ["EdDSA"],
                              "scopes_supported": ["openid"],
                              "token_endpoint_auth_methods_supported": ["client_secret_post"],
                              "claims_supported": ["sub"],
                              "grant_types_supported": ["authorization_code"]
                            }
                            """.trimIndent(),
                        )
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        val client = OidcTestKit.clientFor(server)
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

    @Test
    fun `oidcBegin preserves an existing query string on the authorization_endpoint`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val withQuery = configuration.copy(authorization_endpoint = configuration.authorization_endpoint + "?foo=bar")
        val request = client.oidcBegin(OidcBeginParams(configuration = withQuery, redirectUri = "https://app.example.com/cb"))
        assertTrue(request.url.contains("foo=bar&"))
        assertTrue(request.url.contains("response_type=code"))
    }

    @Test
    fun `a token response missing a required numeric field surfaces as NetworkError`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, """{"access_token": "a", "token_type": "Bearer"}""")
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

    @Test
    fun `introspect on an empty 200 body defaults to active=false rather than throwing`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/introspect", 200, "")
        val result = client.introspect(IntrospectParams.of("t", tenantId = "22222222-2222-2222-2222-222222222222"))
        assertFalse(result.active)
    }

    @Test
    fun `a 400 body with no error field falls back to the generic taxonomy, not OAuthProtocolError`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 400, """{"something_else": "value"}""")
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
        assertTrue(ex !is OAuthProtocolError)
    }

    @Test
    fun `a malformed (non-JSON) error body falls back to the generic taxonomy`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 400, "not json at all")
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
