package io.axiam.sdk.oidc

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SEC-075: a discovery document's `jwks_uri` is untrusted server-supplied
 * data. It must be constrained to the configured base URL's origin
 * (`https` + same host + same port) or the SDK falls back to the
 * conventional `{baseUrl}/oauth2/jwks` instead of following it — mirroring
 * the PHP SDK's `isSameOriginHttps` fix for the same `SDK-19` class.
 */
class JwksOriginPinningTest {

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

    /**
     * The discovery document claims a `jwks_uri` on a completely different
     * (unreachable, attacker-controlled-in-spirit) origin. If the SDK
     * followed it, this test would hang/fail trying to reach
     * `evil.example.com`; instead it must silently fall back to this
     * server's own `/oauth2/jwks` and the exchange must succeed.
     */
    @Test
    fun `a cross-origin jwks_uri in discovery is not followed - the baseUrl-oauth2-jwks fallback is used instead`(): Unit = runBlocking {
        val origin = server.url("/").toString().trimEnd('/')
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path?.substringBefore('?') ?: ""
                return when (path) {
                    "/.well-known/openid-configuration" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            """
                            {
                              "issuer": "$origin",
                              "authorization_endpoint": "$origin/oauth2/authorize",
                              "token_endpoint": "$origin/oauth2/token",
                              "userinfo_endpoint": "$origin/oauth2/userinfo",
                              "jwks_uri": "https://evil.example.com/steal-the-keys",
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
                    "/oauth2/jwks" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(OidcTestKit.jwksJson(signingKey.toPublicJWK()))
                    "/oauth2/token" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            OidcTestKit.tokenResponseJson(
                                accessToken = "acc-1",
                                idToken = OidcTestKit.signIdToken(signingKey, issuer = origin, nonce = "the-nonce"),
                                scope = "openid",
                            ),
                        )
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        val client = OidcTestKit.clientFor(server)
        val tokens = client.oidcExchange(
            OidcExchangeParams.of(
                code = "auth-code",
                codeVerifier = "verifier-value",
                redirectUri = "https://app.example.com/cb",
                nonce = "the-nonce",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )

        assertEquals("acc-1", tokens.accessToken.expose())
        assertEquals("user-1", tokens.idClaims?.sub)
    }

    /**
     * A relative `jwks_uri` (no scheme/host at all) is not a same-origin
     * `https` URL either — it must fall back rather than being resolved
     * against some ambient base, matching the PHP SDK's guard.
     */
    @Test
    fun `a relative jwks_uri falls back rather than being resolved against an ambient base`(): Unit = runBlocking {
        val origin = server.url("/").toString().trimEnd('/')
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path?.substringBefore('?') ?: ""
                return when (path) {
                    "/.well-known/openid-configuration" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            """
                            {
                              "issuer": "$origin",
                              "authorization_endpoint": "$origin/oauth2/authorize",
                              "token_endpoint": "$origin/oauth2/token",
                              "userinfo_endpoint": "$origin/oauth2/userinfo",
                              "jwks_uri": "/oauth2/jwks",
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
                    "/oauth2/jwks" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(OidcTestKit.jwksJson(signingKey.toPublicJWK()))
                    "/oauth2/token" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            OidcTestKit.tokenResponseJson(
                                accessToken = "acc-2",
                                idToken = OidcTestKit.signIdToken(signingKey, issuer = origin, nonce = "n2"),
                                scope = "openid",
                            ),
                        )
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        val client = OidcTestKit.clientFor(server)
        val tokens = client.oidcExchange(
            OidcExchangeParams.of(
                code = "auth-code",
                codeVerifier = "verifier-value",
                redirectUri = "https://app.example.com/cb",
                nonce = "n2",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )
        assertEquals("acc-2", tokens.accessToken.expose())
    }
}
