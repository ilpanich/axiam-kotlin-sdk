package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcTestKit
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AxiamOidcLoginTest {

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

    private fun client() = OidcTestKit.clientFor(server, clientSecret = null)

    @Test
    fun `GET login redirects to the authorization URL and parks state`() = testApplication {
        val axiamClient = client()
        val store = MemoryOidcStateStore()
        application {
            routing {
                axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback", store = store)
            }
        }
        val response = this.client.config { followRedirects = false }.get("/login")
        assertEquals(HttpStatusCode.Found, response.status)
        val location = response.headers[HttpHeaders.Location]
        assertNotNull(location)
        assertTrue(location!!.contains("response_type=code"))
        assertEquals(1, store.size)
    }

    @Test
    fun `GET login with return_to captures it for the post-login redirect`() = testApplication {
        val axiomClient = client()
        val store = MemoryOidcStateStore()
        application {
            routing {
                axiamOidcLogin(axiomClient, redirectUri = "https://app.example.com/callback", store = store)
            }
        }
        this.client.config { followRedirects = false }.get("/login?return_to=/dashboard")
        assertEquals(1, store.size)
    }

    @Test
    fun `GET login responds 503 when AXIAM discovery is unreachable`() = testApplication {
        server.shutdown()
        val axiamClient = client()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback") }
        }
        val response = this.client.get("/login")
        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
        assertTrue(response.bodyAsText().contains("oidc_unavailable"))
    }

    @Test
    fun `GET callback with an idp error responds 401 authentication_failed`() = testApplication {
        val axiamClient = client()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback") }
        }
        val response = this.client.get("/callback?error=access_denied&error_description=user+said+no")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("authentication_failed"))
        assertTrue(response.bodyAsText().contains("access_denied"))
    }

    @Test
    fun `GET callback missing state or code responds 400 invalid_request`() = testApplication {
        val axiamClient = client()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback") }
        }
        val response = this.client.get("/callback?code=abc")
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.bodyAsText().contains("invalid_request"))
    }

    @Test
    fun `GET callback with an unknown state responds 401 authentication_failed`() = testApplication {
        val axiamClient = client()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback") }
        }
        val response = this.client.get("/callback?state=never-issued&code=abc")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `full happy path - login then callback exchanges the code and returns a JSON summary`() = testApplication {
        val axiamClient = client()
        val store = MemoryOidcStateStore()
        var onSuccessCalled = false
        application {
            routing {
                axiamOidcLogin(
                    axiamClient,
                    redirectUri = "https://app.example.com/callback",
                    store = store,
                    onSuccess = { _, _ -> onSuccessCalled = true },
                )
            }
        }

        val loginResponse = this.client.config { followRedirects = false }.get("/login")
        val location = loginResponse.headers[HttpHeaders.Location]!!
        val state = Regex("state=([^&]+)").find(location)!!.groupValues[1]

        val configuration = axiamClient.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = extractNonce(store, state))
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "acc", idToken = idToken))

        val callbackResponse = this.client.get("/callback?state=$state&code=auth-code")
        assertEquals(HttpStatusCode.OK, callbackResponse.status)
        assertTrue(callbackResponse.bodyAsText().contains("\"authenticated\":true"))
        assertTrue(onSuccessCalled)
    }

    @Test
    fun `happy path with successRedirect sends a 302 instead of the JSON summary`() = testApplication {
        val axiamClient = client()
        val store = MemoryOidcStateStore()
        application {
            routing {
                axiamOidcLogin(
                    axiamClient,
                    redirectUri = "https://app.example.com/callback",
                    store = store,
                    successRedirect = "/welcome",
                )
            }
        }
        val loginResponse = this.client.config { followRedirects = false }.get("/login")
        val location = loginResponse.headers[HttpHeaders.Location]!!
        val state = Regex("state=([^&]+)").find(location)!!.groupValues[1]

        val configuration = axiamClient.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "acc"))

        val callbackResponse = this.client.config { followRedirects = false }.get("/callback?state=$state&code=auth-code")
        assertEquals(HttpStatusCode.Found, callbackResponse.status)
        assertEquals("/welcome", callbackResponse.headers[HttpHeaders.Location])
    }

    @Test
    fun `a token-exchange auth failure responds 401 authentication_failed`() = testApplication {
        val axiamClient = client()
        val store = MemoryOidcStateStore()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback", store = store) }
        }
        val loginResponse = this.client.config { followRedirects = false }.get("/login")
        val location = loginResponse.headers[HttpHeaders.Location]!!
        val state = Regex("state=([^&]+)").find(location)!!.groupValues[1]

        dispatcher.onJson("/oauth2/token", 400, OidcTestKit.oauth2ErrorJson("invalid_grant", "replayed code"))

        val callbackResponse = this.client.get("/callback?state=$state&code=auth-code")
        assertEquals(HttpStatusCode.Unauthorized, callbackResponse.status)
        assertTrue(callbackResponse.bodyAsText().contains("invalid_grant"))
    }

    @Test
    fun `a token-endpoint network failure responds 503 oidc_unavailable`() = testApplication {
        val axiamClient = client()
        val store = MemoryOidcStateStore()
        application {
            routing { axiamOidcLogin(axiamClient, redirectUri = "https://app.example.com/callback", store = store) }
        }
        val loginResponse = this.client.config { followRedirects = false }.get("/login")
        val location = loginResponse.headers[HttpHeaders.Location]!!
        val state = Regex("state=([^&]+)").find(location)!!.groupValues[1]

        server.shutdown()

        val callbackResponse = this.client.get("/callback?state=$state&code=auth-code")
        assertEquals(HttpStatusCode.ServiceUnavailable, callbackResponse.status)
    }

    private suspend fun extractNonce(store: MemoryOidcStateStore, state: String): String {
        // Peek without consuming: re-save after reading, since the real
        // callback path must still be able to consume it single-use.
        val entry = store.consume(state) ?: error("missing state entry")
        store.save(entry)
        return entry.nonce
    }
}
