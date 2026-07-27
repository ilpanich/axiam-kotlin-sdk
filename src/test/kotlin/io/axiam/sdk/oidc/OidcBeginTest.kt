package io.axiam.sdk.oidc

import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder

class OidcBeginTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        server.dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun queryParams(url: String): Map<String, String> {
        val query = url.substringAfter('?')
        return query.split("&").associate {
            val (k, v) = it.split("=", limit = 2)
            URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
        }
    }

    @Test
    fun `oidcBegin performs no network IO and builds all eight mandated parameters`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val callsBefore = (server.dispatcher as OidcTestKit.RoutingDispatcher).discoveryCallCount

        val request = client.oidcBegin(OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"))

        assertEquals(callsBefore, (server.dispatcher as OidcTestKit.RoutingDispatcher).discoveryCallCount)
        assertTrue(request.url.startsWith(configuration.authorization_endpoint))
        val params = queryParams(request.url)
        assertEquals("code", params["response_type"])
        assertEquals(OidcTestKit.CLIENT_ID, params["client_id"])
        assertEquals("https://app.example.com/cb", params["redirect_uri"])
        assertEquals("openid", params["scope"])
        assertEquals(request.state, params["state"])
        assertEquals(request.nonce, params["nonce"])
        assertEquals("S256", params["code_challenge_method"])
        assertEquals(OidcPkce.computeCodeChallenge(request.codeVerifier.expose()), params["code_challenge"])
    }

    @Test
    fun `oidcBegin adds openid to a caller-supplied scope that omits it`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val request = client.oidcBegin(
            OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb", scope = "profile email"),
        )
        val scope = queryParams(request.url)["scope"]
        assertEquals(listOf("openid", "profile", "email"), scope!!.split(" "))
    }

    @Test
    fun `oidcBegin does not duplicate openid when the caller already included it`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val request = client.oidcBegin(
            OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb", scope = "profile openid"),
        )
        val scope = queryParams(request.url)["scope"]!!.split(" ")
        assertEquals(1, scope.count { it == "openid" })
    }

    @Test
    fun `oidcBegin percent-encodes a space in extraParams as %20, not plus`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val request = client.oidcBegin(
            OidcBeginParams(
                configuration = configuration,
                redirectUri = "https://app.example.com/cb",
                extraParams = mapOf("login_hint" to "alice example"),
            ),
        )
        assertTrue(request.url.contains("login_hint=alice%20example"))
        assertFalse(request.url.contains("login_hint=alice+example"))
    }

    @Test
    fun `oidcBegin rejects extraParams overriding a reserved parameter as a programming error`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        assertThrows(IllegalArgumentException::class.java) {
            client.oidcBegin(
                OidcBeginParams(
                    configuration = configuration,
                    redirectUri = "https://app.example.com/cb",
                    extraParams = mapOf("client_id" to "someone-else"),
                ),
            )
        }
    }

    @Test
    fun `oidcBegin requires oidcClientId to have been configured`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientId = null)
        val configuration = client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            client.oidcBegin(OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"))
        }
    }

    @Test
    fun `two oidcBegin calls never produce the same state, nonce, or code_verifier`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val a = client.oidcBegin(OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"))
        val b = client.oidcBegin(OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"))
        assertTrue(a.state != b.state)
        assertTrue(a.nonce != b.nonce)
        assertTrue(a.codeVerifier.expose() != b.codeVerifier.expose())
    }
}
