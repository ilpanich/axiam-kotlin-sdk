package io.axiam.sdk.oidc

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

/**
 * CONTRACT.md §12.1 rule 3 (contract 1.65, C165-23, C165-25): no redirect is followed from a POST
 * to an `/oauth2/` (any path) endpoint, and a `3xx` is a [NetworkError] whatever its body says.
 */
class OAuth2NoRedirectTest {

    private lateinit var server: MockWebServer
    private lateinit var other: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val tenantId = "22222222-2222-2222-2222-222222222222"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey())
        server.dispatcher = dispatcher
        server.start()
        other = MockWebServer().also { it.start() }
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        other.shutdown()
    }

    private fun redirectTokenTo(code: Int, body: String = "") {
        val target = other.url("/oauth2/token").toString()
        dispatcher.on("/oauth2/token") {
            MockResponse().setResponseCode(code).addHeader("Location", target).setBody(body)
        }
    }

    private fun assertNothingLeaked(e: Throwable, vararg secrets: String) {
        assertNull(other.takeRequest(300, TimeUnit.MILLISECONDS), "the second host must see no request")
        assertEquals(0, other.requestCount)
        val text = generateSequence(e) { it.cause }.joinToString(" | ") { it.toString() }
        secrets.forEach { assertFalse(text.contains(it), "the error must not carry $it") }
        assertFalse(text.contains(other.hostName + ":" + other.port), "the Location is not echoed")
    }

    @Test
    fun `oidcRefresh answered 307 is a NetworkError and the second host sees nothing`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = "s3cret")
        client.oidcDiscover()
        redirectTokenTo(307)

        val e = assertThrows(NetworkError::class.java) {
            runBlocking { client.oidcRefresh(OidcRefreshParams.of("the-refresh-token", tenantId = tenantId)) }
        }
        assertNothingLeaked(e, "the-refresh-token", "s3cret")
    }

    @Test
    fun `loginClientCredentials answered 308 is a NetworkError and the second host sees nothing`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = "s3cret")
        client.oidcDiscover()
        redirectTokenTo(308)

        val e = assertThrows(NetworkError::class.java) {
            runBlocking { client.loginClientCredentials(LoginClientCredentialsParams(tenantId = tenantId)) }
        }
        assertNothingLeaked(e, "s3cret")
    }

    @Test
    fun `a 302 is not followed as a GET either`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = "s3cret")
        client.oidcDiscover()
        redirectTokenTo(302)

        val e = assertThrows(NetworkError::class.java) {
            runBlocking { client.oidcRefresh(OidcRefreshParams.of("rt", tenantId = tenantId)) }
        }
        assertNothingLeaked(e, "rt", "s3cret")
    }

    @Test
    fun `a 3xx carrying an OAuth2 error body is a NetworkError, not an OAuthProtocolError`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = "s3cret")
        client.oidcDiscover()
        redirectTokenTo(307, OidcTestKit.oauth2ErrorJson("invalid_grant", "nope"))

        val e = assertThrows(NetworkError::class.java) {
            runBlocking { client.oidcRefresh(OidcRefreshParams.of("rt", tenantId = tenantId)) }
        }
        // A runtime check: the two types are unrelated, so a compile-time `is` is rejected
        // by Kotlin 2.4 (IMPOSSIBLE_IS_CHECK_ERROR); the mapping is what is being asserted.
        assertFalse(OAuthProtocolError::class.java.isInstance(e))
        assertNothingLeaked(e, "rt", "s3cret")
        assertTrue(server.requestCount >= 1)
    }
}
