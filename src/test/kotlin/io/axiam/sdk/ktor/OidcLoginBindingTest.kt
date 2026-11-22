package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcTestKit
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLEncoder
import java.util.concurrent.atomic.AtomicInteger

/**
 * CONTRACT.md §12.8 rules 1, 3 and 4 (contract 1.68; C7, C6) for the Ktor
 * "Login with AXIAM" glue [axiamOidcLogin].
 *
 * C7: the callback must complete only for the browser that called the login
 * route (login CSRF, RFC 6749 §10.12). C6: `return_to` is followed only as a
 * same-origin relative path.
 */
class OidcLoginBindingTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val tokenRequests = AtomicInteger()
    private val onSuccessCalls = AtomicInteger()

    private val httpsRedirect = "https://app.example.com/callback"
    private val hostCookie = "__Host-axiam_oidc_bind"
    private val loopbackCookie = "axiam_oidc_bind"

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        dispatcher.on("/oauth2/token") {
            tokenRequests.incrementAndGet()
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "acc"))
        }
        server.dispatcher = dispatcher
        server.start()
        tokenRequests.set(0)
        onSuccessCalls.set(0)
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun axiam(): AxiamClient = OidcTestKit.clientFor(server, clientSecret = null)

    /** What the browser kept from the login response. */
    private class Login(val state: String, val cookieName: String?, val cookieValue: String?, val setCookies: List<String>)

    private fun ApplicationTestBuilder.mount(
        axiam: AxiamClient,
        store: MemoryOidcStateStore,
        redirectUri: String = httpsRedirect,
        successRedirect: String? = null,
    ) {
        application {
            routing {
                axiamOidcLogin(
                    axiam,
                    redirectUri = redirectUri,
                    store = store,
                    successRedirect = successRedirect,
                    onSuccess = { _, _ -> onSuccessCalls.incrementAndGet() },
                )
            }
        }
    }

    private fun noRedirects(client: HttpClient) = client.config { followRedirects = false }

    private suspend fun login(client: HttpClient, returnTo: String? = null): Login {
        val query = returnTo?.let { "?return_to=" + URLEncoder.encode(it, Charsets.UTF_8) } ?: ""
        val response = noRedirects(client).get("/login$query")
        assertEquals(HttpStatusCode.Found, response.status)
        val state = Regex("state=([^&]+)").find(response.headers[HttpHeaders.Location]!!)!!.groupValues[1]
        val setCookies = response.headers.getAll(HttpHeaders.SetCookie) ?: emptyList()
        val bind = setCookies.firstOrNull { it.startsWith("$hostCookie=") || it.startsWith("$loopbackCookie=") }
        val name = bind?.substringBefore("=")
        return Login(state, name, bind?.substringAfter("=")?.substringBefore(";"), setCookies)
    }

    /** The callback as the browser would send it, with [cookie] (name to value) when given. */
    private suspend fun callback(client: HttpClient, state: String, cookie: Pair<String, String>? = null): HttpResponse =
        noRedirects(client).get("/callback?state=$state&code=auth-code") {
            cookie?.let { header(HttpHeaders.Cookie, "${it.first}=${it.second}") }
        }

    private fun Login.cookie(): Pair<String, String>? = if (cookieName != null && cookieValue != null) cookieName to cookieValue else null

    private fun clearedBy(response: HttpResponse, name: String): Boolean =
        (response.headers.getAll(HttpHeaders.SetCookie) ?: emptyList())
            .any { it.startsWith("$name=;") && it.contains("Max-Age=0") }

    // ---- login response -----------------------------------------------------

    @Test
    fun `the login response sets the host-prefixed binding cookie with the required attributes`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val login = login(client)
        val header = login.setCookies.firstOrNull { it.startsWith("$hostCookie=") }
        assertNotNull(header, "the login response must set $hostCookie")
        val value = header!!.substringAfter("=").substringBefore(";")
        assertTrue(Regex("[A-Za-z0-9_-]{43}").matches(value), "32 random bytes, base64url, no padding: $value")
        assertTrue(header.contains("HttpOnly"), header)
        assertTrue(header.contains("Secure"), header)
        assertTrue(header.contains("SameSite=Lax"), header)
        assertTrue(header.contains("Path=/"), header)
        assertFalse(header.contains("Domain", ignoreCase = true), header)
        val maxAge = Regex("Max-Age=(\\d+)").find(header)?.groupValues?.get(1)?.toInt()
        assertTrue(maxAge != null && maxAge in 1..600, "Max-Age must be at most the store TTL: $header")
    }

    @Test
    fun `every login draws a fresh binding value`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val a = login(client)
        val b = login(client)
        assertNotNull(a.cookieValue)
        assertTrue(a.cookieValue != b.cookieValue)
    }

    @Test
    fun `plain-HTTP loopback uses the fallback name without Secure`() = testApplication {
        mount(axiam(), MemoryOidcStateStore(), redirectUri = "http://localhost:8080/callback")
        val login = login(client)
        val header = login.setCookies.firstOrNull { it.startsWith("$loopbackCookie=") }
        assertNotNull(header, "loopback must use $loopbackCookie")
        assertFalse(header!!.contains("Secure"), header)
        assertTrue(header.contains("HttpOnly") && header.contains("SameSite=Lax"), header)
        assertTrue(login.setCookies.none { it.startsWith("$hostCookie=") })
    }

    @Test
    fun `plain-HTTP to a non-loopback host still uses the host-prefixed name`() = testApplication {
        mount(axiam(), MemoryOidcStateStore(), redirectUri = "http://app.example.com/callback")
        val login = login(client)
        assertNotNull(login.setCookies.firstOrNull { it.startsWith("$hostCookie=") })
        assertTrue(login.setCookies.none { it.startsWith("$loopbackCookie=") })
    }

    // ---- callback: binding ---------------------------------------------------

    @Test
    fun `a valid state with no binding cookie is refused 401 with no exchange and no success callback`() = testApplication {
        val store = MemoryOidcStateStore()
        mount(axiam(), store)
        val login = login(client)

        val response = callback(client, login.state, cookie = null)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(0, tokenRequests.get(), "the code must not be exchanged")
        assertEquals(0, onSuccessCalls.get(), "onSuccess must not run")
        assertTrue(clearedBy(response, hostCookie), "the refusal must clear the cookie")
        // The 401 consumed the entry: the right cookie no longer helps.
        val retry = callback(client, login.state, login.cookie())
        assertEquals(HttpStatusCode.Unauthorized, retry.status)
        assertEquals(0, tokenRequests.get())
    }

    @Test
    fun `a valid state with another login's binding cookie is refused 401`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val attacker = login(client)
        val victim = login(client)

        val response = callback(client, attacker.state, victim.cookie())

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(0, tokenRequests.get())
        assertEquals(0, onSuccessCalls.get())
        assertTrue(clearedBy(response, hostCookie))
    }

    @Test
    fun `the refusal for a wrong browser is byte-identical to the one for an unknown state`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val login = login(client)
        val wrongBrowser = callback(client, login.state, cookie = null)
        val unknown = callback(client, "never-issued", cookie = null)
        assertEquals(unknown.status, wrongBrowser.status)
        assertEquals(unknown.bodyAsText(), wrongBrowser.bodyAsText())
    }

    @Test
    fun `the matching cookie completes the login clears the cookie and a replay is refused`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val login = login(client)

        val response = callback(client, login.state, login.cookie())

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, tokenRequests.get())
        assertEquals(1, onSuccessCalls.get())
        assertTrue(clearedBy(response, hostCookie), "the success response must clear the cookie")
        val replay = callback(client, login.state, login.cookie())
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
    }

    @Test
    fun `every other callback error clears the cookie too`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val idpError = noRedirects(client).get("/callback?error=access_denied")
        assertEquals(HttpStatusCode.Unauthorized, idpError.status)
        assertTrue(clearedBy(idpError, hostCookie), "IdP error")
        val missing = noRedirects(client).get("/callback?state=abc")
        assertEquals(HttpStatusCode.BadRequest, missing.status)
        assertTrue(clearedBy(missing, hostCookie), "missing code")
    }

    @Test
    fun `on loopback the fallback name is read and the host-prefixed one is ignored`() = testApplication {
        mount(axiam(), MemoryOidcStateStore(), redirectUri = "http://localhost:8080/callback")
        val login = login(client)
        assertEquals(loopbackCookie, login.cookieName)
        val wrongName = callback(client, login.state, hostCookie to login.cookieValue!!)
        assertEquals(HttpStatusCode.Unauthorized, wrongName.status)
        assertEquals(0, tokenRequests.get())
    }

    // ---- return_to (C6) ------------------------------------------------------

    @Test
    fun `hostile return_to values are dropped at login and never followed`() {
        for (hostile in listOf("https://evil.example/x", "//evil.example/x", "/\\evil.example", "/a\\b", "/a\r", "/a\u0000", "/a\u007f")) {
            testApplication {
                mount(axiam(), MemoryOidcStateStore())
                val login = login(client, returnTo = hostile)
                val response = callback(client, login.state, login.cookie())
                assertEquals(HttpStatusCode.OK, response.status, "[${hostile.replace("\r", "\\r")}] must fall back to the JSON summary")
                assertNull(response.headers[HttpHeaders.Location], "[$hostile] must not be redirected to")
            }
        }
    }

    @Test
    fun `a same-origin relative return_to is followed`() = testApplication {
        mount(axiam(), MemoryOidcStateStore())
        val login = login(client, returnTo = "/dashboard?tab=1")
        val response = callback(client, login.state, login.cookie())
        assertEquals(HttpStatusCode.Found, response.status)
        assertEquals("/dashboard?tab=1", response.headers[HttpHeaders.Location])
    }

    @Test
    fun `the configured successRedirect still wins over a valid return_to`() = testApplication {
        mount(axiam(), MemoryOidcStateStore(), successRedirect = "/welcome")
        val login = login(client, returnTo = "/dashboard")
        val response = callback(client, login.state, login.cookie())
        assertEquals("/welcome", response.headers[HttpHeaders.Location])
    }
}
