package io.axiam.sdk.ktor

import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcStateEntry
import io.axiam.sdk.oidc.OidcTestKit
import io.axiam.sdk.Sensitive
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The parts of CONTRACT.md §12.8 that need the 1.4.0 API: the success callback
 * that receives the request (rule 2), the integrator's `return_to` predicate
 * (rule 3), the digest on the stored entry (rule 1 (a)) and the entries a
 * caller stores directly (rules 1 (c) and 3).
 */
class OidcLoginBindingHooksTest {

    private lateinit var server: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val tokenRequests = AtomicInteger()
    private val redirectUri = "https://app.example.com/callback"
    private val cookieName = "__Host-axiam_oidc_bind"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey())
        dispatcher.on("/oauth2/token") {
            tokenRequests.incrementAndGet()
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "acc"))
        }
        server.dispatcher = dispatcher
        server.start()
        tokenRequests.set(0)
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun axiam() = OidcTestKit.clientFor(server, clientSecret = null)

    private fun entry(state: String, returnTo: String?, digest: String?) = OidcStateEntry(
        state = state,
        nonce = "n",
        codeVerifier = Sensitive.of("v"),
        redirectUri = redirectUri,
        returnTo = returnTo,
        bindingDigest = digest,
    )

    @Test
    fun `the stored entry carries the SHA-256 digest of the cookie value and never the value`() = testApplication {
        val store = MemoryOidcStateStore()
        application { routing { axiamOidcLogin(axiam(), redirectUri, store = store) } }
        val response = client.config { followRedirects = false }.get("/login")
        val state = Regex("state=([^&]+)").find(response.headers[HttpHeaders.Location]!!)!!.groupValues[1]
        val value = response.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith("$cookieName=") }
            .substringAfter("=").substringBefore(";")
        val stored = store.consume(state)!!
        assertEquals(bindingDigest(value), stored.bindingDigest)
        assertTrue(Regex("[0-9a-f]{64}").matches(stored.bindingDigest!!))
        assertFalse(stored.toString().contains(value))
    }

    @Test
    fun `the success callback receives the request that completed the sign-in`() = testApplication {
        val store = MemoryOidcStateStore()
        val seen = AtomicReference<String?>()
        application {
            routing {
                axiamOidcLogin(
                    axiam(), redirectUri, store = store,
                    onSuccessWithCall = { _, _, call: ApplicationCall -> seen.set(call.request.headers["X-Probe"]) },
                )
            }
        }
        val login = client.config { followRedirects = false }.get("/login")
        val state = Regex("state=([^&]+)").find(login.headers[HttpHeaders.Location]!!)!!.groupValues[1]
        val cookie = login.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith("$cookieName=") }.substringBefore(";")
        val response = client.config { followRedirects = false }.get("/callback?state=$state&code=c") {
            header(HttpHeaders.Cookie, cookie)
            header("X-Probe", "this-request")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("this-request", seen.get())
    }

    @Test
    fun `the old two-argument onSuccess still works and the request hook runs after it`() = testApplication {
        val order = mutableListOf<String>()
        application {
            routing {
                axiamOidcLogin(
                    axiam(), redirectUri,
                    onSuccessWithCall = { _, _, _ -> order += "call" },
                    onSuccess = { _, _ -> order += "plain" },
                )
            }
        }
        val login = client.config { followRedirects = false }.get("/login")
        val state = Regex("state=([^&]+)").find(login.headers[HttpHeaders.Location]!!)!!.groupValues[1]
        val cookie = login.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith("$cookieName=") }.substringBefore(";")
        client.get("/callback?state=$state&code=c") { header(HttpHeaders.Cookie, cookie) }
        assertEquals(listOf("plain", "call"), order)
    }

    @Test
    fun `an entry stored with no binding digest is refused 401 and not exchanged`() = testApplication {
        val store = MemoryOidcStateStore()
        runBlocking { store.save(entry("legacy", returnTo = null, digest = null)) }
        application { routing { axiamOidcLogin(axiam(), redirectUri, store = store) } }
        val response = client.get("/callback?state=legacy&code=c") { header(HttpHeaders.Cookie, "$cookieName=anything") }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(0, tokenRequests.get())
    }

    @Test
    fun `hostile return_to values stored directly in the entry are not followed`() {
        for (hostile in listOf("https://evil.example/x", "//evil.example/x", "/\\evil.example", "/a\\b", "/a\r")) {
            testApplication {
                val store = MemoryOidcStateStore()
                val binding = newBindingValue()
                store.save(entry("s", returnTo = hostile, digest = bindingDigest(binding)))
                application { routing { axiamOidcLogin(axiam(), redirectUri, store = store) } }
                val response = client.config { followRedirects = false }.get("/callback?state=s&code=c") {
                    header(HttpHeaders.Cookie, "$cookieName=$binding")
                }
                assertEquals(HttpStatusCode.OK, response.status, hostile.replace("\r", "\\r"))
                assertNull(response.headers[HttpHeaders.Location])
            }
        }
    }

    @Test
    fun `an integrator predicate widens the rule only for the values it accepts`() = testApplication {
        val store = MemoryOidcStateStore()
        val allow: (String) -> Boolean = { it == "https://app.example/x" }
        application { routing { axiamOidcLogin(axiam(), redirectUri, store = store, allowReturnTo = allow) } }

        suspend fun run(returnTo: String): io.ktor.client.statement.HttpResponse {
            val binding = newBindingValue()
            store.save(entry("s-$returnTo", returnTo = returnTo, digest = bindingDigest(binding)))
            return client.config { followRedirects = false }.get("/callback?state=s-$returnTo&code=c") {
                header(HttpHeaders.Cookie, "$cookieName=$binding")
            }
        }
        assertEquals("https://app.example/x", run("https://app.example/x").headers[HttpHeaders.Location])
        assertNull(run("https://evil.example/x").headers[HttpHeaders.Location])
    }

    @Test
    fun `a predicate that throws accepts nothing`() {
        assertFalse(isAcceptableReturnTo("https://app.example/x") { error("boom") })
        assertTrue(isAcceptableReturnTo("/ok") { error("never consulted for a value the default rule accepts") })
    }

    @Test
    fun `isSafeReturnTo covers the contract's table`() {
        assertTrue(isSafeReturnTo("/dashboard?tab=1"))
        assertTrue(isSafeReturnTo("/"))
        for (bad in listOf("", "dashboard", "https://evil.example/x", "//evil.example/x", "/\\evil.example", "/a\\b", "/a\r", "/a\n", "/a\u0000", "/a\u007f", "javascript:alert(1)")) {
            assertFalse(isSafeReturnTo(bad), bad.replace("\r", "\\r").replace("\n", "\\n"))
        }
    }

    @Test
    fun `the cookie name is a pure function of the redirect URI`() {
        assertEquals("__Host-axiam_oidc_bind", oidcBindingCookieName("https://app.example.com/callback"))
        assertEquals("__Host-axiam_oidc_bind", oidcBindingCookieName("https://localhost/callback"))
        assertEquals("__Host-axiam_oidc_bind", oidcBindingCookieName("http://app.example.com/callback"))
        assertEquals("__Host-axiam_oidc_bind", oidcBindingCookieName("http://localhost.evil.example/callback"))
        assertEquals("axiam_oidc_bind", oidcBindingCookieName("http://localhost:3000/callback"))
        assertEquals("axiam_oidc_bind", oidcBindingCookieName("http://127.0.0.1:3000/callback"))
        assertEquals("axiam_oidc_bind", oidcBindingCookieName("http://[::1]:3000/callback"))
        assertEquals("__Host-axiam_oidc_bind", oidcBindingCookieName("not a uri"))
    }

    @Test
    fun `the memory store is bounded and evicts the oldest entries`() = runBlocking {
        val store = MemoryOidcStateStore(maxEntries = 3)
        for (i in 1..5) store.save(entry("s$i", null, "d"))
        assertEquals(3, store.size)
        assertNotNull(store.consume("s5"))
        assertNull(store.consume("s1"))
    }
}
