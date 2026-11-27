package io.axiam.sdk.ktor

import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcStateEntry
import io.axiam.sdk.oidc.OidcTestKit
import io.axiam.sdk.Sensitive
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.hooks.CallFailed
import io.ktor.server.application.install
import io.ktor.server.response.respondText
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

    private fun cleared(response: io.ktor.client.statement.HttpResponse) =
        response.headers.getAll(HttpHeaders.SetCookie).orEmpty().any {
            it.startsWith("$cookieName=;") && it.contains("Max-Age=0")
        }

    /** Begins a login on [client] and returns the callback request's cookie header and `state`. */
    private suspend fun beginLogin(client: io.ktor.client.HttpClient): Pair<String, String> {
        val login = client.config { followRedirects = false }.get("/login?return_to=${java.net.URLEncoder.encode("/a b/café", "UTF-8")}")
        val state = Regex("state=([^&]+)").find(login.headers[HttpHeaders.Location]!!)!!.groupValues[1]
        val cookie = login.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith("$cookieName=") }.substringBefore(";")
        return cookie to state
    }

    private val errorHandler = createApplicationPlugin("test-error-handler") {
        // An application error handler: it answers 500 and keeps the headers already set.
        on(CallFailed) { call, _ -> call.respondText("boom", status = HttpStatusCode.InternalServerError) }
    }

    @Test
    fun `a success hook that throws still clears the binding cookie (KOT-R1-4)`() = testApplication {
        application {
            install(errorHandler)
            routing { axiamOidcLogin(axiam(), redirectUri, onSuccess = { _, _ -> error("the session store is down") }) }
        }
        val (cookie, state) = beginLogin(client)
        val response = client.config { followRedirects = false }.get("/callback?state=$state&code=c") {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertTrue(cleared(response), "the 500 must carry the clearing Set-Cookie")
    }

    @Test
    fun `a request hook that responds itself still gets the cookie cleared (KOT-R1-4 pin)`() = testApplication {
        val failures = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
        val sent = java.util.concurrent.CopyOnWriteArrayList<String>()
        application {
            install(
                createApplicationPlugin("failure-recorder") {
                    on(CallFailed) { _, cause -> failures += cause }
                    // Every attempt to send a response body, accepted or not.
                    onCallRespond { _, body -> sent += body.toString() }
                },
            )
            routing {
                axiamOidcLogin(
                    axiam(), redirectUri,
                    onSuccessWithCall = { _, _, call -> call.respondText("mine", status = HttpStatusCode.Accepted) },
                )
            }
        }
        val (cookie, state) = beginLogin(client)
        val response = client.config { followRedirects = false }.get("/callback?state=$state&code=c") {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.Accepted, response.status)
        assertEquals("mine", response.bodyAsText())
        assertTrue(cleared(response))
        // The glue must not respond a second time (the isCommitted guard).
        assertTrue(failures.isEmpty(), "the callback failed: $failures")
        assertTrue(sent.none { it.contains("authenticated") }, "the glue responded after the hook did: $sent")
    }

    @Test
    fun `a wrong cookie spends the state, answers the uniform 401 and clears (GLUE-R1-4)`() = testApplication {
        val calls = AtomicInteger()
        application {
            routing { axiamOidcLogin(axiam(), redirectUri, onSuccess = { _, _ -> calls.incrementAndGet() }) }
        }
        val (cookie, state) = beginLogin(client)
        val wrong = client.get("/callback?state=$state&code=c") { header(HttpHeaders.Cookie, "$cookieName=another-logins-value") }
        assertEquals(HttpStatusCode.Unauthorized, wrong.status)
        assertTrue(cleared(wrong))
        // The state is spent: the right cookie now gets the same 401, and nothing was exchanged.
        val retry = client.get("/callback?state=$state&code=c") { header(HttpHeaders.Cookie, cookie) }
        assertEquals(HttpStatusCode.Unauthorized, retry.status)
        assertEquals(wrong.bodyAsText(), retry.bodyAsText())
        assertEquals(0, tokenRequests.get())
        assertEquals(0, calls.get())
    }

    @Test
    fun `a predicate that throws an Error accepts nothing (N4)`() {
        assertFalse(isAcceptableReturnTo("https://app.example/x") { throw NoSuchMethodError("linkage") })
    }

    // Decision 7 (login-glue-binding.md): the adapter encodes the Location value.

    @Test
    fun `the callback redirect carries the percent-encoded return_to - space and non-ASCII (Decision 7)`() = testApplication {
        application { routing { axiamOidcLogin(axiam(), redirectUri) } }
        val (cookie, state) = beginLogin(client)
        val response = client.config { followRedirects = false }.get("/callback?state=$state&code=c") {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.Found, response.status)
        assertEquals("/a%20b/caf%C3%A9", response.headers[HttpHeaders.Location])
        assertTrue(cleared(response))
    }

    @Test
    fun `a CR LF destination admitted by the predicate is encoded and injects no header (Decision 7)`() = testApplication {
        val store = MemoryOidcStateStore()
        val value = newBindingValue()
        val hostile = "https://app.example/x\r\nSet-Cookie: pwned=1"
        runBlocking { store.save(entry("hostile", returnTo = hostile, digest = bindingDigest(value))) }
        application { routing { axiamOidcLogin(axiam(), redirectUri, store = store, allowReturnTo = { true }) } }
        val response = client.config { followRedirects = false }.get("/callback?state=hostile&code=c") {
            header(HttpHeaders.Cookie, "$cookieName=$value")
        }
        assertEquals(HttpStatusCode.Found, response.status)
        val location = response.headers[HttpHeaders.Location]!!
        assertEquals("https://app.example/x%0D%0ASet-Cookie:%20pwned=1", location)
        assertNull(response.headers["pwned"])
        assertFalse(response.headers.getAll(HttpHeaders.SetCookie).orEmpty().any { it.startsWith("pwned") })
    }

    @Test
    fun `encodeRedirectLocation follows the contract table`() {
        assertEquals("/a%20b", encodeRedirectLocation("/a b"))
        assertEquals("/caf%C3%A9", encodeRedirectLocation("/café"))
        assertEquals("/%E2%82%AC", encodeRedirectLocation("/€"))
        assertEquals("/%F0%9F%98%80", encodeRedirectLocation("/\uD83D\uDE00"))
        assertEquals("/%EF%BF%BD", encodeRedirectLocation("/\uD83D"))
        assertEquals("/a%20b", encodeRedirectLocation("/a%20b"))
        assertEquals("/100%25", encodeRedirectLocation("/100%"))
        assertEquals("/%25zz", encodeRedirectLocation("/%zz"))
        assertEquals("/%25%41", encodeRedirectLocation("/%%41"))
        assertEquals("/a%252", encodeRedirectLocation("/a%2"))
        assertEquals("/%EF%BF%BD%EF%BF%BD", encodeRedirectLocation("/\uD800\uD800"))
        assertEquals("/a\\b", encodeRedirectLocation("/a\\b"))
        assertEquals("/%0D%0A", encodeRedirectLocation("/\r\n"))
        assertEquals("/%22%3C%3E%60%7B%7D%7F", encodeRedirectLocation("/\"<>`{}\u007f"))
        assertEquals("/a?b=c&d=e#f", encodeRedirectLocation("/a?b=c&d=e#f"))
        assertTrue(encodeRedirectLocation("/日本 \r\n\u0000é").all { it.code in 0x21..0x7E })
    }

    @Test
    fun `the memory store never overshoots its bound under concurrent saves (KOT-R1-7)`() {
        repeat(20) {
            val store = MemoryOidcStateStore(maxEntries = 50)
            val pool = java.util.concurrent.Executors.newFixedThreadPool(8)
            val start = java.util.concurrent.CountDownLatch(1)
            val maxSeen = AtomicInteger()
            val tasks = (0 until 8).map { t ->
                pool.submit {
                    start.await()
                    for (i in 0 until 400) {
                        runBlocking { store.save(entry("s-$t-$i", null, "d")) }
                        maxSeen.accumulateAndGet(store.size) { a, b -> maxOf(a, b) }
                    }
                }
            }
            start.countDown()
            tasks.forEach { it.get() }
            pool.shutdown()
            assertTrue(maxSeen.get() <= 50, "the store held ${maxSeen.get()} entries, bound is 50")
            assertEquals(50, store.size)
        }
    }
}
