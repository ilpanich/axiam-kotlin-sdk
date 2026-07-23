package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.SessionState
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpCookie
import java.net.URI
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Direct, in-isolation coverage of [SessionState] — bypassing [AxiamClient] so
 * every error path (near-expiry, refresh transport failures, org resolution,
 * unverified-claims decoding) can be driven without needing a full login flow.
 */
class SessionStateDirectTest {

    private var server: MockWebServer? = null

    @AfterEach
    fun tearDown() {
        server?.shutdown()
    }

    private fun newServer(): MockWebServer = MockWebServer().also {
        it.start()
        server = it
    }

    /** Builds a raw JWT-shaped string from an already-JSON payload (no signature verification). */
    private fun rawToken(payloadJson: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"EdDSA"}""".toByteArray()) + "." +
            enc.encodeToString(payloadJson.toByteArray()) + ".sig"
    }

    private fun newSession(
        srv: MockWebServer,
        tenantId: String = TestSupport.TENANT_ID,
        orgSlug: String? = null,
        orgId: UUID? = null,
        attach: Boolean = true,
    ): SessionState {
        val cookieManager = CookieManager(null, CookiePolicy.ACCEPT_ALL)
        val baseUrl = srv.url("/").toString()
        val session = SessionState(cookieManager, baseUrl, tenantId, orgSlug, orgId)
        if (attach) {
            session.attachHttpClient(
                OkHttpClient.Builder().cookieJar(okhttp3.JavaNetCookieJar(cookieManager)).build(),
            )
        }
        return session
    }

    /**
     * Builds a session whose `axiam_access` cookie is seeded via a REAL
     * request/response round trip through the session's own [OkHttpClient] +
     * `JavaNetCookieJar` (rather than poking the [CookieManager] directly) —
     * so a later refresh response's `Set-Cookie` reliably updates/clears what
     * [SessionState.cachedAccessToken] reads next, exactly as it does through
     * [AxiamClient]. The caller must enqueue the seed response on [srv] FIRST
     * (a 200 with a `Set-Cookie: $cookieName=$cookieValue`), then whatever
     * response the test itself drives [SessionState.doHttpRefresh] with.
     */
    private fun newSessionWithCookie(
        srv: MockWebServer,
        cookieName: String,
        cookieValue: String,
        tenantId: String = TestSupport.TENANT_ID,
        orgSlug: String? = null,
        orgId: UUID? = null,
        attach: Boolean = true,
    ): SessionState {
        val cookieManager = CookieManager(null, CookiePolicy.ACCEPT_ALL)
        val baseUrl = srv.url("/").toString()
        val session = SessionState(cookieManager, baseUrl, tenantId, orgSlug, orgId)
        val client = OkHttpClient.Builder().cookieJar(okhttp3.JavaNetCookieJar(cookieManager)).build()
        if (attach) {
            session.attachHttpClient(client)
        }
        srv.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "$cookieName=$cookieValue; Path=/")
                .setBody("{}"),
        )
        client.newCall(Request.Builder().url(srv.url("/seed")).get().build()).execute().close()
        return session
    }

    @Test
    fun `baseUrl accessor strips the trailing slash`() {
        val srv = newServer()
        val session = newSession(srv)
        assertTrue(session.baseUrl().let { !it.endsWith("/") })
    }

    @Test
    fun `isNearExpiry is false for an undecodable token`() {
        val srv = newServer()
        val session = newSession(srv)
        assertFalse(session.isNearExpiry("not-a-jwt", 5_000))
    }

    @Test
    fun `isNearExpiry is false when the token carries no exp claim`() {
        val srv = newServer()
        val session = newSession(srv)
        val token = rawToken("""{"sub":"u"}""")
        assertFalse(session.isNearExpiry(token, 5_000))
    }

    @Test
    fun `isNearExpiry is true within the buffer and false far out`() {
        val srv = newServer()
        val session = newSession(srv)
        val soon = rawToken("""{"sub":"u","exp":${System.currentTimeMillis() / 1000 + 10}}""")
        assertTrue(session.isNearExpiry(soon, 60_000))
        val later = rawToken("""{"sub":"u","exp":${System.currentTimeMillis() / 1000 + 3600}}""")
        assertFalse(session.isNearExpiry(later, 60_000))
    }

    @Test
    fun `doHttpRefresh throws AuthError when there is no access token`(): Unit = runBlocking {
        val srv = newServer()
        val session = newSession(srv)
        assertThrows(AuthError::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh throws AuthError when tenant_id cannot be resolved`(): Unit = runBlocking {
        val srv = newServer()
        val token = rawToken("""{"sub":"u","exp":${System.currentTimeMillis() / 1000 + 3600}}""")
        val session = newSessionWithCookie(srv, "axiam_access", token)
        assertThrows(AuthError::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh throws AuthError when org_id claim is not a valid UUID`(): Unit = runBlocking {
        val srv = newServer()
        val token = rawToken(
            """{"sub":"u","tenant_id":"${TestSupport.TENANT_UUID}","org_id":"not-a-uuid",""" +
                """"exp":${System.currentTimeMillis() / 1000 + 3600}}""",
        )
        // No configured org id/slug — resolution falls back to the malformed org_id claim.
        val session = newSessionWithCookie(srv, "axiam_access", token)
        assertThrows(AuthError::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh throws IllegalStateException when attachHttpClient was never called`(): Unit = runBlocking {
        val srv = newServer()
        val token = TestSupport.fakeJwt()
        val session = newSessionWithCookie(srv, "axiam_access", token, attach = false)
        assertThrows(IllegalStateException::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh wraps a transport failure as NetworkError`(): Unit = runBlocking {
        // A standalone (unregistered) server: shut down immediately so the
        // refresh POST fails with a connection error, without double-shutdown
        // interfering with @AfterEach.
        val srv = MockWebServer()
        srv.start()
        srv.shutdown()
        val token = TestSupport.fakeJwt()
        val cookieManager = CookieManager(null, CookiePolicy.ACCEPT_ALL)
        val baseUrl = srv.url("/").toString()
        val cookie = HttpCookie("axiam_access", token)
        cookie.path = "/"
        cookieManager.cookieStore.add(URI.create(baseUrl.trimEnd('/')), cookie)
        val session = SessionState(cookieManager, baseUrl, TestSupport.TENANT_ID, null, TestSupport.ORG_ID)
        session.attachHttpClient(
            OkHttpClient.Builder()
                .cookieJar(okhttp3.JavaNetCookieJar(cookieManager))
                .connectTimeout(500, TimeUnit.MILLISECONDS)
                .readTimeout(500, TimeUnit.MILLISECONDS)
                .build(),
        )
        assertThrows(NetworkError::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh throws AuthError when the response has no axiam_access cookie`(): Unit = runBlocking {
        val srv = newServer()
        val token = TestSupport.fakeJwt()
        // Seeded first (consumes its own request/response), THEN the refresh
        // response is enqueued so it's what doHttpRefresh's POST receives.
        val session = newSessionWithCookie(srv, "axiam_access", token, orgId = TestSupport.ORG_ID)
        // The response doesn't renew axiam_access AND explicitly expires the one
        // the session already had, so cookieValue(ACCESS_COOKIE) is null afterward.
        srv.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=; Path=/; Max-Age=0")
                .setBody("{}"),
        )
        assertThrows(AuthError::class.java) { runBlocking { session.doHttpRefresh() } }
    }

    @Test
    fun `doHttpRefresh falls back to now when the refreshed token has no exp`(): Unit = runBlocking {
        val srv = newServer()
        val token = TestSupport.fakeJwt()
        val session = newSessionWithCookie(srv, "axiam_access", token, orgId = TestSupport.ORG_ID)
        val newAccess = rawToken("""{"sub":"u","tenant_id":"${TestSupport.TENANT_UUID}"}""")
        srv.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=$newAccess; Path=/")
                .setBody("{}"),
        )
        val before = System.currentTimeMillis()
        val pair = session.doHttpRefresh()
        assertTrue(pair.expiresAtEpochMs >= before)
        assertEquals(newAccess, pair.access)
    }

    @Test
    fun `decodeUnverifiedClaims returns null for invalid base64 payload`() {
        val bad = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"alg":"EdDSA"}""".toByteArray()) +
            ".not-valid-base64!!!.sig"
        assertNull(SessionState.decodeUnverifiedClaims(bad))
    }

    @Test
    fun `decodeUnverifiedClaims returns null for non-JSON payload text`() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val token = enc.encodeToString("""{"alg":"EdDSA"}""".toByteArray()) + "." +
            enc.encodeToString("not { valid json at all".toByteArray()) + ".sig"
        assertNull(SessionState.decodeUnverifiedClaims(token))
    }

    @Test
    fun `decodeUnverifiedClaims returns null for a non-object JSON payload`() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val token = enc.encodeToString("""{"alg":"EdDSA"}""".toByteArray()) + "." +
            enc.encodeToString("[1,2,3]".toByteArray()) + ".sig"
        assertNull(SessionState.decodeUnverifiedClaims(token))
    }

    @Test
    fun `decodeUnverifiedClaims tolerates JsonNull claim values`() {
        val token = rawToken("""{"sub":null,"tenant_id":null,"exp":1}""")
        val claims = SessionState.decodeUnverifiedClaims(token)
        assertNull(claims!!.sub)
        assertNull(claims.tenantId)
    }

    @Test
    fun `decodeUnverifiedClaims accepts a base64url payload needing padding`() {
        // This payload's base64url (no-padding) encoding is not a multiple of 4
        // characters, exercising padBase64Url's re-added "=" padding.
        val payload = """{"sub":"u","exp":1}"""
        val encodedLen = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray()).length
        assertTrue(encodedLen % 4 != 0)
        val claims = SessionState.decodeUnverifiedClaims(rawToken(payload))
        assertEquals("u", claims!!.sub)
    }
}
