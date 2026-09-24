package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.management.PageRequest
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * CONTRACT.md §6.1 rules 6-10 (contract 1.51) — `authenticateDevice()`.
 *
 * The mTLS device login: no body, the certificate is the credential, three
 * fields back, no refresh token. The mock here is plain HTTP on loopback, so
 * the certificate is configured but never presented on the wire (exactly as
 * the reference (Rust) `tests/device_auth_test.rs` notes of its own mock) —
 * what these tests pin is this SDK's side: the gate before the wire, the
 * request shape, the adoption, and the refusal to send a 401 into the §9
 * refresh guard.
 */
class DeviceAuthTest {

    private lateinit var server: MockWebServer
    private val seen = mutableListOf<RecordedRequest>()
    private val routes = ConcurrentHashMap<String, MockResponse>()

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                val path = request.path.orEmpty().substringBefore('?')
                return routes["${request.method} $path"]
                    ?: MockResponse().setResponseCode(501).setBody("no route mounted for ${request.method} $path")
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun mount(method: String, path: String, status: Int, body: String) {
        routes["$method $path"] = TestSupport.json(status, body)
    }

    private fun deviceIdentity(): Pair<String, String> {
        val cert = HeldCertificate.Builder().commonName("device-001").build()
        return cert.certificatePem() to cert.privateKeyPkcs8Pem()
    }

    private fun deviceClient(): AxiamClient {
        val (cert, key) = deviceIdentity()
        return AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .clientCertificate(cert.toByteArray(), key.toByteArray())
            .build()
    }

    private fun deviceTokenJwt(): String = TestSupport.fakeJwt(sub = "sa-${UUID.randomUUID()}")

    private fun mountDeviceLogin(token: String) {
        mount(
            "POST", "/api/v1/auth/device", 200,
            """{"access_token":"$token","token_type":"Bearer","expires_in":900}""",
        )
    }

    private fun requestsTo(path: String): List<RecordedRequest> = seen.filter { it.path?.substringBefore('?') == path }

    private fun header(r: RecordedRequest, name: String): String? = r.getHeader(name)

    // -------------------------------------------------------------------
    // Rule 7 — unreachable without a certificate
    // -------------------------------------------------------------------

    /**
     * Without a certificate the server can only answer `401`, so the SDK
     * answers first: `AuthError`, zero wire calls.
     */
    @Test
    fun `without a certificate it fails with no wire call`() {
        val client = TestSupport.clientFor(server)

        val err = assertThrows(AuthError::class.java) { runBlocking { client.authenticateDevice() } }

        assertTrue(err.message!!.contains("clientCertificate"), err.message)
        assertTrue(seen.isEmpty(), "§6.1 rule 7: refused before the network")
    }

    // -------------------------------------------------------------------
    // Rule 6 — one call, no body, three fields back, adopted
    // -------------------------------------------------------------------

    @Test
    fun `it posts no body and returns the three fields`() {
        val token = deviceTokenJwt()
        mountDeviceLogin(token)
        val client = deviceClient()

        val result = runBlocking { client.authenticateDevice() }

        assertEquals(token, result.accessToken.expose())
        assertEquals("Bearer", result.tokenType)
        assertEquals(900L, result.expiresIn)
        val rendered = result.toString()
        assertFalse(rendered.contains(token), "§7: the token must not appear in toString: $rendered")

        val sent = requestsTo("/api/v1/auth/device")
        assertEquals(1, sent.size, "exactly one attempt")
        assertEquals(0L, sent[0].bodySize, "the certificate is the credential")
        assertEquals(TestSupport.TENANT_ID, header(sent[0], "X-Tenant-ID"))
        assertNull(header(sent[0], "authorization"))
    }

    /**
     * The token is adopted: what follows sends it as a bearer — on the §27
     * surface and on `checkAccess` alike — which a cookie session never does.
     */
    @Test
    fun `the token is adopted as the clients bearer credential`() {
        val token = deviceTokenJwt()
        mountDeviceLogin(token)
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        mount("POST", "/api/v1/authz/check", 200, """{"allowed":true}""")
        val client = deviceClient()
        runBlocking { client.authenticateDevice() }

        runBlocking {
            client.groups.list(PageRequest(limit = 50))
            assertTrue(client.can("read", UUID.randomUUID().toString()))
        }

        val expected = "Bearer $token"
        for (route in listOf("/api/v1/groups", "/api/v1/authz/check")) {
            val sent = requestsTo(route)
            assertEquals(expected, header(sent[0], "authorization"), route)
        }
    }

    /**
     * A client that held a cookie session and then authenticates as a device
     * must not send the old session's cookie beside the device token: the
     * server reads the cookie first, so it would silently win and the
     * request would run as the previous principal.
     *
     * Observed at the REAL OkHttp client boundary ([RecordedRequest], as
     * [MockWebServer] captures the request MockWebServer's own transport
     * actually sent) rather than at a layer above where the cookie jar
     * attaches cookies — the exact gap the TypeScript port's own device-auth
     * test first fell into (its mock intercepted above that layer, so a
     * "withholds the stale cookie" assertion passed even with the
     * withholding removed).
     */
    @Test
    fun `a device login withholds a previous cookie session`() {
        routes["POST /api/v1/auth/login"] = TestSupport.loginOkResponse()
        val token = deviceTokenJwt()
        mountDeviceLogin(token)
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        val client = deviceClient()

        runBlocking {
            client.login("u@example.com", "hunter2hunter2")
            client.authenticateDevice()
            client.groups.list(PageRequest(limit = 50))
        }

        val deviceCall = requestsTo("/api/v1/auth/device")[0]
        assertFalse(
            (header(deviceCall, "cookie") ?: "").contains("axiam_access"),
            "the device login presents the certificate, not the session",
        )
        val sent = requestsTo("/api/v1/groups")[0]
        assertFalse(
            (header(sent, "cookie") ?: "").contains("axiam_access"),
            "the old session's cookie must be withheld",
        )
        assertEquals("Bearer $token", header(sent, "authorization"))
    }

    /**
     * The I4 twin: a client that never adopted a device token keeps sending
     * its cookie session exactly as it always has (this SDK already sends
     * `Authorization` alongside `Cookie` for every session, unlike the Rust
     * reference — a pre-existing, unrelated design choice this task does not
     * change) — the device path must not have altered that.
     */
    @Test
    fun `a cookie session travels exactly as before, with no device token adopted`() {
        routes["POST /api/v1/auth/login"] = TestSupport.loginOkResponse()
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        val client = TestSupport.clientFor(server)
        runBlocking {
            client.login("u@example.com", "hunter2hunter2")
            client.groups.list(PageRequest(limit = 50))
        }

        val sent = requestsTo("/api/v1/groups")[0]
        assertTrue(
            (header(sent, "authorization") ?: "").startsWith("Bearer "),
            "unchanged pre-existing behaviour",
        )
        assertTrue((header(sent, "cookie") ?: "").contains("axiam_access"))
    }

    // -------------------------------------------------------------------
    // Rules 6 and 8 — refusals, and never the refresh guard
    // -------------------------------------------------------------------

    /**
     * A refused certificate is `401` (server T22.4), surfaced as `AuthError`
     * with the server's message verbatim, and never sent to the §9 guard —
     * this IS the login.
     */
    @Test
    fun `a refused certificate is an auth error and never refreshes`() {
        mount("POST", "/api/v1/auth/device", 401, "certificate is not bound to a service account")
        routes["POST /api/v1/auth/refresh"] = TestSupport.loginOkResponse()
        val client = deviceClient()

        val err = assertThrows(AuthError::class.java) { runBlocking { client.authenticateDevice() } }

        assertTrue(err.message!!.contains("certificate is not bound to a service account"), err.message)
        assertEquals(1, requestsTo("/api/v1/auth/device").size)
        assertTrue(requestsTo("/api/v1/auth/refresh").isEmpty())
    }

    /**
     * The route is rate-limited per IP. A `429` is not an authentication
     * failure, and a login is attempted exactly once (§16).
     */
    @Test
    fun `a rate limited login is not an auth error and is not retried`() {
        routes["POST /api/v1/auth/device"] = MockResponse().setResponseCode(429).addHeader("Retry-After", "1")
        val client = deviceClient()

        val err = assertThrows(Throwable::class.java) { runBlocking { client.authenticateDevice() } }

        assertFalse(err is AuthError, "$err")
        assertEquals(1, requestsTo("/api/v1/auth/device").size)
    }

    /**
     * A later `401` on the device token — expired, or presented without its
     * certificate — is surfaced as `AuthError` without a refresh attempt:
     * there is no refresh token to spend (§6.1 rule 6). Exercised through
     * `checkAccess`, which is the one call that DOES route through the §9
     * reactive-refresh path (`postWithRefresh`) for a cookie session.
     *
     * **This is the test a reverted `session.deviceToken() == null` guard in
     * `postWithRefresh` turns red**: without it, this 401 is (wrongly)
     * treated as refreshable.
     */
    @Test
    fun `a later 401 on the device token does not refresh`() {
        mountDeviceLogin(deviceTokenJwt())
        routes["POST /api/v1/auth/refresh"] = TestSupport.loginOkResponse()
        mount("POST", "/api/v1/authz/check", 401, "token expired")
        val client = deviceClient()
        runBlocking { client.authenticateDevice() }

        val err = assertThrows(AuthError::class.java) {
            runBlocking { client.checkAccess("read", UUID.randomUUID().toString()) }
        }

        // checkAccess's 401 mapping does not read the response body (a
        // pre-existing, general SDK property, not specific to device auth) —
        // what matters here is that it surfaces as AuthError at all, and
        // that no refresh was attempted.
        assertTrue(err.message!!.isNotBlank(), err.message)
        assertTrue(
            requestsTo("/api/v1/auth/refresh").isEmpty(),
            "§6.1 rule 6: nothing for the guard to spend",
        )
        // One attempt, since postWithRefresh's reactive retry never fires.
        assertEquals(1, requestsTo("/api/v1/authz/check").size)
    }

    /**
     * The scenario the guard in `postWithRefresh` actually exists for: a
     * client that held a valid COOKIE session and THEN authenticates as a
     * device must not have a later 401 on the device token trigger a refresh
     * of the OLD cookie session — `session.cachedAccessToken()` still
     * resolves to that stale cookie, so without the device-mode check this
     * would (wrongly) look refreshable.
     *
     * **This is the test a reverted `session.deviceToken() == null` guard in
     * `postWithRefresh` turns red.**
     */
    @Test
    fun `a later 401 after a cookie session switched to a device token still does not refresh`() {
        routes["POST /api/v1/auth/login"] = TestSupport.loginOkResponse()
        mountDeviceLogin(deviceTokenJwt())
        routes["POST /api/v1/auth/refresh"] = TestSupport.loginOkResponse()
        mount("POST", "/api/v1/authz/check", 401, "token expired")
        val client = deviceClient()
        runBlocking {
            client.login("u@example.com", "hunter2hunter2")
            client.authenticateDevice()
        }

        assertThrows(AuthError::class.java) {
            runBlocking { client.checkAccess("read", UUID.randomUUID().toString()) }
        }

        assertTrue(
            requestsTo("/api/v1/auth/refresh").isEmpty(),
            "the stale cookie session must not be refreshed on the device token's 401",
        )
        assertEquals(1, requestsTo("/api/v1/authz/check").size)
    }

    // -------------------------------------------------------------------
    // CONTRACT 1.52 N4.4 (C-12) — a later session-establishing call
    // replaces the device credential.
    // -------------------------------------------------------------------

    /**
     * A device credential is held until replaced (§6.1 rule 11 / N4.4 point
     * 4): a `login()` after `authenticateDevice()` must be the credential
     * every later request sends — the device bearer must stop riding, and
     * the login's own cookie session must resume.
     *
     * Before the C-12 fix, `onCredentialChange()` cleared only the decision
     * memo; nothing released `deviceToken`, so [AuthHeaderInterceptor] kept
     * preferring the stale device bearer and stripping the fresh cookie.
     */
    @Test
    fun `a later login replaces the device credential`() {
        val deviceTok = deviceTokenJwt()
        mountDeviceLogin(deviceTok)
        val loginJwt = TestSupport.fakeJwt(sub = "user-1")
        routes["POST /api/v1/auth/login"] = TestSupport.loginOkResponse(accessJwt = loginJwt)
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        val client = deviceClient()

        runBlocking {
            client.authenticateDevice()
            client.login("u@example.com", "hunter2hunter2")
            client.groups.list(PageRequest(limit = 50))
        }

        val sent = requestsTo("/api/v1/groups")[0]
        assertEquals(
            "Bearer $loginJwt",
            header(sent, "authorization"),
            "the login's cookie session must be the credential, not the stale device token",
        )
        assertTrue(
            (header(sent, "cookie") ?: "").contains("axiam_access"),
            "the cookie must no longer be withheld once the device token is released",
        )
    }

    /**
     * The I4 twin: a login that FAILS must leave a previously-adopted device
     * token exactly as it was (N4.2's reasoning, applied to the SDK's own
     * session-establishing calls generally) — the release happens only on
     * `loginScopeOf`'s success path, never proactively before the wire call.
     * This pins the pre-fix behaviour that must not change.
     */
    @Test
    fun `a refused later login leaves the device credential in place`() {
        val deviceTok = deviceTokenJwt()
        mountDeviceLogin(deviceTok)
        routes["POST /api/v1/auth/login"] = TestSupport.json(401, "invalid credentials")
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        val client = deviceClient()

        runBlocking {
            client.authenticateDevice()
            assertThrows(AuthError::class.java) {
                runBlocking { client.login("u@example.com", "wrong") }
            }
            client.groups.list(PageRequest(limit = 50))
        }

        val sent = requestsTo("/api/v1/groups")[0]
        assertEquals("Bearer $deviceTok", header(sent, "authorization"))
        assertFalse((header(sent, "cookie") ?: "").contains("axiam_access"))
    }

    /**
     * A plain WebAuthn authentication is also a later session-establishing
     * call (§6.1 rule 11 / N4.4 point 4) but does not go through
     * `loginScopeOf` (it never reports `organization_level`) — a separate
     * code path this fix touches, tested separately.
     */
    @Test
    fun `a webauthn authentication also replaces the device credential`() {
        val deviceTok = deviceTokenJwt()
        mountDeviceLogin(deviceTok)
        val webauthnJwt = TestSupport.fakeJwt(sub = "user-2")
        routes["POST /api/v1/auth/webauthn/authenticate/discoverable/finish"] = okhttp3.mockwebserver.MockResponse()
            .setResponseCode(200)
            .addHeader("Content-Type", "application/json")
            .addHeader("Set-Cookie", "axiam_access=$webauthnJwt; Path=/")
            .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
            .setBody(
                """{"access_token":"wa-access","refresh_token":"wa-refresh",""" +
                    """"session_id":"${UUID.randomUUID()}","expires_in":900}""",
            )
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        val client = deviceClient()
        val response = """
            {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
             "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                         "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                         "userHandle":"dXNlci1oYW5kbGU"},
             "type":"public-key","clientExtensionResults":{}}
        """.trimIndent()

        runBlocking {
            client.authenticateDevice()
            client.webauthnDiscoverableFinish(Sensitive.of("state-token"), response)
            client.groups.list(PageRequest(limit = 50))
        }

        val sent = requestsTo("/api/v1/groups")[0]
        assertEquals("Bearer $webauthnJwt", header(sent, "authorization"))
        assertTrue((header(sent, "cookie") ?: "").contains("axiam_access"))
    }
}
