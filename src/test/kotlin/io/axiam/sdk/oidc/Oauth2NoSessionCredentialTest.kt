package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.TestSupport
import io.axiam.sdk.internal.AuthHeaderInterceptor
import io.axiam.sdk.internal.SessionState
import io.axiam.sdk.management.PageRequest
import io.axiam.sdk.management.models.CreateGroupRequest
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.CookieManager
import java.util.Collections

/**
 * CONTRACT.md §14.6, contract 1.62 (C162-05; §12.1 rule 3, §6.1 rule 11): no session or adopted
 * credential on a `/oauth2/` request. After a password login, and in a second run after a device login,
 * `deviceAuthorize`, `devicePoll` and a token request (client credentials, refresh) carry no
 * `Authorization` header and no cookie; the next management request does carry the credential
 * (the control, so the assertion cannot pass for want of one). A credential the caller sets on a
 * single `/oauth2/` call (an RFC 7592 registration token) is untouched.
 */
class Oauth2NoSessionCredentialTest {

    private lateinit var server: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val seen = Collections.synchronizedList(mutableListOf<RecordedRequest>())
    private val tenantId = "22222222-2222-2222-2222-222222222222"
    private val deviceToken = TestSupport.fakeJwt(sub = "sa-device-1")

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey())
        dispatcher.on("/api/v1/auth/login") { TestSupport.loginOkResponse() }
        dispatcher.onJson(
            "/api/v1/auth/device", 200,
            """{"access_token":"$deviceToken","token_type":"Bearer","expires_in":900}""",
        )
        dispatcher.onJson("/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        dispatcher.on("/oauth2/device_authorization") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.deviceAuthorizationJson(server.url("/").toString(), 30, 1))
        }
        dispatcher.on("/oauth2/token") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "t", refreshToken = "r2"))
        }
        dispatcher.on("/oauth2/introspect") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody("""{"active":false}""")
        }
        dispatcher.on("/oauth2/revoke") { seen += it; MockResponse().setResponseCode(200) }
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun certificateClient(): AxiamClient {
        val identity = HeldCertificate.Builder().commonName("device-001").build()
        return AxiamClient.builder(server.url("/").toString(), tenantId)
            .orgId(TestSupport.ORG_ID)
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .oidcClientSecret(OidcTestKit.CLIENT_SECRET)
            .clientCertificate(identity.certificatePem().toByteArray(), identity.privateKeyPkcs8Pem().toByteArray())
            .build()
    }

    private suspend fun runOauth2Calls(client: AxiamClient) {
        val authorization = client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))
        client.devicePoll(DevicePollParams(deviceCode = authorization.deviceCode, tenantId = tenantId))
        client.loginClientCredentials(LoginClientCredentialsParams(tenantId = tenantId))
        client.oidcRefresh(OidcRefreshParams(refreshToken = Sensitive.of(Redaction.secret("r")), tenantId = tenantId))
        client.introspect(IntrospectParams.of("tok", tenantId = tenantId))
        client.revoke(RevokeParams.of("tok", tenantId = tenantId))
    }

    private fun assertNoCredentialOnOauth2() {
        val oauth2 = seen.filter { it.path.orEmpty().startsWith("/oauth2/") }
        val paths = oauth2.map { it.path!!.substringBefore('?') }
        assertTrue(
            paths.containsAll(
                listOf("/oauth2/device_authorization", "/oauth2/token", "/oauth2/introspect", "/oauth2/revoke"),
            ),
            "every operation reached the server: $paths",
        )
        assertTrue(paths.count { it == "/oauth2/token" } >= 3, "device_poll, client credentials and refresh: $paths")
        for (request in oauth2) {
            assertNull(request.getHeader("Authorization"), "${request.path}: no Authorization header")
            assertNull(request.getHeader("Cookie"), "${request.path}: no session cookie")
            assertNull(request.getHeader("X-CSRF-Token"), "${request.path}: no CSRF header")
        }
    }

    @Test
    fun `after a password login no oauth2 request carries a credential and the next management request does`() = runBlocking {
        val client = certificateClient()
        client.login("alice@example.com", "pw")

        runOauth2Calls(client)
        assertNoCredentialOnOauth2()

        client.groups.list(PageRequest(limit = 50))
        val groups = dispatcherRequest("/api/v1/groups")
        assertTrue(
            groups.getHeader("Authorization") != null || groups.getHeader("Cookie") != null,
            "control: the session reaches a management request",
        )
    }

    @Test
    fun `contract 1_63 - a cookie login arms the jar and the CSRF header, and no oauth2 request carries either`() = runBlocking {
        // The mocked server sets the session cookies (axiam_*, axiam_csrf) and the CSRF header on sign-in.
        dispatcher.on("/api/v1/auth/login") {
            TestSupport.loginOkResponse().addHeader("Set-Cookie", "axiam_csrf=csrf-abc; Path=/")
        }
        val posts = Collections.synchronizedList(mutableListOf<RecordedRequest>())
        dispatcher.on("/api/v1/groups") {
            posts += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody("{}")
        }
        val client = certificateClient()
        client.login("alice@example.com", "pw")

        runOauth2Calls(client)
        assertNoCredentialOnOauth2()

        // The control: the next state-changing management request carries the cookie and the CSRF
        // header, so the assertions above cannot pass for want of them. (The reply body is not a
        // group; only the request matters.)
        runCatching { client.groups.create(CreateGroupRequest(description = "d", name = "g")) }
        val control = posts.single { it.method == "POST" }
        assertNotNull(control.getHeader("Cookie"), "control: the jar's cookies reach a management request")
        assertTrue(control.getHeader("Cookie")!!.contains("axiam_"), control.getHeader("Cookie"))
        assertEquals("csrf-abc", control.getHeader("X-CSRF-Token"), "control: the CSRF header is armed")
    }

    @Test
    fun `after a device login no oauth2 request carries a credential and the next management request carries the device token`() =
        runBlocking {
            val client = certificateClient()
            client.authenticateDevice()

            runOauth2Calls(client)
            assertNoCredentialOnOauth2()

            client.groups.list(PageRequest(limit = 50))
            assertEquals("Bearer $deviceToken", dispatcherRequest("/api/v1/groups").getHeader("Authorization"))
        }

    @Test
    fun `an explicit registration token on an oauth2 call survives a session`() = runBlocking {
        val clientId = "dcr-client-1"
        val token = Redaction.secret("reg")
        dispatcher.on("/oauth2/register/$clientId") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody("""{"client_id":"$clientId"}""")
        }
        val client = AxiamClient.builder(server.url("/").toString(), tenantId).build()
        client.login("alice@example.com", "pw")
        val uri = server.url("/oauth2/register/$clientId").newBuilder().addQueryParameter("tenant_id", tenantId).build().toString()

        client.readClientRegistration(uri, Sensitive.of(token))

        val sent = seen.single { it.path.orEmpty().startsWith("/oauth2/register/") }
        assertEquals("Bearer $token", sent.getHeader("Authorization"), "the caller's own credential, nothing else")
        assertNull(sent.getHeader("Cookie"))
    }

    @Test
    fun `the interceptor adds nothing to an oauth2 request and leaves a caller header alone`() {
        val session = SessionState(CookieManager(), server.url("/").toString(), tenantId, null, null)
        val http = OkHttpClient.Builder().addInterceptor(AuthHeaderInterceptor(session)).build()
        val recorded = mutableListOf<RecordedRequest>()
        dispatcher.on("/oauth2/token") { recorded += it; MockResponse().setResponseCode(200).setBody("{}") }
        dispatcher.on("/api/v1/auth/federation/oauth2/start") { recorded += it; MockResponse().setResponseCode(200).setBody("{}") }
        dispatcher.on("/api/v1/other") { recorded += it; MockResponse().setResponseCode(200).setBody("{}") }
        session.adoptDeviceToken(deviceToken)

        http.newCall(Request.Builder().url(server.url("/oauth2/token")).post(okhttp3.FormBody.Builder().build()).build())
            .execute().close()
        http.newCall(
            Request.Builder().url(server.url("/oauth2/token")).header("Authorization", "Bearer explicit")
                .post(okhttp3.FormBody.Builder().build()).build(),
        ).execute().close()
        http.newCall(Request.Builder().url(server.url("/api/v1/auth/federation/oauth2/start")).build()).execute().close()
        http.newCall(Request.Builder().url(server.url("/api/v1/other")).build()).execute().close()

        assertNull(recorded[0].getHeader("Authorization"), "the device token stays off /oauth2/token")
        assertEquals(tenantId, recorded[0].getHeader("X-Tenant-ID"))
        assertEquals("Bearer explicit", recorded[1].getHeader("Authorization"))
        assertNotNull(recorded[2].getHeader("Authorization"), "a federation path under /api/v1 is not /oauth2/*")
        assertNotNull(recorded[3].getHeader("Authorization"))
    }

    @Test
    fun `the exclusion follows the endpoints discovery advertises, not the conventional base path (C163-19)`(): Unit = runBlocking {
        val base = server.url("/").toString()
        val relocated = OidcTestKit.RoutingDispatcher(
            discoveryBody = {
                OidcTestKit.discoveryJson(base)
                    .replace("/oauth2/token", "/idp/token")
                    .replace("/oauth2/device_authorization", "/idp/device")
            },
            jwksBody = { OidcTestKit.jwksJson(OidcTestKit.generateSigningKey().toPublicJWK()) },
        )
        relocated.on("/api/v1/auth/login") { TestSupport.loginOkResponse() }
        relocated.onJson("/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        relocated.on("/idp/device") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.deviceAuthorizationJson(base, 30, 1))
        }
        relocated.on("/idp/token") {
            seen += it
            MockResponse().setResponseCode(400).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.oauth2ErrorJson("authorization_pending", "pending"))
        }
        relocated.on("/idp/elsewhere") {
            seen += it
            MockResponse().setResponseCode(200).setBody("{}")
        }
        server.dispatcher = relocated
        val client = AxiamClient.builder(base, tenantId).oidcClientId(OidcTestKit.CLIENT_ID).build()
        client.login("alice@example.com", "pw")

        // Discovery names the endpoints; from then on they are /oauth2/* requests wherever they sit.
        val authorization = client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))
        runCatching { client.devicePoll(DevicePollParams(authorization.deviceCode, tenantId = tenantId)) }

        val relocatedRequests = seen.filter { it.path.orEmpty().startsWith("/idp/") }
        assertEquals(2, relocatedRequests.size)
        for (r in relocatedRequests) {
            assertNull(r.getHeader("Authorization"), "${r.path}: no session bearer")
            assertNull(r.getHeader("Cookie"), "${r.path}: no cookie")
            assertNull(r.getHeader("X-CSRF-Token"), "${r.path}: no CSRF header")
        }

        // The control, and the boundary: a path discovery did not advertise is an ordinary request.
        val session = SessionState(CookieManager(), base, tenantId, null, null)
        session.adoptDeviceToken(deviceToken)
        session.registerOauth2Endpoints(listOf(server.url("/idp/token").toString()))
        val http = OkHttpClient.Builder().addInterceptor(AuthHeaderInterceptor(session)).build()
        http.newCall(Request.Builder().url(server.url("/idp/token")).build()).execute().close()
        http.newCall(Request.Builder().url(server.url("/idp/elsewhere")).build()).execute().close()
        val token = seen.last { it.path == "/idp/token" }
        val elsewhere = seen.last { it.path == "/idp/elsewhere" }
        assertNull(token.getHeader("Authorization"))
        assertNotNull(elsewhere.getHeader("Authorization"), "not advertised, not under /oauth2/: attached")
    }

    private fun dispatcherRequest(path: String): RecordedRequest {
        while (true) {
            val r = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) ?: error("no request to $path")
            if (r.path!!.substringBefore('?') == path) return r
        }
    }
}
