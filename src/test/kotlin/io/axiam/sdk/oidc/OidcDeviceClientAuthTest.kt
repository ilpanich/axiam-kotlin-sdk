package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.TestSupport
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.util.Collections

/**
 * CONTRACT.md §14.6, the contract 1.62 additions (§14.1 rules 1–4, §14.2 rules 5 and 8): the
 * device grant authenticates its client at BOTH endpoints.
 *
 * A mocked server records exactly what reached `device_authorization` and the token endpoint:
 * the form members, and whether an `Authorization` header was sent. Four client shapes are
 * covered: a confidential client with a secret (`client_secret_post` and `client_secret_basic`
 * registrations behave alike, because the SDK cannot and need not tell them apart: it always sends
 * the secret in the body), a client with an mTLS certificate and no secret, and a public client.
 *
 * Not applicable to this SDK, and so not tested: `private_key_jwt` (§21.8 is optional and this SDK
 * has no client-assertion role, so it never sends `client_assertion`) and a DPoP proof per poll
 * (this SDK verifies DPoP proofs and does not generate them: §21.9's row for Kotlin says "yes",
 * which the source does not bear out, and the README says it does not).
 */
class OidcDeviceClientAuthTest {

    /** One request as it reached the server. */
    private data class Seen(val path: String, val authorization: String?, val cookie: String?, val form: Map<String, String>)

    private lateinit var server: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val seen = Collections.synchronizedList(mutableListOf<Seen>())
    private val refreshCalls = java.util.concurrent.atomic.AtomicInteger(0)
    private val tenantId = "22222222-2222-2222-2222-222222222222"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey())
        dispatcher.on("/api/v1/auth/refresh") {
            refreshCalls.incrementAndGet()
            MockResponse().setResponseCode(401)
        }
        dispatcher.on("/api/v1/auth/login") { TestSupport.loginOkResponse() }
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun record(request: okhttp3.mockwebserver.RecordedRequest) {
        val form = request.body.readUtf8().split('&').filter { it.isNotEmpty() }.associate {
            val eq = it.indexOf('=')
            URLDecoder.decode(it.take(eq), "UTF-8") to URLDecoder.decode(it.substring(eq + 1), "UTF-8")
        }
        seen += Seen(
            request.path!!.substringBefore('?'), request.getHeader("Authorization"), request.getHeader("Cookie"), form,
        )
    }

    private fun mount(authorize: () -> MockResponse = { ok(OidcTestKit.deviceAuthorizationJson(server.url("/").toString(), 30, 1)) },
                      token: (Int) -> MockResponse) {
        dispatcher.on("/oauth2/device_authorization") { record(it); authorize() }
        val polls = java.util.concurrent.atomic.AtomicInteger(0)
        dispatcher.on("/oauth2/token") { record(it); token(polls.getAndIncrement()) }
    }

    private fun ok(body: String) =
        MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody(body)

    private fun error(status: Int, code: String) = MockResponse().setResponseCode(status)
        .addHeader("Content-Type", "application/json").setBody(OidcTestKit.oauth2ErrorJson(code, "$code description"))

    private fun authorizations() = seen.filter { it.path == "/oauth2/device_authorization" }
    private fun polls() = seen.filter { it.path == "/oauth2/token" }

    private fun confidential(secret: String? = OidcTestKit.CLIENT_SECRET) =
        OidcTestKit.clientFor(server, clientSecret = secret)

    private fun mtlsClient(): AxiamClient {
        val identity = HeldCertificate.Builder().commonName("device-client").build()
        return AxiamClient.builder(server.url("/").toString(), tenantId)
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .clientCertificate(identity.certificatePem().toByteArray(), identity.privateKeyPkcs8Pem().toByteArray())
            .build()
    }

    private fun login(client: AxiamClient) = runBlocking {
        client.deviceLogin(DeviceLoginParams(tenantId = tenantId, onUserCode = { }))
    }

    // -- a confidential client ----------------------------------------------------------------

    @Test
    fun `a client with a secret sends it in the body at the authorization and at every poll, and no Authorization header`() {
        mount { n -> if (n < 2) error(400, "authorization_pending") else ok(OidcTestKit.tokenResponseJson(accessToken = "t")) }

        val tokens = login(confidential())

        assertEquals("t", tokens.accessToken.expose())
        assertEquals(1, authorizations().size)
        assertEquals(3, polls().size, "two pending answers and the grant")
        for (request in authorizations() + polls()) {
            assertEquals(OidcTestKit.CLIENT_SECRET, request.form["client_secret"], "${request.path}: client_secret in the form body")
            assertEquals(OidcTestKit.CLIENT_ID, request.form["client_id"], "${request.path}: client_id")
            assertNull(request.authorization, "${request.path}: never Authorization: Basic (§12.1 rule 3), whatever the registration")
            assertFalse(request.form.containsKey("client_assertion"))
            assertFalse(request.form.containsKey("client_assertion_type"))
        }
        // The poll's own members are unchanged.
        assertEquals(DEVICE_GRANT, polls().first().form["grant_type"])
        assertEquals(OidcTestKit.DEVICE_CODE, polls().first().form["device_code"])
    }

    @Test
    fun `deviceAuthorize and devicePoll called directly send the secret too`() = runBlocking {
        mount { ok(OidcTestKit.tokenResponseJson(accessToken = "direct")) }
        val client = confidential()

        val authorization = client.deviceAuthorize(DeviceAuthorizeParams(scope = "openid", tenantId = tenantId))
        client.devicePoll(DevicePollParams(deviceCode = authorization.deviceCode, tenantId = tenantId))

        assertEquals(OidcTestKit.CLIENT_SECRET, authorizations().single().form["client_secret"])
        assertEquals(OidcTestKit.CLIENT_SECRET, polls().single().form["client_secret"])
        assertEquals(OidcTestKit.CLIENT_ID, polls().single().form["client_id"])
        assertNull(authorizations().single().authorization)
        assertNull(polls().single().authorization)
    }

    @Test
    fun `a signed-in client sends no session credential at either endpoint`() = runBlocking {
        mount { ok(OidcTestKit.tokenResponseJson(accessToken = "direct")) }
        val client = confidential()
        client.login("alice@example.com", "pw")

        val authorization = client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))
        client.devicePoll(DevicePollParams(deviceCode = authorization.deviceCode, tenantId = tenantId))

        for (request in authorizations() + polls()) {
            assertNull(request.authorization, "${request.path}: the one credential that reaches the server is the client's")
            assertNull(request.cookie, "${request.path}: and no session cookie")
        }
        assertEquals(OidcTestKit.CLIENT_SECRET, polls().single().form["client_secret"])
    }

    // -- a certificate client ----------------------------------------------------------------

    @Test
    fun `an mTLS client sends client_id and no secret and no Authorization header at both endpoints`() {
        mount { ok(OidcTestKit.tokenResponseJson(accessToken = "mtls")) }

        login(mtlsClient())

        val sent = authorizations() + polls()
        assertEquals(2, sent.size)
        for (request in sent) {
            assertEquals(OidcTestKit.CLIENT_ID, request.form["client_id"])
            assertFalse(request.form.containsKey("client_secret"), "a certificate client invents no secret")
            assertNull(request.authorization)
        }
    }

    // -- a public client ---------------------------------------------------------------------

    @Test
    fun `a public client sends client_id and no credential at either endpoint and is not refused client-side`() {
        mount { n -> if (n == 0) error(400, "authorization_pending") else ok(OidcTestKit.tokenResponseJson(accessToken = "pub")) }

        val tokens = login(confidential(secret = null))

        assertEquals("pub", tokens.accessToken.expose())
        assertEquals(1, authorizations().size)
        assertEquals(2, polls().size)
        for (request in authorizations() + polls()) {
            assertEquals(OidcTestKit.CLIENT_ID, request.form["client_id"], "${request.path}: the poll names its client")
            assertFalse(request.form.containsKey("client_secret"), "${request.path}: a public client sends none")
            assertFalse(request.form.containsKey("client_assertion"))
            assertNull(request.authorization)
        }
    }

    // -- 401 invalid_client -------------------------------------------------------------------

    @Test
    fun `a 401 invalid_client from the authorization raises OAuthProtocolError after exactly one request`() {
        mount(authorize = { error(401, "invalid_client") }) { ok(OidcTestKit.tokenResponseJson()) }

        val e = assertThrows(OAuthProtocolError::class.java) { login(confidential()) }

        assertEquals("invalid_client", e.error)
        assertEquals(1, authorizations().size, "no retry")
        assertEquals(0, polls().size, "and no poll")
        assertEquals(0, refreshCalls.get(), "a failed client authentication never enters the §9 refresh guard")
    }

    @Test
    fun `a 401 invalid_client from the poll is terminal, is never retried and never refreshed`() {
        mount { error(401, "invalid_client") }

        val e = assertThrows(OAuthProtocolError::class.java) { login(confidential()) }

        assertEquals("invalid_client", e.error)
        assertEquals(1, polls().size, "terminal: exactly one poll, never retried")
        assertEquals(0, refreshCalls.get())
    }

    @Test
    fun `a 401 invalid_client from the poll of a signed-in client does not enter the refresh guard either`() = runBlocking {
        mount { error(401, "invalid_client") }
        val client = confidential()
        client.login("alice@example.com", "pw")

        val authorization = client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))
        val e = assertThrows(OAuthProtocolError::class.java) {
            runBlocking { client.devicePoll(DevicePollParams(deviceCode = authorization.deviceCode, tenantId = tenantId)) }
        }

        assertEquals("invalid_client", e.error)
        assertEquals(1, polls().size)
        assertEquals(0, refreshCalls.get(), "not an expired session, and retrying cannot fix it")
    }

    @Test
    fun `a 400 unauthorized_client at the authorization is the servers answer for a client without the grant`() {
        mount(authorize = { error(400, "unauthorized_client") }) { ok(OidcTestKit.tokenResponseJson()) }

        val e = assertThrows(OAuthProtocolError::class.java) { login(confidential()) }

        assertEquals("unauthorized_client", e.error)
        assertEquals(1, authorizations().size)
        assertTrue(polls().isEmpty())
    }

    private companion object {
        const val DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
    }
}
