package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.TestSupport
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.PageRequest
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.io.PrintWriter
import java.io.StringWriter
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlin.time.Duration.Companion.seconds

/**
 * CONTRACT.md §37 (contract 1.65) — native sign-in with a provider ID token.
 * One test per entry of §37.9, under the contract's names (camelCase), so the
 * eleven SDKs' suites can be compared. The discovery document is fetched once
 * up front and passed in, so "one request in total" counts the token call only.
 */
class NativeSignInTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val seen = Collections.synchronizedList(mutableListOf<RecordedRequest>())

    @Volatile private var authMethods = """["client_secret_post"]"""

    private val tenantId = "22222222-2222-2222-2222-222222222222"
    private val grant = "urn:axiam:params:oauth:grant-type:provider-id-token"

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = {
                OidcTestKit.discoveryJson(server.url("/").toString())
                    .replace("""["client_secret_post"]""", authMethods)
            },
            jwksBody = { OidcTestKit.jwksJson(signingKey.toPublicJWK()) },
        )
        dispatcher.on("/api/v1/auth/login") { TestSupport.loginOkResponse() }
        dispatcher.on("/api/v1/groups") {
            seen += it
            MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                .setBody("""{"items":[],"total":0,"offset":0,"limit":50}""")
        }
        dispatcher.on("/oauth2/token") {
            seen += it
            tokenOk()
        }
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    // ---- helpers -----------------------------------------------------------

    private fun tokenOk(body: String = OidcTestKit.tokenResponseJson(accessToken = "native-access")) =
        MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody(body)

    private fun respond(response: () -> MockResponse) {
        dispatcher.on("/oauth2/token") {
            seen += it
            response()
        }
    }

    private fun respondJson(code: Int, body: String, vararg headers: Pair<String, String>) = respond {
        MockResponse().setResponseCode(code).addHeader("Content-Type", "application/json").setBody(body)
            .also { r -> headers.forEach { (k, v) -> r.addHeader(k, v) } }
    }

    private fun client(
        secret: String? = null,
        tenant: String = tenantId,
        telemetry: ((io.axiam.sdk.telemetry.TelemetryEvent) -> Unit)? = null,
        clientId: String? = OidcTestKit.CLIENT_ID,
    ): AxiamClient {
        val b = AxiamClient.builder(server.url("/").toString(), tenant).orgId(TestSupport.ORG_ID)
        clientId?.let { b.oidcClientId(it) }
        secret?.let { b.oidcClientSecret(it) }
        telemetry?.let { sink -> b.telemetryHook { sink(it) } }
        return b.build()
    }

    private fun tokenRequests() = synchronized(seen) { seen.filter { it.path.orEmpty().startsWith("/oauth2/token") } }

    private fun pairs(body: String): List<Pair<String, String>> = body.split("&").filter { it.isNotEmpty() }.map {
        val eq = it.indexOf('=')
        URLDecoder.decode(it.substring(0, eq), StandardCharsets.UTF_8) to
            URLDecoder.decode(it.substring(eq + 1), StandardCharsets.UTF_8)
    }

    private fun sha256Hex(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
        .joinToString("") { "%02x".format(it) }

    private suspend fun AxiamClient.signIn(
        configuration: OidcConfiguration,
        provider: String = "corp-okta",
        idToken: String = "provider.id.token",
        nonce: String = "raw-nonce-1",
        scopes: List<String>? = null,
        resource: String? = null,
    ) = loginWithProviderIdToken(
        ProviderIdTokenLoginParams.of(provider, idToken, nonce, scopes, resource, tenantId, configuration),
    )

    // ---- 1 -----------------------------------------------------------------

    @Test
    fun requestBodyExact(): Unit = runBlocking {
        val client = client()
        client.login("alice@example.com", "pw") // a live session, so "no Authorization" is not vacuous
        val configuration = client.oidcDiscover()

        client.signIn(configuration, scopes = listOf("profile", "email"), resource = "https://api.example.com/")
        val full = tokenRequests().single()
        val query = full.requestUrl!!
        assertEquals(tenantId, query.queryParameter("tenant_id"))
        assertEquals("/oauth2/token", query.encodedPath)
        assertEquals("application/x-www-form-urlencoded", full.getHeader("Content-Type")?.substringBefore(';'))
        assertNull(full.getHeader("Authorization"))
        assertNull(full.getHeader("Cookie"))
        assertNull(full.getHeader("X-CSRF-Token"))
        val fields = pairs(full.body.readUtf8())
        assertEquals(
            setOf("grant_type", "client_id", "provider", "id_token", "nonce", "scope", "resource"),
            fields.map { it.first }.toSet(),
        )
        assertEquals(fields.size, fields.map { it.first }.toSet().size, "no field is repeated")
        val map = fields.toMap()
        assertEquals(grant, map["grant_type"])
        assertEquals(OidcTestKit.CLIENT_ID, map["client_id"])
        assertEquals("profile email", map["scope"])
        assertEquals("https://api.example.com/", map["resource"])
        assertFalse(map.containsKey("tenant_id"), "tenant_id is a query parameter, never a body field")

        seen.clear()
        client.signIn(configuration)
        val bare = pairs(tokenRequests().single().body.readUtf8())
        assertEquals(
            setOf("grant_type", "client_id", "provider", "id_token", "nonce"),
            bare.map { it.first }.toSet(),
        )
        assertFalse(bare.any { it.second.split(" ").contains("openid") }, "openid is never added")

        // An empty list of scopes is "none", not `scope=`.
        seen.clear()
        client.signIn(configuration, scopes = emptyList())
        assertFalse(pairs(tokenRequests().single().body.readUtf8()).any { it.first == "scope" })
    }

    // ---- 2 -----------------------------------------------------------------

    @Test
    fun rawNonceSentNotHash(): Unit = runBlocking {
        val raw = "n-0S6_WzA2Mj"
        val hash = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"
        assertEquals(hash, sha256Hex(raw), "the fixed vector")
        val fixtureToken = OidcTestKit.rawTokenWithHeader(
            """{"alg":"none"}""",
            """{"sub":"u","nonce":"$hash"}""",
        )
        assertTrue(String(Base64.getUrlDecoder().decode(fixtureToken.split(".")[1])).contains(hash))

        val client = client()
        val configuration = client.oidcDiscover()
        client.signIn(configuration, idToken = fixtureToken, nonce = raw)
        val body = tokenRequests().single().body.readUtf8()
        val fields = pairs(body)
        assertEquals(raw, fields.single { it.first == "nonce" }.second)
        assertFalse(body.contains(hash), "neither the hash nor the token's nonce claim travels as a field")
        assertFalse(body.lowercase().contains(hash))
        assertEquals(fixtureToken, fields.single { it.first == "id_token" }.second)
    }

    // ---- 3 -----------------------------------------------------------------

    @Test
    fun providerSentVerbatim(): Unit = runBlocking {
        val client = client()
        val configuration = client.oidcDiscover()
        val before = server.requestCount
        val uuid = "3f2b8c1e-7d44-4b0a-9a55-0e1c2d3e4f50"
        val sent = listOf(uuid, "Corp-Okta", "google", " padded ", "UPPER")
        for (provider in sent) client.signIn(configuration, provider = provider)

        assertEquals(sent.size, server.requestCount - before, "one request per call: no sso_providers lookup, no discovery")
        assertEquals(sent, tokenRequests().map { r -> pairs(r.body.readUtf8()).single { it.first == "provider" }.second })
        assertTrue(seen.none { it.path.orEmpty().contains("federation") || it.path.orEmpty().contains("well-known") })
    }

    // ---- 4 -----------------------------------------------------------------

    @Test
    fun publicClientSendsClientIdOnly(): Unit = runBlocking {
        val client = client(secret = null)
        val configuration = client.oidcDiscover()
        val tokens = client.signIn(configuration)
        assertEquals("native-access", tokens.accessToken.expose())
        val request = tokenRequests().single()
        assertEquals(
            setOf("grant_type", "client_id", "provider", "id_token", "nonce"),
            pairs(request.body.readUtf8()).map { it.first }.toSet(),
        )
        assertNull(request.getHeader("Authorization"))
    }

    @Test
    fun confidentialClientSendsItsCredential(): Unit = runBlocking {
        for (method in listOf("client_secret_post", "client_secret_basic")) {
            authMethods = """["$method"]"""
            seen.clear()
            val client = client(secret = OidcTestKit.CLIENT_SECRET)
            val configuration = client.oidcDiscover()
            client.signIn(configuration)
            val request = tokenRequests().single()
            assertEquals(OidcTestKit.CLIENT_SECRET, pairs(request.body.readUtf8()).toMap()["client_secret"], method)
            assertNull(request.getHeader("Authorization"), "$method: the credential is in the body, never a Basic header")
        }
    }

    // ---- 5 -----------------------------------------------------------------

    @Test
    fun emptyInputsRefusedLocally(): Unit = runBlocking {
        val client = client()
        // No pre-fetched configuration: even discovery must not be reached.
        val cases = listOf(
            ProviderIdTokenLoginParams.of("", "tok", "n", tenantId = tenantId),
            ProviderIdTokenLoginParams.of("p", "", "n", tenantId = tenantId),
            ProviderIdTokenLoginParams.of("p", "tok", "", tenantId = tenantId),
        )
        for (params in cases) {
            assertThrows(ValidationError::class.java) { runBlocking { client.loginWithProviderIdToken(params) } }
        }
        assertEquals(0, server.requestCount)

        // A slug-only client (§12.3 rule 4) raises its taxonomy error, still with no wire call.
        val slugOnly = client(tenant = "acme")
        assertThrows(AuthError::class.java) {
            runBlocking { slugOnly.loginWithProviderIdToken(ProviderIdTokenLoginParams.of("p", "tok", "n")) }
        }
        // And a client with no client id at all.
        val anonymous = client(clientId = null)
        assertThrows(AuthError::class.java) {
            runBlocking { anonymous.loginWithProviderIdToken(ProviderIdTokenLoginParams.of("p", "tok", "n", tenantId = tenantId)) }
        }
        assertEquals(0, server.requestCount)
    }

    // ---- 6 -----------------------------------------------------------------

    @Test
    fun genericInvalidGrantMapped(): Unit = runBlocking {
        respondJson(400, OidcTestKit.oauth2ErrorJson("invalid_grant", "the provider ID token is not acceptable"))
        val client = client()
        client.login("alice@example.com", "pw")
        val guardEntered = java.util.concurrent.atomic.AtomicInteger()
        client.oidcRefreshAfterPublishHook = { guardEntered.incrementAndGet() }
        val configuration = client.oidcDiscover()
        seen.clear()
        val before = server.requestCount

        val error = assertThrows(OAuthProtocolError::class.java) { runBlocking { client.signIn(configuration) } }
        assertEquals("invalid_grant", error.error)
        assertEquals("the provider ID token is not acceptable", error.errorDescription)
        assertEquals("invalid_grant: the provider ID token is not acceptable", error.message)
        assertEquals(1, server.requestCount - before, "exactly one request: no retry, no regenerated nonce")
        assertEquals(0, guardEntered.get(), "the §9 guard is not entered")
        assertTrue(seen.none { it.path.orEmpty().contains("/auth/refresh") })
    }

    // ---- 7 -----------------------------------------------------------------

    @Test
    fun consentRequiredMapped(): Unit = runBlocking {
        respondJson(400, OidcTestKit.oauth2ErrorJson("consent_required", "the requested scope needs consent"))
        val client = client()
        val configuration = client.oidcDiscover()
        val before = server.requestCount
        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking { client.signIn(configuration, scopes = listOf("profile")) }
        }
        assertEquals("consent_required", error.error)
        assertEquals(1, server.requestCount - before)
        assertTrue(seen.all { it.path.orEmpty().startsWith("/oauth2/token") }, "no fallback to another grant or a browser flow")
    }

    // ---- 8 -----------------------------------------------------------------

    @Test
    fun clientAndScopeRefusalsSurfaced(): Unit = runBlocking {
        val client = client()
        client.login("alice@example.com", "pw")
        val guardEntered = java.util.concurrent.atomic.AtomicInteger()
        client.oidcRefreshAfterPublishHook = { guardEntered.incrementAndGet() }
        val configuration = client.oidcDiscover()
        seen.clear()

        val refusals = listOf(
            Triple(400, "unauthorized_client", emptyArray<Pair<String, String>>()),
            Triple(401, "invalid_client", arrayOf("WWW-Authenticate" to """Basic realm="oauth2"""")),
            Triple(400, "invalid_scope", emptyArray()),
            Triple(400, "invalid_target", emptyArray()),
        )
        for ((status, code, headers) in refusals) {
            respondJson(status, OidcTestKit.oauth2ErrorJson(code, "refused"), *headers)
            val before = tokenRequests().size
            val error = assertThrows(OAuthProtocolError::class.java) {
                runBlocking { client.signIn(configuration, scopes = listOf("admin")) }
            }
            assertEquals(code, error.error)
            assertEquals(1, tokenRequests().size - before, "$code: one request, no narrowing, no re-send")
        }
        // invalid_scope was not narrowed: every request asked for the same scope.
        assertTrue(tokenRequests().all { r -> pairs(r.body.readUtf8()).toMap()["scope"] == "admin" })
        assertEquals(0, guardEntered.get(), "the 401 does not enter the §9 guard")
        assertTrue(seen.none { it.path.orEmpty().contains("/auth/refresh") })
    }

    // ---- 9 -----------------------------------------------------------------

    @Test
    fun rateLimitWithRetryAfterMapped(): Unit = runBlocking {
        respondJson(429, OidcTestKit.oauth2ErrorJson("rate_limit_exceeded", "slow down"), "Retry-After" to "7")
        val client = client()
        val configuration = client.oidcDiscover()
        val before = server.requestCount
        val error = assertThrows(OAuthProtocolError::class.java) { runBlocking { client.signIn(configuration) } }
        assertEquals("rate_limit_exceeded", error.error)
        assertEquals(7.seconds, error.retryAfter)
        assertEquals(1, server.requestCount - before)
    }

    // ---- 10 ----------------------------------------------------------------

    @Test
    fun serverErrorNotRetried(): Unit = runBlocking {
        val client = client()
        val configuration = client.oidcDiscover()

        respondJson(500, OidcTestKit.oauth2ErrorJson("server_error", "the datastore is unavailable"))
        var before = server.requestCount
        val protocol = assertThrows(OAuthProtocolError::class.java) { runBlocking { client.signIn(configuration) } }
        assertEquals("server_error", protocol.error)
        assertEquals(1, server.requestCount - before)

        respond { MockResponse().setResponseCode(500) }
        before = server.requestCount
        assertThrows(NetworkError::class.java) { runBlocking { client.signIn(configuration) } }
        assertEquals(1, server.requestCount - before, "a 5xx without a body is NetworkError, and not retried")

        respond { MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) }
        before = server.requestCount
        assertThrows(NetworkError::class.java) { runBlocking { client.signIn(configuration) } }
        assertEquals(1, server.requestCount - before, "a transport failure after the request left is not replayed")
    }

    // ---- 11 ----------------------------------------------------------------

    @Test
    fun resultIsTheOrdinaryTokenSet(): Unit = runBlocking {
        val raw = "raw-nonce-xyz"
        val client = client()
        client.login("alice@example.com", "pw")
        val configuration = client.oidcDiscover()

        client.groups.list(PageRequest(limit = 50))
        val credentialBefore = seen.last { it.path.orEmpty().startsWith("/api/v1/groups") }.getHeader("Cookie")
        assertNotNull(credentialBefore, "control: the session reaches a management request")

        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = raw)
        respondJson(
            200,
            OidcTestKit.tokenResponseJson(
                accessToken = "native-access", tokenType = "DPoP", scope = "openid profile",
                refreshToken = "native-refresh", idToken = idToken,
            ),
        )
        val tokens = client.signIn(configuration, nonce = raw, scopes = listOf("openid", "profile"))
        assertEquals("DPoP", tokens.tokenType, "token_type is read, not assumed")
        assertEquals("openid profile", tokens.scope)
        assertEquals("native-access", tokens.accessToken.expose())
        assertEquals("native-refresh", tokens.refreshToken?.expose())
        assertEquals(idToken, tokens.idToken?.expose())
        assertEquals("user-1", tokens.idClaims?.sub)

        // Adoption posture (as loginClientCredentials / deviceLogin in this SDK): not adopted.
        client.groups.list(PageRequest(limit = 50))
        val after = seen.last { it.path.orEmpty().startsWith("/api/v1/groups") }
        assertEquals(credentialBefore, after.getHeader("Cookie"))
        assertFalse(after.getHeader("Authorization").orEmpty().contains("native-access"))

        // A claim that does not equal the RAW nonce is nonce_mismatch.
        val mismatching = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = "someone-elses")
        respondJson(200, OidcTestKit.tokenResponseJson(scope = "openid", idToken = mismatching))
        val error = assertThrows(AuthError::class.java) {
            runBlocking { client.signIn(configuration, nonce = raw, scopes = listOf("openid")) }
        }
        assertEquals("nonce_mismatch", error.reason)

        // No refresh_token and no id_token: both absent.
        respondJson(200, OidcTestKit.tokenResponseJson(accessToken = "only-access"))
        val bare = client.signIn(configuration)
        assertNull(bare.refreshToken)
        assertNull(bare.idToken)
        assertNull(bare.idClaims)
    }

    // ---- 12 ----------------------------------------------------------------

    @Test
    fun noSecretInLogsOrErrors(): Unit = runBlocking {
        val idTokenSecret = Redaction.secret("tok")
        val nonceSecret = Redaction.secret("non")
        val secrets = listOf(idTokenSecret, nonceSecret)

        // The most verbose logging there is: every java.util.logging record, stdout and stderr.
        val logged = StringBuffer()
        val root = Logger.getLogger("")
        val previousLevel = root.level
        val handler = object : Handler() {
            override fun publish(record: LogRecord) {
                logged.append(record.loggerName).append(' ').append(record.message).append(' ')
                    .append(record.parameters?.joinToString { it.toString() }).append(' ')
                record.thrown?.let { logged.append(render(it)) }
            }
            override fun flush() = Unit
            override fun close() = Unit
        }
        handler.level = Level.ALL
        root.level = Level.ALL
        root.addHandler(handler)
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val realOut = System.out
        val realErr = System.err
        System.setOut(PrintStream(out, true))
        System.setErr(PrintStream(err, true))

        val telemetry = Collections.synchronizedList(mutableListOf<String>())
        val renderings = mutableListOf<String>()
        try {
            val client = client(telemetry = { telemetry += it.toString() })
            val configuration = client.oidcDiscover()
            fun params(provider: String = "corp-okta", token: String = idTokenSecret, nonce: String = nonceSecret) =
                ProviderIdTokenLoginParams.of(provider, token, nonce, tenantId = tenantId, configuration = configuration)

            // Success.
            val ok = client.loginWithProviderIdToken(params())
            renderings += ok.toString()
            renderings += params().toString()
            val pair = client.nativeNonce()
            renderings += pair.toString()
            renderings += pair.raw.toString()

            // Test 5's refusals, then 6 to 10's failures.
            val local = listOf(params(provider = ""), params(token = ""), params(nonce = ""))
            for (p in local) {
                val e = assertThrows(ValidationError::class.java) { runBlocking { client.loginWithProviderIdToken(p) } }
                renderings += render(e)
            }
            val statuses = listOf(
                400 to OidcTestKit.oauth2ErrorJson("invalid_grant", "the provider ID token is not acceptable"),
                400 to OidcTestKit.oauth2ErrorJson("consent_required", "needs consent"),
                401 to OidcTestKit.oauth2ErrorJson("invalid_client", "bad client"),
                400 to OidcTestKit.oauth2ErrorJson("invalid_scope", "no"),
                429 to OidcTestKit.oauth2ErrorJson("rate_limit_exceeded", "later"),
                500 to OidcTestKit.oauth2ErrorJson("server_error", "boom"),
                500 to "",
            )
            for ((status, body) in statuses) {
                respond { MockResponse().setResponseCode(status).setBody(body) }
                val e = assertThrows(Throwable::class.java) { runBlocking { client.loginWithProviderIdToken(params()) } }
                renderings += render(e)
            }
            respond { MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) }
            val transport = assertThrows(NetworkError::class.java) { runBlocking { client.loginWithProviderIdToken(params()) } }
            renderings += render(transport)
        } finally {
            System.setOut(realOut)
            System.setErr(realErr)
            root.removeHandler(handler)
            root.level = previousLevel
        }

        val haystacks = renderings + logged.toString() + out.toString() + err.toString() + telemetry
        assertTrue(renderings.size > 10, "the scan covered every path")
        for (secret in secrets) {
            for ((i, h) in haystacks.withIndex()) Redaction.assertNoFragment(h, secret, "rendering #$i")
        }
    }

    private fun render(t: Throwable): String {
        val sw = StringWriter()
        t.printStackTrace(PrintWriter(sw))
        return "${t.message} $t ${t.cause} $sw"
    }

    // ---- 13 ----------------------------------------------------------------

    @Test
    fun nativeNoncePair(): Unit = runBlocking {
        val client = client()
        val a = client.nativeNonce()
        val b = client.nativeNonce()

        val raw = a.raw.expose()
        assertFalse(raw.contains('='), "base64url without padding")
        assertTrue(Regex("^[A-Za-z0-9_-]+$").matches(raw))
        assertTrue(Base64.getUrlDecoder().decode(raw).size >= 32, "at least 32 bytes")
        assertEquals(64, a.hashed.length)
        assertTrue(Regex("^[0-9a-f]{64}$").matches(a.hashed), "lower-case hexadecimal")
        assertEquals(sha256Hex(raw), a.hashed)
        assertEquals("0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19", ProviderNonce.hashOf("n-0S6_WzA2Mj"))
        assertNotEquals(a.raw.expose(), b.raw.expose())
        assertNotEquals(a.hashed, b.hashed)
        assertTrue(a.raw is Sensitive<*>)
        assertEquals("[SENSITIVE]", a.raw.toString())
        assertFalse(a.toString().contains(raw))
        assertEquals(0, server.requestCount, "pure local computation")
    }
}
