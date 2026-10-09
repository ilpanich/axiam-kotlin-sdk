package io.axiam.sdk.oidc

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.errors.ValidationError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URLDecoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * CIBA — CONTRACT.md §33.8's sixteen required tests (nine initiation and
 * polling, four ping, three signed request), plus the unsupported-endpoint
 * refusal.
 *
 * No credential, key or token literal: the client secret, the `auth_req_id`,
 * the notification token and every signing key are generated at run time.
 */
class CibaTest {

    private val tenant = "22222222-2222-2222-2222-222222222222"
    private lateinit var server: MockWebServer
    private lateinit var secret: String
    private val idTokenKey = OidcTestKit.generateSigningKey("ciba-id-token-key")

    /** One recorded request to bc-authorize or the token endpoint. */
    private data class Seen(val form: Map<String, String>, val tenantQuery: String?, val at: Duration, val request: RecordedRequest)

    private val initiates = Collections.synchronizedList(mutableListOf<Seen>())
    private val polls = Collections.synchronizedList(mutableListOf<Seen>())
    private var bcAnswer: () -> MockResponse = { json(200, """{"auth_req_id":"${random()}","expires_in":120}""") }
    private var tokenScript: List<() -> MockResponse> = listOf { json(400, oauthError("authorization_pending")) }
    private var clock: TestClock? = null
    private var discoveryExtra: String = ""

    @BeforeEach
    fun setUp() {
        secret = Redaction.secret()
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.requestUrl?.encodedPath ?: ""
                return when (path) {
                    "/.well-known/openid-configuration" -> json(200, discovery())
                    "/oauth2/jwks" -> json(200, OidcTestKit.jwksJson(idTokenKey.toPublicJWK()))
                    "/oauth2/bc-authorize" -> {
                        initiates += seen(request)
                        bcAnswer()
                    }
                    "/oauth2/token" -> {
                        polls += seen(request)
                        tokenScript[(polls.size - 1).coerceAtMost(tokenScript.size - 1)]()
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun origin() = server.url("/").toString().trimEnd('/')

    private fun discovery(): String {
        val base = OidcTestKit.discoveryJson(origin()).trimEnd().removeSuffix("}").trimEnd()
        return "$base,\n  \"backchannel_authentication_endpoint\": \"${origin()}/oauth2/bc-authorize\"$discoveryExtra\n}"
    }

    private fun seen(request: RecordedRequest): Seen {
        val body = request.body.readUtf8()
        val form = body.split('&').filter { it.isNotEmpty() }.associate {
            val (k, v) = it.split('=', limit = 2).let { p -> p[0] to p.getOrElse(1) { "" } }
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }
        return Seen(form, request.requestUrl?.queryParameter("tenant_id"), clock?.elapsed ?: Duration.ZERO, request)
    }

    private fun json(code: Int, body: String) =
        MockResponse().setResponseCode(code).addHeader("Content-Type", "application/json").setBody(body)

    private fun oauthError(code: String) = """{"error":"$code","error_description":"$code here"}"""

    private fun random() = Redaction.secret("r")

    private fun client(withSecret: Boolean = true, certificate: Boolean = false): AxiamClient {
        val builder = AxiamClient.builder(server.url("/").toString(), tenant).oidcClientId(OidcTestKit.CLIENT_ID)
        if (withSecret) builder.oidcClientSecret(secret)
        if (certificate) {
            val identity = HeldCertificate.Builder().commonName("ciba-client").build()
            builder.clientCertificate(identity.certificatePem().toByteArray(), identity.privateKeyPkcs8Pem().toByteArray())
        }
        return builder.build()
    }

    private fun params(client: AxiamClient) = CibaInitiateParams(
        scope = "openid profile",
        hint = CibaUserHint.LoginHint("ada"),
        configuration = runBlocking { client.oidcDiscover() },
    )

    private fun tokens(): MockResponse {
        val idToken = OidcTestKit.signIdToken(idTokenKey, issuer = origin(), nonce = null)
        return json(
            200,
            OidcTestKit.tokenResponseJson(accessToken = random(), expiresIn = 900, scope = "openid profile", idToken = idToken),
        )
    }

    /** A clock that never sleeps: `sleep` advances it and records the wait. */
    private class TestClock : CibaClock {
        val start: Instant = Instant.now()
        var elapsed: Duration = Duration.ZERO
        val sleeps = mutableListOf<Long>()
        override fun now(): Instant = start.plus(elapsed)
        override suspend fun sleep(duration: Duration) {
            elapsed = elapsed.plus(duration)
            sleeps += duration.seconds
        }
    }

    private fun initiated(expiresIn: Long, interval: Long, at: Instant) =
        CibaInitiateResponse(Sensitive.of(random()), expiresIn, interval, at)

    private fun await(client: AxiamClient, initiated: CibaInitiateResponse, clock: TestClock): OidcTokenSet =
        runBlocking { client.cibaAwait(initiated, CibaAwaitParams(configuration = client.oidcDiscover(), clock = clock)) }

    // -- 1. Redaction ------------------------------------------------------------------

    @Test
    fun `t01 the three values are on the wire and in no rendering`() = runBlocking {
        val client = client()
        val notification = random()
        val authReqId = random()
        bcAnswer = { json(200, """{"auth_req_id":"$authReqId","expires_in":120,"interval":5}""") }
        val p = params(client).copy(delivery = CibaDelivery.Ping(Sensitive.of(notification)))
        Redaction.assertNoFragment(p.toString(), notification, "params")
        val response = client.cibaInitiate(p)
        Redaction.assertNoFragment(response.toString(), authReqId, "response")
        assertEquals(authReqId, response.authReqId.expose())
        assertEquals(notification, initiates[0].form["client_notification_token"])

        bcAnswer = { json(400, oauthError("invalid_binding_message")) }
        val e = assertThrows<OAuthProtocolError> { runBlocking { client.cibaInitiate(p) } }
        assertEquals("invalid_binding_message", e.error)
        assertEquals("invalid_binding_message here", e.errorDescription, "surfaced with its description")
        Redaction.assertNoFragment(e.toString(), notification, "error")
    }

    // -- 2. Client authentication is mandatory -------------------------------------------

    @Test
    fun `t02 no credential is refused locally and one is sent with the tenant in the query`() = runBlocking {
        val public = client(withSecret = false)
        val configuration = public.oidcDiscover()
        assertThrows<AuthError> { runBlocking { public.cibaInitiate(params(public)) } }
        assertThrows<AuthError> {
            runBlocking { public.cibaPoll(CibaPollParams(Sensitive.of(random()), configuration = configuration)) }
        }
        assertTrue(initiates.isEmpty() && polls.isEmpty(), "no anonymous request")

        val client = client()
        client.cibaInitiate(params(client))
        runCatching { client.cibaPoll(CibaPollParams(Sensitive.of(random()), configuration = configuration)) }
        for (s in listOf(initiates[0], polls[0])) {
            assertEquals(OidcTestKit.CLIENT_ID, s.form["client_id"])
            assertEquals(secret, s.form["client_secret"])
            assertFalse("tenant_id" in s.form, "never a body field")
            assertEquals(tenant, s.tenantQuery)
            assertEquals(tenant, s.request.getHeader("X-Tenant-ID"), "§5 tenant header")
        }

        // A tls_client_auth client: the certificate is the credential.
        val mtls = client(withSecret = false, certificate = true)
        mtls.cibaInitiate(params(mtls))
        assertEquals(OidcTestKit.CLIENT_ID, initiates[1].form["client_id"])
        assertFalse("client_secret" in initiates[1].form)
    }

    // -- 3. The initiate request ----------------------------------------------------------

    @Test
    fun `t03 exactly the members set are sent`() = runBlocking {
        val client = client()
        client.cibaInitiate(params(client))
        val token = random()
        client.cibaInitiate(
            params(client).copy(
                hint = CibaUserHint.IdTokenHint("an.id.token"),
                bindingMessage = "W4SCT",
                requestedExpiry = 120,
                acrValues = "urn:axiam:acr:mfa",
                resource = "https://api.example.test",
                delivery = CibaDelivery.Ping(Sensitive.of(token)),
            ),
        )
        assertEquals(listOf("client_id", "client_secret", "login_hint", "scope"), initiates[0].form.keys.sorted())
        assertEquals(
            listOf(
                "acr_values", "binding_message", "client_id", "client_notification_token", "client_secret",
                "id_token_hint", "requested_expiry", "resource", "scope",
            ),
            initiates[1].form.keys.sorted(),
        )
        assertEquals("120", initiates[1].form["requested_expiry"])
        assertEquals(token, initiates[1].form["client_notification_token"])
        assertEquals("application/x-www-form-urlencoded", initiates[1].request.getHeader("Content-Type")?.substringBefore(';'))
        // login_hint_token, user_code and request_uri have no parameter, and
        // CibaUserHint holds one hint: both at once cannot be written.
        val names = CibaInitiateParams::class.members.map { it.name }
        for (absent in listOf("loginHintToken", "userCode", "requestUri", "extraParams")) {
            assertFalse(absent in names, absent)
        }
        // A ping request with an empty token is refused before any request.
        assertThrows<ValidationError> {
            runBlocking { client.cibaInitiate(params(client).copy(delivery = CibaDelivery.Ping(Sensitive.of("")))) }
        }
        assertEquals(2, initiates.size)
    }

    // -- 4. No retry on initiate -------------------------------------------------------------

    @Test
    fun `t04 initiate is sent once on 503, 429 and a dropped connection`() = runBlocking {
        val client = client() // retry ENABLED
        bcAnswer = { MockResponse().setResponseCode(503) }
        assertThrows<NetworkError> { runBlocking { client.cibaInitiate(params(client)) } }
        assertEquals(1, initiates.size, "503: exactly one request")

        bcAnswer = { json(429, """{"error":"rate_limit_exceeded"}""") }
        val limited = assertThrows<OAuthProtocolError> { runBlocking { client.cibaInitiate(params(client)) } }
        assertEquals("rate_limit_exceeded", limited.error, "§2's /oauth2 row: an error body is an OAuthProtocolError")
        assertEquals(2, initiates.size, "429: exactly one request")

        // A listener that accepts and hangs up.
        val accepts = AtomicInteger()
        ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).use { listener ->
            val acceptor = Thread {
                try {
                    while (true) {
                        listener.accept().use { accepts.incrementAndGet() }
                    }
                } catch (_: Exception) {
                    // closed
                }
            }.apply { isDaemon = true; start() }
            val configuration = client.oidcDiscover().copy(
                backchannel_authentication_endpoint = "http://127.0.0.1:${listener.localPort}/oauth2/bc-authorize",
            )
            assertThrows<NetworkError> {
                runBlocking { client.cibaInitiate(params(client).copy(configuration = configuration)) }
            }
            Thread.sleep(200)
            assertEquals(1, accepts.get(), "one connection, no retry")
            listener.close()
            acceptor.join(1000)
        }
    }

    // -- 5. Poll outcomes -------------------------------------------------------------------------

    @Test
    fun `t05 pending loops, slow_down persists and the terminal answers are distinct`() {
        val client = client()
        val c = TestClock().also { clock = it }
        tokenScript = listOf(
            { json(400, oauthError("slow_down")) },
            { json(400, oauthError("slow_down")) },
            { json(400, oauthError("authorization_pending")) },
            { tokens() },
        )
        val initiation = initiated(600, 5, c.start)
        val set = await(client, initiation, c)
        assertNotNull(set.idClaims)
        assertEquals(listOf(5L, 10L, 15L, 15L), c.sleeps, "+5 s twice, and pending lowers nothing")
        assertTrue(polls.all { it.form["grant_type"] == CIBA_GRANT_TYPE && it.form["auth_req_id"] == initiation.authReqId.expose() })

        for ((code, check) in listOf<Pair<String, (OAuthProtocolError) -> Boolean>>(
            "access_denied" to { it.isAccessDenied && !it.isExpiredToken },
            "expired_token" to { it.isExpiredToken && !it.isAccessDenied },
            "invalid_grant" to { it.error == "invalid_grant" },
            "a_code_nobody_defined" to { it.error == "a_code_nobody_defined" },
        )) {
            polls.clear()
            val terminal = TestClock().also { clock = it }
            tokenScript = listOf { json(400, oauthError(code)) }
            val e = assertThrows<OAuthProtocolError> { await(client, initiated(600, 5, terminal.start), terminal) }
            assertTrue(check(e), "$code: the typed outcome")
            assertEquals(1, polls.size, "$code is terminal")
        }
    }

    // -- 6. The first poll waits --------------------------------------------------------------------

    @Test
    fun `t06 the first poll waits the interval or five seconds`() = runBlocking {
        val client = client()
        for ((intervalField, expected) in listOf(""","interval":7""" to 7L, "" to 5L)) {
            polls.clear()
            val c = TestClock().also { clock = it }
            bcAnswer = { json(200, """{"auth_req_id":"${random()}","expires_in":300$intervalField}""") }
            tokenScript = listOf { json(400, oauthError("access_denied")) }
            val response = client.cibaInitiate(params(client))
            assertEquals(expected, response.interval)
            runCatching { await(client, response.copy(receivedAt = c.start), c) }
            assertEquals(Duration.ofSeconds(expected), polls[0].at, "the first poll waited the interval")
        }
    }

    // -- 7. Deadline ------------------------------------------------------------------------------------

    @Test
    fun `t07 no request after expires_in and expired_token is raised locally`() {
        val client = client()
        val c = TestClock().also { clock = it }
        tokenScript = listOf { json(400, oauthError("authorization_pending")) }
        val e = assertThrows<OAuthProtocolError> { await(client, initiated(12, 5, c.start), c) }
        assertTrue(e.isExpiredToken)
        assertEquals(listOf(5L, 10L), polls.map { it.at.seconds }, "nothing at 15 s, past the 12 s deadline")
    }

    // -- 8. Transient failure is not terminal ------------------------------------------------------------

    @Test
    fun `t08 a 500 and a 429 mid-loop are survived`() {
        val client = client()
        val c = TestClock().also { clock = it }
        tokenScript = listOf(
            { json(400, oauthError("authorization_pending")) },
            { MockResponse().setResponseCode(500) },
            { json(429, """{"error":"rate_limit_exceeded"}""") },
            { tokens() },
        )
        val set = await(client, initiated(600, 5, c.start), c)
        assertTrue(set.accessToken.expose().isNotEmpty())
        assertNotNull(set.idToken)
        assertNotNull(set.idClaims)
        assertEquals(4, polls.size)
    }

    // -- 9. Single use ---------------------------------------------------------------------------------------

    @Test
    fun `t09 a second redemption is invalid_grant and not retried`() = runBlocking {
        val client = client()
        tokenScript = listOf({ tokens() }, { json(400, oauthError("invalid_grant")) })
        val poll = CibaPollParams(Sensitive.of(random()), configuration = client.oidcDiscover())
        client.cibaPoll(poll)
        val e = assertThrows<OAuthProtocolError> { runBlocking { client.cibaPoll(poll) } }
        assertEquals("invalid_grant", e.error)
        assertEquals(2, polls.size, "no retry of the second")
    }

    // -- 10–13. The ping -----------------------------------------------------------------------------------

    private fun ping(vararg authorization: String): List<Pair<String, String>> =
        listOf("content-type" to "application/json") + authorization.map { "Authorization" to it }

    @Test
    fun `t10 a valid ping returns its auth_req_id in any scheme case`() {
        val client = client()
        val token = random()
        val id = random()
        for (scheme in listOf("Bearer", "bearer", "BEARER")) {
            val got = client.cibaHandlePing(ping("$scheme $token"), """{"auth_req_id":"$id"}""", Sensitive.of(token))
            assertEquals(id, got.expose())
            Redaction.assertNoFragment(got.toString(), id, "result")
        }
        val viaMap = client.cibaHandlePing(
            mapOf("Authorization" to listOf("Bearer $token")),
            """{"auth_req_id":"$id"}""",
            Sensitive.of(token),
        )
        assertEquals(id, viaMap.expose())
    }

    @Test
    fun `t11 a wrong, absent, empty, duplicate or Basic authorization is refused`() {
        val client = client()
        val token = random()
        val lastDiffers = token.dropLast(1) + (if (token.last() == 'a') 'b' else 'a')
        val body = """{"auth_req_id":"${random()}"}"""
        val expected = Sensitive.of(token)
        val cases = listOf(
            ping("Bearer ${random()}"),
            ping(),
            ping(""),
            ping("Bearer "),
            ping("Bearer $token", "Bearer $token"),
            ping("Basic $token"),
            ping("Bearer $lastDiffers"),
            ping("Bearer  $token"),
        )
        for ((i, case) in cases.withIndex()) {
            val e = assertThrows<AuthError>("case $i") { client.cibaHandlePing(case, body, expected) }
            Redaction.assertNoFragment(e.toString(), token, "case $i error")
        }
        assertThrows<AuthError> {
            client.cibaHandlePing(mapOf("authorization" to listOf("Bearer $token", "Bearer $token")), body, expected)
        }
        // The comparison is constant-time: asserted structurally.
        val source = File("src/main/kotlin/io/axiam/sdk/oidc/CibaPing.kt").readText()
        assertTrue(source.contains("MessageDigest.isEqual("), "the token is compared with MessageDigest.isEqual")
    }

    @Test
    fun `t12 a malformed body is a ValidationError and extras are ignored`() {
        val client = client()
        val token = random()
        val header = ping("Bearer $token")
        val expected = Sensitive.of(token)
        for (body in listOf("not json", "{}", """{"auth_req_id":""}""", """{"auth_req_id":42}""", """["auth_req_id"]""")) {
            assertThrows<ValidationError>(body) { client.cibaHandlePing(header, body, expected) }
        }
        val id = random()
        val got = client.cibaHandlePing(
            header,
            """{"auth_req_id":"$id","status":"approved","access_token":"x"}""",
            expected,
        )
        assertEquals(id, got.expose())
    }

    @Test
    fun `t13 the ping helper makes no network call`() {
        val client = client()
        val before = server.requestCount
        val token = random()
        client.cibaHandlePing(ping("Bearer $token"), """{"auth_req_id":"${random()}"}""", Sensitive.of(token))
        assertEquals(before, server.requestCount, "the transport was never touched")
    }

    // -- 14–16. The signed form -------------------------------------------------------------------------------

    private fun keyPair(alg: CibaSigningAlg): KeyPair = when (alg) {
        CibaSigningAlg.EDDSA -> KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        CibaSigningAlg.ES256 -> KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        CibaSigningAlg.PS256 -> KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    /** A PKCS#8 PEM, assembled at run time (no key material or PEM header is committed). */
    private fun pem(pair: KeyPair): String {
        val label = "PRIVATE" + " KEY"
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(pair.private.encoded)
        return "-----BEGIN $label-----\n$body\n-----END $label-----\n"
    }

    private fun verify(request: String, alg: CibaSigningAlg, pair: KeyPair): Boolean {
        val jwt = SignedJWT.parse(request)
        return when (alg) {
            CibaSigningAlg.EDDSA -> {
                val x = pair.public.encoded.takeLast(32).toByteArray()
                jwt.verify(Ed25519Verifier(OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x)).build()))
            }
            CibaSigningAlg.ES256 -> jwt.verify(ECDSAVerifier(pair.public as ECPublicKey))
            CibaSigningAlg.PS256 -> jwt.verify(RSASSAVerifier(pair.public as RSAPublicKey))
        }
    }

    @Test
    fun `t14 the signed request is one member with the registered alg and a fresh jti`() = runBlocking {
        val client = client()
        val notification = random()
        for (alg in CibaSigningAlg.values()) {
            initiates.clear()
            val pair = keyPair(alg)
            val signer = CibaRequestSigner.fromPem(alg, Sensitive.of(pem(pair)), "client-key-1")
            assertEquals(alg, signer.alg)
            val p = params(client).copy(
                bindingMessage = "W4SCT",
                requestedExpiry = 90,
                delivery = CibaDelivery.Ping(Sensitive.of(notification)),
                signer = signer,
            )
            client.cibaInitiate(p)
            client.cibaInitiate(p)
            val jtis = mutableListOf<String>()
            for (s in initiates) {
                assertEquals(listOf("client_id", "client_secret", "request"), s.form.keys.sorted(), "nothing beside request")
                assertEquals(secret, s.form["client_secret"])
                val request = s.form.getValue("request")
                val jwt = SignedJWT.parse(request)
                assertEquals(alg.jose, jwt.header.algorithm, "the caller's algorithm only")
                assertEquals("client-key-1", jwt.header.keyID)
                assertTrue(verify(request, alg, pair), "$alg: the signature verifies with the public key")
                val claims = jwt.jwtClaimsSet
                assertEquals(OidcTestKit.CLIENT_ID, claims.issuer)
                assertEquals(listOf(origin()), claims.audience)
                val exp = claims.expirationTime.time / 1000
                val nbf = claims.notBeforeTime.time / 1000
                assertNotNull(claims.issueTime)
                assertTrue(exp > nbf && exp - nbf <= 3600)
                assertEquals("ada", claims.getStringClaim("login_hint"))
                assertEquals("W4SCT", claims.getStringClaim("binding_message"))
                assertTrue(claims.getClaim("requested_expiry") is Number, "a number inside the JWT")
                assertEquals(90L, (claims.getClaim("requested_expiry") as Number).toLong())
                assertEquals(notification, claims.getStringClaim("client_notification_token"))
                assertEquals("openid profile", claims.getStringClaim("scope"))
                jtis += claims.jwtid
            }
            assertNotEquals(jtis[0], jtis[1], "$alg: a fresh jti per request")
        }
    }

    @Test
    fun `t15 no key or a key for another algorithm is refused before any request`() {
        val ed = keyPair(CibaSigningAlg.EDDSA)
        val ec = keyPair(CibaSigningAlg.ES256)
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        for ((alg, pem) in listOf(
            CibaSigningAlg.EDDSA to "",
            CibaSigningAlg.ES256 to pem(ed),
            CibaSigningAlg.PS256 to pem(ec),
            CibaSigningAlg.EDDSA to pem(ec),
            CibaSigningAlg.ES256 to pem(p384),
        )) {
            assertThrows<ValidationError>(alg.name) { CibaRequestSigner.fromPem(alg, Sensitive.of(pem)) }
        }
        assertThrows<ValidationError> { CibaRequestSigner.of(CibaSigningAlg.PS256, ed.private) }
        assertTrue(initiates.isEmpty())
    }

    @Test
    fun `t16 the key and the request appear in no rendering`() = runBlocking {
        val client = client()
        bcAnswer = { json(400, oauthError("invalid_request")) }
        val pair = keyPair(CibaSigningAlg.EDDSA)
        val keyText = pem(pair)
        val keyLine = keyText.lines()[1]
        val signer = CibaRequestSigner.fromPem(CibaSigningAlg.EDDSA, Sensitive.of(keyText))
        val p = params(client).copy(signer = signer)
        val e = assertThrows<OAuthProtocolError> { runBlocking { client.cibaInitiate(p) } }
        val request = initiates[0].form.getValue("request")
        for ((label, rendering) in listOf(
            "signer" to signer.toString(),
            "params" to p.toString(),
            "error" to e.toString(),
        )) {
            Redaction.assertNoFragment(rendering, keyLine, "$label (key)")
            Redaction.assertNoFragment(rendering, request, "$label (request)")
        }
    }

    // -- discovery ------------------------------------------------------------------------------------------------

    @Test
    fun `a server without the endpoint is refused, and discovery carries the CIBA members`() = runBlocking {
        discoveryExtra = """,
          "backchannel_token_delivery_modes_supported": ["poll", "ping"],
          "backchannel_user_code_parameter_supported": false,
          "backchannel_authentication_request_signing_alg_values_supported": ["PS256", "ES256", "EdDSA"]"""
        val client = client()
        val configuration = client.oidcDiscover()
        assertEquals("${origin()}/oauth2/bc-authorize", configuration.backchannel_authentication_endpoint)
        assertEquals(listOf("poll", "ping"), configuration.backchannel_token_delivery_modes_supported)
        assertEquals(false, configuration.backchannel_user_code_parameter_supported)
        assertEquals(listOf("PS256", "ES256", "EdDSA"), configuration.backchannel_authentication_request_signing_alg_values_supported)

        val without = configuration.copy(backchannel_authentication_endpoint = null)
        assertThrows<AuthError> {
            runBlocking { client.cibaInitiate(params(client).copy(configuration = without)) }
        }
        assertTrue(initiates.isEmpty(), "never synthesised from the issuer")
    }

    // -- edges ----------------------------------------------------------------------------------------------------

    @Test
    fun `an initiate response without auth_req_id or expires_in is a NetworkError`() = runBlocking {
        val client = client()
        for (body in listOf("""{"expires_in":120}""", """{"auth_req_id":"${random()}","expires_in":"soon"}""")) {
            bcAnswer = { json(200, body) }
            assertThrows<NetworkError> { runBlocking { client.cibaInitiate(params(client)) } }
        }
        assertEquals(2, initiates.size)
    }

    @Test
    fun `a transport failure that outlived section 16 is one more interval, a bodiless 400 is terminal`() {
        val client = client()
        val c = TestClock().also { clock = it }
        tokenScript = listOf(
            { MockResponse().setResponseCode(503) },
            { MockResponse().setResponseCode(503) },
            { MockResponse().setResponseCode(503) },
            { tokens() },
        )
        await(client, initiated(600, 5, c.start), c)
        assertEquals(listOf(5L, 5L), c.sleeps, "three attempts at one poll, then the next interval")
        assertEquals(4, polls.size)

        polls.clear()
        val terminal = TestClock().also { clock = it }
        tokenScript = listOf { MockResponse().setResponseCode(400) }
        assertThrows<NetworkError> { await(client, initiated(600, 5, terminal.start), terminal) }
        assertEquals(1, polls.size, "a bodiless 400 is neither retried nor looped")
    }

    @Test
    fun `the default await parameters use discovery and the system clock`() = runBlocking {
        val client = client()
        // Already inside the last interval: expired_token locally, no wait and no request.
        val e = assertThrows<OAuthProtocolError> {
            runBlocking { client.cibaAwait(CibaInitiateResponse(Sensitive.of(random()), 1, 5, Instant.now())) }
        }
        assertTrue(e.isExpiredToken)
        assertTrue(polls.isEmpty())
        val before = CibaClock.SYSTEM.now()
        CibaClock.SYSTEM.sleep(Duration.ZERO)
        assertTrue(!CibaClock.SYSTEM.now().isBefore(before))
        assertEquals("CibaClock.SYSTEM", CibaClock.SYSTEM.toString())
        val hint = random()
        Redaction.assertNoFragment(CibaUserHint.IdTokenHint(hint).toString(), hint, "id_token_hint")
    }
}
