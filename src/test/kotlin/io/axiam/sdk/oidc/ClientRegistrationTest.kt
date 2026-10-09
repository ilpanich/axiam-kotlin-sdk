package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.TestSupport
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.errors.ValidationError
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializerOrNull
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Collections
import java.util.UUID
import kotlin.reflect.typeOf

/**
 * CONTRACT.md §28.12 — RFC 7592 client configuration: the five required tests
 * of §28.12.6, plus the retry and decoding rules around them.
 *
 * No credential literal: every registration token, client secret and session
 * token is generated at run time.
 */
class ClientRegistrationTest {

    private lateinit var server: MockWebServer
    private val seen = Collections.synchronizedList(mutableListOf<RecordedRequest>())
    private val refreshes = java.util.concurrent.atomic.AtomicInteger()

    /** What the registration endpoint answers, per method; a list is consumed in order (last repeats). */
    private val answers = mutableMapOf<String, MutableList<MockResponse>>()
    private val tenant = "22222222-2222-2222-2222-222222222222"
    private val clientId = "dcr-client-1"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.requestUrl?.encodedPath ?: ""
                return when {
                    path == "/api/v1/auth/login" -> TestSupport.loginOkResponse(
                        accessJwt = TestSupport.fakeJwt(jti = UUID.randomUUID().toString()),
                        refresh = Redaction.secret("r"),
                    )
                    path == "/api/v1/auth/refresh" -> {
                        refreshes.incrementAndGet()
                        MockResponse().setResponseCode(500)
                    }
                    path == "/oauth2/register/$clientId" -> {
                        seen += request
                        val queue = answers[request.method] ?: return MockResponse().setResponseCode(501)
                        if (queue.size > 1) queue.removeAt(0) else queue.first()
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

    private fun client(retry: Boolean = true): AxiamClient =
        AxiamClient.builder(server.url("/").toString(), tenant)
            .apply { if (!retry) retryDisabled() }
            .build()

    private fun registrationUri(): String =
        server.url("/oauth2/register/$clientId").newBuilder()
            .addQueryParameter("tenant_id", tenant).build().toString()

    private fun registrationBody(extra: Map<String, Any> = emptyMap()): String {
        val base = mutableMapOf<String, Any>(
            "client_id" to clientId,
            "client_id_issued_at" to 1_700_000_000,
            "client_name" to "Agent",
            "redirect_uris" to listOf("https://agent.example.test/cb"),
            "grant_types" to listOf("authorization_code"),
            "response_types" to listOf("code"),
            "token_endpoint_auth_method" to "private_key_jwt",
            "scope" to "openid",
            "registration_client_uri" to registrationUri(),
            "jwks_uri" to "https://agent.example.test/jwks",
        )
        base.putAll(extra)
        return toJson(base).toString()
    }

    private fun toJson(value: Any?): kotlinx.serialization.json.JsonElement = when (value) {
        null -> kotlinx.serialization.json.JsonNull
        is String -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is List<*> -> kotlinx.serialization.json.JsonArray(value.map { toJson(it) })
        is Map<*, *> -> JsonObject(value.entries.associate { (k, v) -> k.toString() to toJson(v) })
        else -> error("unsupported")
    }

    private fun json(code: Int, body: String) =
        MockResponse().setResponseCode(code).addHeader("Content-Type", "application/json").setBody(body)

    // -- §28.12.6 (1) origin refusal -------------------------------------------

    @Test
    fun `a URI at another origin is refused locally and nothing is sent`() = runBlocking {
        answers["GET"] = mutableListOf(json(200, registrationBody()))
        answers["PUT"] = mutableListOf(json(200, registrationBody()))
        answers["DELETE"] = mutableListOf(MockResponse().setResponseCode(204))
        val client = client()
        val token = Sensitive.of(Redaction.secret())
        val host = server.hostName
        val otherHost = if (host == "localhost") "127.0.0.1" else "localhost"
        val uris = listOf(
            "http://$otherHost:${server.port}/oauth2/register/$clientId",
            "http://$host:${server.port + 1}/oauth2/register/$clientId",
            "ftp://$host/oauth2/register/$clientId",
            "/oauth2/register/$clientId",
        )
        for (uri in uris) {
            val read = assertThrows<ValidationError> { runBlocking { client.readClientRegistration(uri, token) } }
            assertTrue(!read.message.orEmpty().contains(otherHost), "the refusal names no part of the URI")
            assertThrows<ValidationError> { runBlocking { client.deleteClientRegistration(uri, token) } }
            assertThrows<ValidationError> {
                runBlocking { client.updateClientRegistration(uri, token, ClientRegistration(clientId)) }
            }
        }

        // http against an https base URL, at the same host and port otherwise.
        val https = AxiamClient.builder("https://iam.example.test", tenant).build()
        assertThrows<ValidationError> {
            runBlocking { https.readClientRegistration("http://iam.example.test/oauth2/register/x", token) }
        }
        // ...and a non-loopback http base URL cannot be built at all (SEC-073), so
        // the loopback carve-out is the only way http is ever accepted.
        assertEquals(0, seen.size, "no request reached the registration endpoint")
    }

    // -- §28.12.6 (2) header only ------------------------------------------------

    @Test
    fun `read and delete send the bearer only, no session and the query verbatim`() = runBlocking {
        answers["GET"] = mutableListOf(json(200, registrationBody()))
        answers["DELETE"] = mutableListOf(MockResponse().setResponseCode(204))
        val client = client()
        client.login("admin@example.test", Redaction.secret("p"))
        val session = client.okHttpClient().cookieJar
            .loadForRequest(server.url("/")).firstOrNull { it.name == "axiam_access" }?.value
        assertTrue(!session.isNullOrEmpty(), "a real session is present")

        val token = Redaction.secret()
        val read = client.readClientRegistration(registrationUri(), Sensitive.of(token))
        assertEquals(clientId, read.clientId)
        assertNull(read.registrationAccessToken)
        client.deleteClientRegistration(registrationUri(), Sensitive.of(token))

        assertEquals(listOf("GET", "DELETE"), seen.map { it.method })
        for (request in seen) {
            assertEquals("Bearer $token", request.getHeader("Authorization"), "${request.method}: the bearer")
            assertNull(request.getHeader("Cookie"), "${request.method}: no session cookie")
            assertNull(request.getHeader("X-CSRF-Token"), "${request.method}: no CSRF header")
            assertTrue(
                !request.getHeader("Authorization").orEmpty().contains(session!!),
                "${request.method}: never the SDK's access token",
            )
            assertEquals(0L, request.bodySize, "${request.method}: no body")
            assertEquals("tenant_id=$tenant", request.requestUrl?.encodedQuery, "the URI's own query, verbatim")
        }
    }

    // -- §28.12.6 (3) update body, rotation and no retry -------------------------

    @Test
    fun `update drops the five server-stated members and returns the rotated token`() = runBlocking {
        val rotated = Redaction.secret()
        answers["PUT"] = mutableListOf(json(200, registrationBody(mapOf("registration_access_token" to rotated))))
        val client = client()
        val read = ClientRegistration.fromJson(
            Json.parseToJsonElement(
                registrationBody(
                    mapOf(
                        "registration_access_token" to Redaction.secret(),
                        "client_secret" to Redaction.secret(),
                        "client_secret_expires_at" to 0,
                        "backchannel_token_delivery_mode" to "poll",
                    ),
                ),
            ).jsonObject,
        )
        val updated = client.updateClientRegistration(
            registrationUri(),
            Sensitive.of(Redaction.secret()),
            read.copy(clientName = "Agent v2"),
        )
        assertEquals(rotated, updated.registrationAccessToken?.expose(), "the rotated token is returned")

        assertEquals(1, seen.size)
        val body = Json.parseToJsonElement(seen[0].body.readUtf8()).jsonObject
        for (gone in ClientRegistration.SERVER_STATED_MEMBERS) {
            assertTrue(gone !in body, "$gone is never sent")
        }
        assertEquals(JsonPrimitive(clientId), body["client_id"])
        assertEquals(JsonPrimitive("Agent v2"), body["client_name"])
        assertEquals(JsonPrimitive("poll"), body["backchannel_token_delivery_mode"], "unknown members round-trip")
        assertEquals(JsonPrimitive("https://agent.example.test/jwks"), body["jwks_uri"])
        assertEquals("application/json", seen[0].getHeader("Content-Type")?.substringBefore(';'))
    }

    @Test
    fun `neither write is retried on a 503, and the read is`() = runBlocking {
        answers["PUT"] = mutableListOf(MockResponse().setResponseCode(503))
        answers["DELETE"] = mutableListOf(MockResponse().setResponseCode(503))
        answers["GET"] = mutableListOf(MockResponse().setResponseCode(503), json(200, registrationBody()))
        val client = client() // retry ENABLED: a retry-disabled client would prove nothing
        val token = Sensitive.of(Redaction.secret())

        assertThrows<NetworkError> {
            runBlocking { client.updateClientRegistration(registrationUri(), token, ClientRegistration(clientId)) }
        }
        assertThrows<NetworkError> { runBlocking { client.deleteClientRegistration(registrationUri(), token) } }
        assertEquals(listOf("PUT", "DELETE"), seen.map { it.method }, "exactly one request each")

        client.readClientRegistration(registrationUri(), token)
        assertEquals(listOf("PUT", "DELETE", "GET", "GET"), seen.map { it.method }, "the read is retried per §16")
    }

    @Test
    fun `the read is not retried on a bodiless 400`() = runBlocking {
        answers["GET"] = mutableListOf(MockResponse().setResponseCode(400))
        val client = client()
        assertThrows<NetworkError> {
            runBlocking { client.readClientRegistration(registrationUri(), Sensitive.of(Redaction.secret())) }
        }
        assertEquals(1, seen.size, "a 4xx other than 408/429 is decisive")
    }

    // -- §28.12.6 (4) errors -------------------------------------------------------

    @Test
    fun `a 401 invalid_token is an OAuthProtocolError and never refreshes`() = runBlocking {
        answers["GET"] = mutableListOf(
            json(401, """{"error":"invalid_token","error_description":"the token is not valid"}""")
                .addHeader("WWW-Authenticate", "Bearer error=\"invalid_token\""),
        )
        answers["PUT"] = mutableListOf(json(400, """{"error":"invalid_client_metadata"}"""))
        answers["DELETE"] = mutableListOf(MockResponse().setResponseCode(204))
        val client = client()
        client.login("admin@example.test", Redaction.secret("p"))
        val token = Sensitive.of(Redaction.secret())

        val e = assertThrows<OAuthProtocolError> {
            runBlocking { client.readClientRegistration(registrationUri(), token) }
        }
        assertEquals("invalid_token", e.error)
        assertEquals(1, seen.size, "a 401 is decisive")
        val metadata = assertThrows<OAuthProtocolError> {
            runBlocking { client.updateClientRegistration(registrationUri(), token, ClientRegistration(clientId)) }
        }
        assertEquals("invalid_client_metadata", metadata.error)
        assertEquals("", metadata.errorDescription, "error_description is optional")
        client.deleteClientRegistration(registrationUri(), token)
        assertEquals(0, refreshes.get(), "no §9 refresh was attempted")
    }

    // -- §28.12.6 (5) redaction ------------------------------------------------------

    @Test
    fun `the token and secret appear in no rendering and no error`() = runBlocking {
        val token = Redaction.secret()
        val secret = Redaction.secret()
        val registration = ClientRegistration(
            clientId = clientId,
            clientSecret = Sensitive.of(secret),
            registrationAccessToken = Sensitive.of(token),
        )
        for ((label, rendering) in listOf("toString" to registration.toString(), "template" to "$registration")) {
            Redaction.assertNoFragment(rendering, token, label)
            Redaction.assertNoFragment(rendering, secret, label)
        }
        // Serializing for logs: the type has no serializer at all, so no JSON
        // encoder can reach either value.
        assertNull(serializerOrNull(typeOf<ClientRegistration>()), "ClientRegistration is not serializable")

        answers["GET"] = mutableListOf(json(401, """{"error":"invalid_token"}"""))
        answers["DELETE"] = mutableListOf(MockResponse().setResponseCode(500))
        val client = client(retry = false)
        val errors = listOf(
            assertThrows<OAuthProtocolError> {
                runBlocking { client.readClientRegistration(registrationUri(), Sensitive.of(token)) }
            },
            assertThrows<NetworkError> {
                runBlocking { client.deleteClientRegistration(registrationUri(), Sensitive.of(token)) }
            },
            assertThrows<ValidationError> {
                runBlocking { client.readClientRegistration("https://elsewhere.test/r?t=$token", Sensitive.of(token)) }
            },
        )
        for (error in errors) {
            Redaction.assertNoFragment(error.toString(), token, "error")
            Redaction.assertNoFragment(error.stackTraceToString(), token, "error stack trace")
        }
    }

    // -- decoding -----------------------------------------------------------------------

    @Test
    fun `decoding keeps unknown and mistyped members and wraps both secrets`() {
        val registration = ClientRegistration.fromJson(
            Json.parseToJsonElement(
                """{"client_id":"c1","client_secret":"${Redaction.secret()}",
                   "registration_access_token":"${Redaction.secret()}",
                   "backchannel_token_delivery_mode":"poll","client_id_issued_at":"not-a-number",
                   "redirect_uris":["https://a"],"jwks":{"keys":[]},"client_name":null}""",
            ).jsonObject,
        )
        assertEquals(JsonPrimitive("poll"), registration.extra["backchannel_token_delivery_mode"])
        assertEquals(JsonPrimitive("not-a-number"), registration.extra["client_id_issued_at"])
        assertTrue(registration.clientSecret != null && registration.registrationAccessToken != null)
        assertEquals(listOf("https://a"), registration.redirectUris)
        assertNull(registration.clientName)
        val body = registration.updateBody()
        assertTrue("client_id_issued_at" !in body, "a mistyped server-stated member is dropped too")
        assertEquals(JsonPrimitive("poll"), body["backchannel_token_delivery_mode"])
        assertTrue("jwks" in body)

        assertThrows<NetworkError> { ClientRegistration.fromJson(JsonObject(mapOf("x" to JsonPrimitive(1)))) }
    }

    @Test
    fun `a bodiless 401, a non-JSON 500 and a non-object 200 map by section 2`() = runBlocking {
        answers["GET"] = mutableListOf(
            MockResponse().setResponseCode(401),
            MockResponse().setResponseCode(500).setBody("upstream exploded"),
            json(200, "[]"),
        )
        val client = client(retry = false)
        val token = Sensitive.of(Redaction.secret())
        val unauthorized = assertThrows<io.axiam.sdk.errors.AuthError> {
            runBlocking { client.readClientRegistration(registrationUri(), token) }
        }
        assertTrue(unauthorized !is OAuthProtocolError, "no error object, so §2's 401 row")
        assertThrows<NetworkError> { runBlocking { client.readClientRegistration(registrationUri(), token) } }
        assertThrows<NetworkError> { runBlocking { client.readClientRegistration(registrationUri(), token) } }
        assertEquals(0, refreshes.get())
    }

    @Test
    fun `a member of an unexpected type is kept rather than dropped`() {
        val registration = ClientRegistration.fromJson(
            Json.parseToJsonElement("""{"client_id":"c1","redirect_uris":"https://a","grant_types":null}""").jsonObject,
        )
        assertEquals(JsonPrimitive("https://a"), registration.extra["redirect_uris"])
        assertTrue(registration.redirectUris.isEmpty())
        assertTrue("grant_types" !in registration.extra, "a null is absence, not a member to keep")
    }
}
