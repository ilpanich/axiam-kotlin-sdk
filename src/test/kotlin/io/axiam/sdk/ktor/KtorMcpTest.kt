package io.axiam.sdk.ktor

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.AxiamClient
import io.axiam.sdk.TestSupport
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.mcp.Mcp
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date

/**
 * CONTRACT.md §28.9 required tests 3, 4 and 5 — the three that need a route
 * behind the guard — plus the regression that matters more than all five.
 * Tests 1 and 2 live in `io.axiam.sdk.mcp.McpTest`, framework-independent.
 *
 * Uses §28.9's fixture: `resource = "https://mcp.example.com/mcp"`,
 * `authorizationServers = ["https://axiam.example.com"]`,
 * `scopesSupported = ["mcp:read", "mcp:tools"]`, so `metadataUrl` is
 * `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` and the
 * four §28.4 vectors are exactly the ones `McpTest` asserts.
 */
class KtorMcpTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair

    private val allowUuid = "10000000-0000-0000-0000-000000000001"
    private val noGrantUuid = "10000000-0000-0000-0000-000000000002"
    private val deniedByRuleUuid = "10000000-0000-0000-0000-000000000003"
    private val absentReasonUuid = "10000000-0000-0000-0000-000000000004"

    private val resource = "https://mcp.example.com/mcp"
    private val metadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    private fun metadata() = Mcp.protectedResourceMetadata(
        resource = resource,
        authorizationServers = listOf("https://axiam.example.com"),
        scopesSupported = listOf("mcp:read", "mcp:tools"),
    )

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        backend = MockWebServer()
        backend.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path ?: ""
                return when {
                    path.startsWith("/oauth2/jwks") -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(JWKSet(signingKey.toPublicJWK()).toString())
                    path.startsWith("/api/v1/authz/check") -> {
                        val body = request.body.readUtf8()
                        val decision = when {
                            body.contains(allowUuid) -> """{"allowed":true}"""
                            body.contains(noGrantUuid) -> """{"allowed":false,"reason_code":"no_grant"}"""
                            body.contains(deniedByRuleUuid) -> """{"allowed":false,"reason_code":"denied_by_rule"}"""
                            body.contains(absentReasonUuid) -> """{"allowed":false}"""
                            else -> """{"allowed":false,"reason_code":"no_grant"}"""
                        }
                        MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody(decision)
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        backend.start()
    }

    @AfterEach
    fun tearDown() = backend.shutdown()

    private fun guardClient(): AxiamClient =
        AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID)
            .expectedAudience(resource)
            .build()

    private fun token(aud: String? = resource, expired: Boolean = false): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .apply { if (aud != null) audience(aud) }
            .expirationTime(Date(System.currentTimeMillis() + if (expired) -3_600_000 else 3_600_000))
            .build()
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    // -----------------------------------------------------------------
    // §28.9 test 3 — 401 with the challenge, and the unauthenticated document
    // -----------------------------------------------------------------

    @Test
    fun `401 carries vector 1 with no credential and vector 2 with an expired token, body unchanged`() = testApplication {
        val axiam = guardClient()
        val meta = metadata()
        application {
            install(AxiamAuthentication) { client = axiam; resourceMetadataUrl = metadataUrl }
            routing {
                serveProtectedResourceMetadata(meta, metadataUrl, axiam.expectedAudience())
                get("/me") { call.requireAuth() ?: return@get; call.respondText("ok") }
            }
        }

        val noCred = client.get("/me")
        assertEquals(HttpStatusCode.Unauthorized, noCred.status)
        assertEquals(
            "Bearer resource_metadata=\"$metadataUrl\"",
            noCred.headers[HttpHeaders.WWWAuthenticate],
        )
        assertEquals("""{"error":"authentication_failed","message":"authentication required"}""", noCred.bodyAsText())
        assertFalse(noCred.bodyAsText().contains("error_description"))

        val expired = client.get("/me") { header("Authorization", "Bearer ${token(expired = true)}") }
        assertEquals(HttpStatusCode.Unauthorized, expired.status)
        assertEquals(
            "Bearer error=\"invalid_token\", resource_metadata=\"$metadataUrl\"",
            expired.headers[HttpHeaders.WWWAuthenticate],
        )
        assertEquals(
            """{"error":"authentication_failed","message":"invalid or expired token"}""",
            expired.bodyAsText(),
        )
        assertFalse(expired.bodyAsText().contains("error_description"))

        // Separately: the document itself, unauthenticated.
        val doc = client.get(meta.metadataPath)
        assertEquals(HttpStatusCode.OK, doc.status)
        assertTrue(doc.bodyAsText().contains("\"resource\":\"$resource\""))

        axiam.close()
    }

    // -----------------------------------------------------------------
    // §28.9 test 4 — 403 insufficient_scope, and the three that carry none
    // -----------------------------------------------------------------

    @Test
    fun `403 carries vector 3 only for a scoped no_grant denial`() = testApplication {
        val axiam = guardClient()
        application {
            install(AxiamAuthentication) { client = axiam; resourceMetadataUrl = metadataUrl }
            routing {
                get("/scoped/{id}") {
                    call.requireAccess("read", call.parameters["id"]!!, scope = "mcp:tools") ?: return@get
                    call.respondText("ok")
                }
                get("/unscoped/{id}") {
                    call.requireAccess("read", call.parameters["id"]!!) ?: return@get
                    call.respondText("ok")
                }
            }
        }
        val auth: io.ktor.client.request.HttpRequestBuilder.() -> Unit = { header("Authorization", "Bearer ${token()}") }

        val noGrant = client.get("/scoped/$noGrantUuid", auth)
        assertEquals(HttpStatusCode.Forbidden, noGrant.status)
        assertEquals(
            "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"$metadataUrl\"",
            noGrant.headers[HttpHeaders.WWWAuthenticate],
        )
        assertEquals("""{"error":"authorization_denied","message":"access denied"}""", noGrant.bodyAsText())

        val deniedByRule = client.get("/scoped/$deniedByRuleUuid", auth)
        assertEquals(HttpStatusCode.Forbidden, deniedByRule.status)
        assertNull(deniedByRule.headers[HttpHeaders.WWWAuthenticate])

        val absentReason = client.get("/scoped/$absentReasonUuid", auth)
        assertEquals(HttpStatusCode.Forbidden, absentReason.status)
        assertNull(absentReason.headers[HttpHeaders.WWWAuthenticate])

        val unscoped = client.get("/unscoped/$noGrantUuid", auth)
        assertEquals(HttpStatusCode.Forbidden, unscoped.status)
        assertNull(unscoped.headers[HttpHeaders.WWWAuthenticate])

        axiam.close()
    }

    // -----------------------------------------------------------------
    // §28.9 test 5 — a token whose aud is not the resource is refused
    // -----------------------------------------------------------------

    @Test
    fun `a token whose aud is not the resource is refused, the matching one admitted`() = testApplication {
        val axiam = guardClient()
        application {
            install(AxiamAuthentication) { client = axiam; resourceMetadataUrl = metadataUrl }
            routing { get("/me") { call.requireAuth() ?: return@get; call.respondText("ok") } }
        }

        val wrongResource = client.get("/me") { header("Authorization", "Bearer ${token(aud = "https://other.example.com/mcp")}") }
        assertEquals(HttpStatusCode.Unauthorized, wrongResource.status)
        assertEquals(
            "Bearer error=\"invalid_token\", resource_metadata=\"$metadataUrl\"",
            wrongResource.headers[HttpHeaders.WWWAuthenticate],
        )

        // A general-purpose AXIAM user token is not a token for this resource server.
        val generalPurpose = client.get("/me") { header("Authorization", "Bearer ${token(aud = "axiam:user")}") }
        assertEquals(HttpStatusCode.Unauthorized, generalPurpose.status)
        assertEquals(
            "Bearer error=\"invalid_token\", resource_metadata=\"$metadataUrl\"",
            generalPurpose.headers[HttpHeaders.WWWAuthenticate],
        )

        val admitted = client.get("/me") { header("Authorization", "Bearer ${token(aud = resource)}") }
        assertEquals(HttpStatusCode.OK, admitted.status)

        axiam.close()
    }

    @Test
    fun `configuring resourceMetadataUrl without an expected audience fails at construction`() {
        assertThrows(ValidationError::class.java) {
            testApplication {
                val axiam = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()
                application {
                    // No .expectedAudience(...) on `axiam` — §28.5 rule 2.
                    install(AxiamAuthentication) { client = axiam; resourceMetadataUrl = metadataUrl }
                    routing { get("/ping") { call.respondText("pong") } }
                }
                client.get("/ping")
            }
        }
    }

    // -----------------------------------------------------------------
    // The regression that matters more than all five
    // -----------------------------------------------------------------

    @Test
    fun `with resourceMetadataUrl unset every response carries no WWW-Authenticate header`() = testApplication {
        val axiam = guardClient()
        application {
            install(AxiamAuthentication) { client = axiam } // resourceMetadataUrl left unset
            routing {
                get("/me") { call.requireAuth() ?: return@get; call.respondText("ok") }
                get("/scoped/{id}") {
                    call.requireAccess("read", call.parameters["id"]!!, scope = "mcp:tools") ?: return@get
                    call.respondText("ok")
                }
            }
        }

        val noCred = client.get("/me")
        assertEquals(HttpStatusCode.Unauthorized, noCred.status)
        assertNull(noCred.headers[HttpHeaders.WWWAuthenticate], "§28 off: no header on a 401 with no credential")
        assertEquals("""{"error":"authentication_failed","message":"authentication required"}""", noCred.bodyAsText())

        val expired = client.get("/me") { header("Authorization", "Bearer ${token(expired = true)}") }
        assertEquals(HttpStatusCode.Unauthorized, expired.status)
        assertNull(expired.headers[HttpHeaders.WWWAuthenticate], "§28 off: no header on a 401 for a bad credential")

        val denied = client.get("/scoped/$noGrantUuid") { header("Authorization", "Bearer ${token()}") }
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertNull(denied.headers[HttpHeaders.WWWAuthenticate], "§28 off: no header on a no_grant 403 either")

        val allowed = client.get("/scoped/$allowUuid") { header("Authorization", "Bearer ${token()}") }
        assertEquals(HttpStatusCode.OK, allowed.status)
        assertNull(allowed.headers[HttpHeaders.WWWAuthenticate])

        axiam.close()
    }
}
