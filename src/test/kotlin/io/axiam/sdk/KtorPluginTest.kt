package io.axiam.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.ktor.AxiamAuthentication
import io.axiam.sdk.ktor.requireAccess
import io.axiam.sdk.ktor.requireAuth
import io.axiam.sdk.ktor.requireRole
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
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
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date

class KtorPluginTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair
    private val allowUuid = "33333333-3333-3333-3333-333333333333"
    private val denyUuid = "44444444-4444-4444-4444-444444444444"

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
                        val allowed = !body.contains(denyUuid)
                        MockResponse().setResponseCode(200)
                            .addHeader("Content-Type", "application/json")
                            .setBody("""{"allowed":$allowed}""")
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        backend.start()
    }

    @AfterEach
    fun tearDown() = backend.shutdown()

    private fun token(scope: String = "documents:read"): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .claim("scope", scope)
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
            .build()
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    private fun client() = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()

    @Test
    fun `requireAuth rejects an unauthenticated request with 401`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                get("/me") {
                    val user = call.requireAuth() ?: return@get
                    call.respondText(user.userId)
                }
            }
        }
        val response = client.get("/me")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        axiam.close()
    }

    @Test
    fun `requireAuth injects the user for a valid token`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                get("/me") {
                    val user = call.requireAuth() ?: return@get
                    call.respondText(user.userId)
                }
            }
        }
        val response = client.get("/me") { header("Authorization", "Bearer ${token()}") }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("user-1", response.bodyAsText())
        axiam.close()
    }

    @Test
    fun `requireRole allows a holder and forbids a non-holder`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                get("/admin") {
                    call.requireRole("admin") ?: return@get
                    call.respondText("ok")
                }
            }
        }
        assertEquals(
            HttpStatusCode.OK,
            client.get("/admin") { header("Authorization", "Bearer ${token("admin ops")}") }.status,
        )
        assertEquals(
            HttpStatusCode.Forbidden,
            client.get("/admin") { header("Authorization", "Bearer ${token("documents:read")}") }.status,
        )
        axiam.close()
    }

    @Test
    fun `requireAccess maps allow deny bad-uuid to 200 403 400`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                get("/docs/{id}") {
                    call.requireAccess("read", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("ok")
                }
            }
        }
        val auth: io.ktor.client.request.HttpRequestBuilder.() -> Unit =
            { header("Authorization", "Bearer ${token()}") }
        assertEquals(HttpStatusCode.OK, client.get("/docs/$allowUuid", auth).status)
        assertEquals(HttpStatusCode.Forbidden, client.get("/docs/$denyUuid", auth).status)
        assertEquals(HttpStatusCode.BadRequest, client.get("/docs/not-a-uuid", auth).status)
        axiam.close()
    }
}
