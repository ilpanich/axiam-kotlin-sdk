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
import io.axiam.sdk.annotations.AxiamRequireAccess
import io.axiam.sdk.annotations.AxiamRequireAuth
import io.axiam.sdk.annotations.AxiamRequireRole
import io.axiam.sdk.ktor.AxiamAuthentication
import io.axiam.sdk.ktor.axiamUser
import io.axiam.sdk.ktor.enforce
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

@AxiamRequireAuth
@AxiamRequireRole("admin")
@AxiamRequireAccess(action = "read", resourceParam = "id")
private class AnnotatedEndpointMarker

class KtorEnforceTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair
    private var authzUp = true
    private val resUuid = "55555555-5555-5555-5555-555555555555"

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        authzUp = true
        backend = MockWebServer()
        backend.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path ?: ""
                return when {
                    path.startsWith("/oauth2/jwks") -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(JWKSet(signingKey.toPublicJWK()).toString())
                    path.startsWith("/api/v1/authz/check") ->
                        if (authzUp) {
                            MockResponse().setResponseCode(200)
                                .addHeader("Content-Type", "application/json").setBody("""{"allowed":true}""")
                        } else {
                            MockResponse().setResponseCode(500).setBody("down")
                        }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        backend.start()
    }

    @AfterEach
    fun tearDown() = backend.shutdown()

    private fun token(scope: String): String {
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

    private val annotations: Array<Annotation> =
        AnnotatedEndpointMarker::class.java.annotations

    @Test
    fun `enforce honors the annotation set and accepts a cookie-sourced token`() = testApplication {
        val axiam = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()
        application {
            install(AxiamAuthentication) { client = axiam }
            routing {
                get("/docs/{id}") {
                    val user = call.enforce(*annotations) ?: return@get
                    call.respondText(user.userId)
                }
            }
        }
        // Token supplied via the axiam_access cookie (not a Bearer header).
        val ok = client.get("/docs/$resUuid") {
            header("Cookie", "axiam_access=${token("admin ops")}")
        }
        assertEquals(HttpStatusCode.OK, ok.status)
        assertEquals("user-1", ok.bodyAsText())
        axiam.close()
    }

    @Test
    fun `enforce fails closed with 503 when the authz endpoint is down`() = testApplication {
        authzUp = false
        val axiam = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()
        application {
            install(AxiamAuthentication) { client = axiam }
            routing {
                get("/docs/{id}") {
                    call.enforce(*annotations) ?: return@get
                    call.respondText("ok")
                }
            }
        }
        val res = client.get("/docs/$resUuid") { header("Authorization", "Bearer ${token("admin")}") }
        assertEquals(HttpStatusCode.ServiceUnavailable, res.status)
        axiam.close()
    }

    @Test
    fun `enforce with no axiam annotations is a passthrough`() = testApplication {
        val axiam = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()
        application {
            install(AxiamAuthentication) { client = axiam }
            routing {
                get("/open") {
                    call.enforce() // no annotations
                    call.respondText("public:${call.axiamUser?.userId ?: "anon"}")
                }
            }
        }
        assertEquals(HttpStatusCode.OK, client.get("/open").status)
        axiam.close()
    }
}
