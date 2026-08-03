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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date

class KtorPluginTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair
    private val allowUuid = "33333333-3333-3333-3333-333333333333"
    private val denyUuid = "44444444-4444-4444-4444-444444444444"
    private val authzErrorUuid = "66666666-6666-6666-6666-666666666666"
    private val authErrorUuid = "77777777-7777-7777-7777-777777777777"

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
                        when {
                            body.contains(authzErrorUuid) -> MockResponse().setResponseCode(403).setBody("{}")
                            body.contains(authErrorUuid) -> MockResponse().setResponseCode(401).setBody("{}")
                            else -> {
                                val allowed = !body.contains(denyUuid)
                                MockResponse().setResponseCode(200)
                                    .addHeader("Content-Type", "application/json")
                                    .setBody("""{"allowed":$allowed}""")
                            }
                        }
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

    @Test
    fun `requireAccess maps a thrown AuthzError to 403 and a thrown AuthError to 401`() = testApplication {
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
        assertEquals(HttpStatusCode.Forbidden, client.get("/docs/$authzErrorUuid", auth).status)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/docs/$authErrorUuid", auth).status)
        axiam.close()
    }

    @Test
    fun `AxiamAuthentication requires a configured client`() {
        assertThrows(IllegalArgumentException::class.java) {
            testApplication {
                application {
                    install(AxiamAuthentication) { }
                    routing {
                        get("/ping") { call.respondText("pong") }
                    }
                }
                // Forces the (lazily-started) test application to actually
                // initialize, so the plugin's requireNotNull runs.
                client.get("/ping")
            }
        }
    }

    // --- §15.3.3: a presented-but-invalid token is rejected by the plugin ---
    //
    // The plugin used to swallow the AuthError and leave the user attribute
    // absent, deferring the decision to the per-route helpers. A route that
    // forgot requireAuth() therefore ran UNAUTHENTICATED for a caller who had
    // presented an expired, foreign-tenant or forged token. Java and C# make the
    // same choice deliberately, but they sit behind Spring Security / ASP.NET
    // authorization; Ktor has no equivalent layer behind this plugin.

    private fun expiredToken(): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .expirationTime(Date(System.currentTimeMillis() - 3_600_000))
            .build()
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    /** The headline case: an unguarded route must NOT serve a bad token. */
    @Test
    fun `a route without requireAuth does not serve a caller whose token failed`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                // Deliberately no requireAuth() — this is the mistake the plugin
                // must not turn into an unauthenticated success.
                get("/unguarded") { call.respondText("sensitive") }
            }
        }
        val response = client.get("/unguarded") {
            header("Authorization", "Bearer ${expiredToken()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            false,
            response.bodyAsText().contains("sensitive"),
            "the handler must not have run for a caller whose credential failed",
        )
        axiam.close()
    }

    /** Garbage and foreign-tenant tokens are the same class. */
    @Test
    fun `a malformed token is rejected by the plugin itself`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing { get("/unguarded") { call.respondText("sensitive") } }
        }
        val response = client.get("/unguarded") { header("Authorization", "Bearer not-a-jwt") }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        axiam.close()
    }

    /**
     * The distinction that keeps this from being a blunt instrument: a call with
     * NO token has not failed authentication, so public routes must keep working.
     */
    @Test
    fun `a request with no token at all still reaches a public route`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing { get("/public") { call.respondText("open") } }
        }
        val response = client.get("/public")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("open", response.bodyAsText())
        axiam.close()
    }
}

