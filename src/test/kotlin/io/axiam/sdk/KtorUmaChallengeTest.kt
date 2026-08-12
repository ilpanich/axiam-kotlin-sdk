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
import io.axiam.sdk.ktor.UmaChallenger
import io.axiam.sdk.ktor.requireAccess
import io.axiam.sdk.oidc.umaParseChallenge
import io.ktor.client.request.get
import io.ktor.client.request.header
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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger

/**
 * The §20.3 emit half, wired into the §11 `requireAccess` guard.
 *
 * Everything asserted here is about the *deny* path, because that is the only
 * path that mints anything:
 *
 *  1. A denial with a challenger mints exactly one ticket and emits it.
 *  2. An allow mints nothing — a guard that minted on the happy path would put
 *     a Protection API call in front of every authorized request.
 *  3. A minting failure still denies, without a challenge. An outage must not
 *     turn a deny into a 503, and must never turn it into an allow.
 */
class KtorUmaChallengeTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair
    private val permCalls = AtomicInteger()
    private val permBodies = mutableListOf<String>()

    private val allowUuid = "33333333-3333-3333-3333-333333333333"
    private val denyUuid = "44444444-4444-4444-4444-444444444444"
    private val pat = "pat-token-value"
    private val ticket = "ticket-value"

    /** Set before start to make the Protection API fail instead of minting. */
    private var permStatus = 201

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
                    path.startsWith("/uma2/perm") -> {
                        permCalls.incrementAndGet()
                        synchronized(permBodies) { permBodies.add(request.body.readUtf8()) }
                        if (permStatus != 201) {
                            MockResponse().setResponseCode(permStatus).setBody("{}")
                        } else {
                            MockResponse().setResponseCode(201)
                                .addHeader("Content-Type", "application/json")
                                .setBody("""{"ticket":"$ticket"}""")
                        }
                    }
                    path.startsWith("/api/v1/authz/check") -> {
                        val allowed = !request.body.readUtf8().contains(denyUuid)
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

    private fun token(): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .claim("scope", "invoices:read")
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
            .build()
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    private fun client() = AxiamClient.builder(backend.url("/").toString(), TestSupport.TENANT_ID).build()

    private fun challenger(axiam: AxiamClient) =
        UmaChallenger("invoices", "https://id.example", Sensitive.of(pat), axiam)

    @Test
    fun `a denial mints one ticket and emits the challenge`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) {
                this.client = axiam
                this.umaChallenge = challenger(axiam)
            }
            routing {
                get("/invoices/{id}") {
                    call.requireAccess("invoices:read", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("invoice")
                }
            }
        }

        val response = client.get("/invoices/$denyUuid") { header("Authorization", "Bearer ${token()}") }

        assertEquals(HttpStatusCode.Forbidden, response.status, "the challenge is additive, not a redirect")
        assertEquals(1, permCalls.get(), "one ticket, not two")

        // The emitted header is the one this SDK's own parser consumes — the
        // round trip is the point of shipping both halves.
        val parsed = umaParseChallenge(response.headers["WWW-Authenticate"] ?: "")
        assertEquals("invoices", parsed?.realm)
        assertEquals("https://id.example", parsed?.asUri)
        assertEquals(ticket, parsed?.ticket?.expose())
        axiam.close()
    }

    @Test
    fun `the ticket asks for the action that was refused`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) {
                this.client = axiam
                this.umaChallenge = challenger(axiam)
            }
            routing {
                get("/invoices/{id}") {
                    call.requireAccess("invoices:approve", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("invoice")
                }
            }
        }

        client.get("/invoices/$denyUuid") { header("Authorization", "Bearer ${token()}") }

        // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else
        // would mint a ticket for authority other than the one just refused —
        // and would step outside the grants the engine evaluated, deny rules
        // included.
        val body = synchronized(permBodies) { permBodies.single() }
        assertTrue(body.contains(""""resource_id":"$denyUuid""""), body)
        assertTrue(body.contains(""""resource_scopes":["invoices:approve"]"""), body)
        axiam.close()
    }

    @Test
    fun `an allow mints nothing`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) {
                this.client = axiam
                this.umaChallenge = challenger(axiam)
            }
            routing {
                get("/invoices/{id}") {
                    call.requireAccess("invoices:read", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("invoice")
                }
            }
        }

        val response = client.get("/invoices/$allowUuid") { header("Authorization", "Bearer ${token()}") }

        assertEquals(HttpStatusCode.OK, response.status)
        // Minting on the happy path would put a Protection API call — and a
        // live credential — in front of every authorized request.
        assertEquals(0, permCalls.get())
        assertNull(response.headers["WWW-Authenticate"])
        axiam.close()
    }

    @Test
    fun `a minting failure still denies without a challenge`() = testApplication {
        permStatus = 500
        val axiam = client()
        application {
            install(AxiamAuthentication) {
                this.client = axiam
                this.umaChallenge = challenger(axiam)
            }
            routing {
                get("/invoices/{id}") {
                    call.requireAccess("invoices:read", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("invoice")
                }
            }
        }

        val response = client.get("/invoices/$denyUuid") { header("Authorization", "Bearer ${token()}") }

        // Failure is not escalation: the caller was going to be refused, and a
        // Protection API outage must not turn that into a 503 — nor, far worse,
        // into an allow.
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(response.headers["WWW-Authenticate"])
        assertTrue(permCalls.get() >= 1)
        axiam.close()
    }

    @Test
    fun `without a challenger a denial is the plain 403 it always was`() = testApplication {
        val axiam = client()
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                get("/invoices/{id}") {
                    call.requireAccess("invoices:read", call.parameters["id"] ?: "") ?: return@get
                    call.respondText("invoice")
                }
            }
        }

        val response = client.get("/invoices/$denyUuid") { header("Authorization", "Bearer ${token()}") }

        // Opt-in means opt-in: an application that never asked for UMA
        // semantics gets no Protection API traffic from its guards.
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(response.headers["WWW-Authenticate"])
        assertEquals(0, permCalls.get())
        axiam.close()
    }

    @Test
    fun `the challenger never renders its pat`() {
        val axiam = client()
        val rendered = challenger(axiam).toString()
        // §7: a challenger is configuration an application may reasonably log,
        // and the PAT inside it is not.
        assertTrue(!rendered.contains(pat), rendered)
        assertTrue(rendered.contains("invoices"), rendered)
        axiam.close()
    }
}
