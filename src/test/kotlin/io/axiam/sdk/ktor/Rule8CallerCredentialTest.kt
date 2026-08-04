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
import io.axiam.sdk.errors.AuthError
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
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64
import java.util.Date

/**
 * CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
 *
 * Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the token
 * the decision is even ABOUT. SEC-085 satisfied all seven and was still an
 * authentication bypass: the PHP guard routed a failed verification into a
 * second, successful one against the *application's own* session, admitting the
 * caller as the app's service account — in an IAM integration typically far more
 * privileged than the user whose request it replaced.
 *
 * **This SDK matters more than most here.** Unlike the Go/Python/TypeScript
 * guards, which are handed a verifier and a tenant, the Ktor plugin holds a full
 * [AxiamClient] (`config.client`) and calls `client.verifySession(token)` on it.
 * That is precisely the structural shape SEC-085 exploited — a stateful client,
 * carrying its own session, reachable from the guard. `verifySession` is
 * correct today (it decides on the supplied token alone), but nothing pinned
 * that, and the client's session sits one method call away.
 *
 * These tests make the substitution path *genuinely reachable* before asserting
 * it is not taken: the client is logged in, its cookie jar holds a real session
 * token for `app-service-account`, and a precondition assertion proves that
 * session is live. Without that priming the tests would pass against the
 * vulnerable shape for an incidental reason — the fallback would fail because
 * there was no session to fall back to — which is the trap the PHP test file
 * documents at length.
 */
class Rule8CallerCredentialTest {

    private lateinit var backend: MockWebServer
    private lateinit var signingKey: OctetKeyPair

    /** The identity an SEC-085-shaped fallback would silently admit callers as. */
    private val appPrincipal = "app-service-account"

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        backend = MockWebServer()
        backend.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path ?: ""
                return when {
                    // Serve the real public key, so verification genuinely
                    // succeeds for a well-formed token. A JWKS that failed for
                    // everything would make every assertion below vacuous.
                    path.startsWith("/oauth2/jwks") -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(JWKSet(signingKey.toPublicJWK()).toString())

                    // Login hands back a session cookie carrying a genuinely
                    // verifiable token for the application's own principal —
                    // the credential a fallback would substitute.
                    path.contains("/auth/login") -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .addHeader("Set-Cookie", "axiam_access=${signed(sub = appPrincipal)}; Path=/")
                        .setBody("""{"user":{"id":"$appPrincipal"}}""")

                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        backend.start()
    }

    @AfterEach
    fun tearDown() = backend.shutdown()

    /** A genuinely Ed25519-signed token, varying only in the claim under test. */
    private fun signed(
        sub: String = "caller-user",
        tenantId: String = TestSupport.TENANT_ID,
        expMillisFromNow: Long = 3_600_000,
    ): String {
        val claims = JWTClaimsSet.Builder()
            .subject(sub)
            .claim("tenant_id", tenantId)
            .claim("scope", "documents:read")
            .expirationTime(Date(System.currentTimeMillis() + expMillisFromNow))
            .build()
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    /** An `alg: none` token — a shape a real signer cannot produce. */
    private fun algNone(): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none","typ":"JWT"}""".toByteArray())
        val payload = enc.encodeToString(
            """{"sub":"attacker","tenant_id":"${TestSupport.TENANT_ID}","exp":4102444800}""".toByteArray(),
        )
        return "$header.$payload."
    }

    /**
     * A client whose OWN session is live — the setup that makes a substitution
     * *possible*, which is the entire point of these tests.
     */
    private fun loggedInClient(): AxiamClient {
        val client = TestSupport.clientFor(backend)
        runBlocking { client.login("app@example.test", "secret") }

        // Guard the guard. If the app session were ever absent, a fallback
        // would fail for an incidental reason and these tests would pass
        // against the vulnerable shape, proving nothing.
        assertNotNull(
            client.verifySession(signed(sub = appPrincipal)),
            "precondition: the application's own credential MUST verify here, " +
                "otherwise a substitution could not succeed and these tests " +
                "cannot distinguish the safe shape from the vulnerable one",
        )
        return client
    }

    /** Caller credentials that must never be admitted, one per failure mode. */
    private fun rejectedCallerTokens(): Map<String, String> = mapOf(
        "expired" to signed(expMillisFromNow = -3_600_000),
        "garbage" to "not-a-real-jwt",
        "unsigned alg:none" to algNone(),
        "foreign tenant" to signed(tenantId = "other-tenant"),
    )

    @Test
    fun `a failed caller token is rejected even when the client session is healthy`() {
        for ((label, callerToken) in rejectedCallerTokens()) {
            testApplication {
                val axiam = loggedInClient()
                application {
                    install(AxiamAuthentication) { this.client = axiam }
                    routing {
                        get("/me") {
                            // Reached only if the guard admitted the caller.
                            val user = call.axiamUser
                            call.respondText(user?.userId ?: "no-identity")
                        }
                    }
                }

                val response = client.get("/me") { header("Authorization", "Bearer $callerToken") }
                val body = response.bodyAsText()

                assertEquals(
                    HttpStatusCode.Unauthorized,
                    response.status,
                    "[$label] a caller token that fails verification must yield 401",
                )
                // The bypass, stated directly: the app's principal must never
                // appear as the identity for a request it did not authenticate.
                assert(!body.contains(appPrincipal)) {
                    "[$label] SECURITY: the caller was admitted as the application's " +
                        "own principal ($appPrincipal) — rule 8 violated"
                }
                axiam.close()
            }
        }
    }

    @Test
    fun `verifySession decides on the supplied token and never the client session`() {
        // Pins the seam directly, so the guard's correctness does not rest on
        // which client method it happens to call today. This is the assertion
        // that would have caught SEC-085 at its source rather than at the
        // framework bridge.
        val axiam = loggedInClient()
        try {
            for ((label, callerToken) in rejectedCallerTokens()) {
                assertThrows(
                    AuthError::class.java,
                    { axiam.verifySession(callerToken) },
                    "[$label] verifySession must throw for a failed token, never fall " +
                        "back to the client's own session",
                )
            }
        } finally {
            axiam.close()
        }
    }

    @Test
    fun `a rejected caller has no identity attached to the call`() {
        // SEC-085 was a bypass rather than a mere error because the request
        // continued carrying an identity. Rejection must leave none behind.
        testApplication {
            val axiam = loggedInClient()
            var observed: String? = "sentinel"
            application {
                install(AxiamAuthentication) { this.client = axiam }
                routing {
                    get("/me") {
                        observed = call.axiamUser?.userId
                        call.respondText("reached")
                    }
                }
            }

            val response = client.get("/me") {
                header("Authorization", "Bearer ${signed(expMillisFromNow = -3_600_000)}")
            }

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertNull(
                observed.takeIf { it != "sentinel" },
                "no identity may be attached for a rejected caller — least of all the " +
                    "application's own service account",
            )
            axiam.close()
        }
    }
}
