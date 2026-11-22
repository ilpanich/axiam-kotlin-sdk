package io.axiam.sdk.ktor

import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.AccessTokenFixtures
import io.axiam.sdk.AccessTokenFixtures.str
import io.axiam.sdk.AccessTokenFixtures.strings
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §11.2 rule 11 (contract 1.68; N15, D-1): `require_role` reads the
 * `roles` claim and nothing else, and fails closed when it is absent.
 *
 * Until 1.4.0 this SDK split the `scope` claim into the identity's roles, so any
 * user signed in through a client registered for a scope named like an
 * application role passed that role's guard.
 */
class RequireRoleClaimTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    private fun statusFor(claims: Map<String, kotlinx.serialization.json.JsonElement>): HttpStatusCode {
        var status: HttpStatusCode? = null
        testApplication {
            val axiam = jwks.client()
            application {
                install(AxiamAuthentication) { this.client = axiam }
                routing {
                    get("/admin") {
                        call.requireRole("admin") ?: return@get
                        call.respondText("ok")
                    }
                }
            }
            status = client.get("/admin") {
                header("Authorization", "Bearer ${AccessTokenFixtures.mint(key, claims = claims)}")
            }.status
            axiam.close()
        }
        return status!!
    }

    @Test
    fun `scope openid admin with no roles claim is refused 403`() =
        assertEquals(HttpStatusCode.Forbidden, statusFor(mapOf("scope" to str("openid admin"))))

    @Test
    fun `roles admin with scope openid is admitted`() =
        assertEquals(
            HttpStatusCode.OK,
            statusFor(mapOf("scope" to str("openid"), "roles" to strings("admin"))),
        )

    @Test
    fun `an empty roles array is refused 403`() =
        assertEquals(
            HttpStatusCode.Forbidden,
            statusFor(mapOf("scope" to str("openid admin"), "roles" to strings())),
        )

    @Test
    fun `role names match exactly and case-sensitively`() =
        assertEquals(HttpStatusCode.Forbidden, statusFor(mapOf("roles" to strings("Admin"))))

    @Test
    fun `a roles claim that is a string is refused 403`() =
        assertEquals(
            HttpStatusCode.Forbidden,
            statusFor(mapOf("scope" to str("openid"), "roles" to JsonPrimitive("admin"))),
        )

    @Test
    fun `a roles array with a non-string member is refused 403`() =
        assertEquals(
            HttpStatusCode.Forbidden,
            statusFor(mapOf("roles" to kotlinx.serialization.json.JsonArray(listOf(JsonPrimitive("admin"), JsonPrimitive(1))))),
        )
}
