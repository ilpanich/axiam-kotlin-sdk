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
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §11.2 rule 11 (d) and (g): `require_scope` reads the `scope`
 * claim only; `roles` and `scope` never stand in for each other.
 */
class RequireScopeTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    private fun statusFor(
        claims: Map<String, kotlinx.serialization.json.JsonElement>,
        omit: Set<String> = emptySet(),
        route: String = "scope",
        bearer: Boolean = true,
    ): HttpStatusCode {
        var status: HttpStatusCode? = null
        testApplication {
            val axiam = jwks.client()
            application {
                install(AxiamAuthentication) { this.client = axiam }
                routing {
                    get("/scope") { call.requireScope("admin") ?: return@get; call.respondText("ok") }
                    get("/role") { call.requireRole("admin") ?: return@get; call.respondText("ok") }
                }
            }
            status = client.get("/$route") {
                if (bearer) header("Authorization", "Bearer ${AccessTokenFixtures.mint(key, claims = claims, omit = omit)}")
            }.status
            axiam.close()
        }
        return status!!
    }

    @Test
    fun `scope openid admin passes requireScope admin`() =
        assertEquals(HttpStatusCode.OK, statusFor(mapOf("scope" to str("openid admin"))))

    @Test
    fun `roles admin with scope openid is refused by requireScope`() =
        assertEquals(
            HttpStatusCode.Forbidden,
            statusFor(mapOf("scope" to str("openid"), "roles" to strings("admin"))),
        )

    @Test
    fun `no scope claim is refused 403`() =
        assertEquals(HttpStatusCode.Forbidden, statusFor(emptyMap(), omit = setOf("scope")))

    @Test
    fun `a scope claim that is not a string is refused 403`() =
        assertEquals(HttpStatusCode.Forbidden, statusFor(mapOf("scope" to JsonPrimitive(12345))))

    @Test
    fun `scope administrator does not pass requireScope admin`() =
        assertEquals(HttpStatusCode.Forbidden, statusFor(mapOf("scope" to str("administrator"))))

    @Test
    fun `an unauthenticated call is 401`() =
        assertEquals(HttpStatusCode.Unauthorized, statusFor(emptyMap(), bearer = false))

    @Test
    fun `the same token passes requireScope and fails requireRole`() {
        val claims = mapOf("scope" to str("openid admin"))
        assertEquals(HttpStatusCode.OK, statusFor(claims, route = "scope"))
        assertEquals(HttpStatusCode.Forbidden, statusFor(claims, route = "role"))
    }

    @Test
    fun `the identity keeps an absent roles claim distinguishable from an empty one`() {
        jwks.client().use { c ->
            val absent = c.verifySession(AccessTokenFixtures.mint(key))
            assertFalse(absent.rolesClaimPresent)
            assertTrue(absent.roles.isEmpty())

            val empty = c.verifySession(AccessTokenFixtures.mint(key, claims = mapOf("roles" to strings())))
            assertTrue(empty.rolesClaimPresent)
            assertTrue(empty.roles.isEmpty())

            val held = c.verifySession(AccessTokenFixtures.mint(key, claims = mapOf("roles" to strings("admin", "auditor"))))
            assertTrue(held.rolesClaimPresent)
            assertEquals(listOf("admin", "auditor"), held.roles)

            val malformed = c.verifySession(AccessTokenFixtures.mint(key, claims = mapOf("roles" to JsonPrimitive("admin"))))
            assertFalse(malformed.rolesClaimPresent)
            assertTrue(malformed.roles.isEmpty())
        }
    }
}
