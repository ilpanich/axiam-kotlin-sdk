package io.axiam.sdk.management

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.models.CreatePermissionRequest
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateScimTokenRequest
import io.axiam.sdk.management.models.CreateUserRequest
import io.axiam.sdk.management.models.SetMtlsTrustAnchor
import io.axiam.sdk.management.models.UpdateUserRequest
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * CONTRACT.md §27.4, §27.5 and §27.2 semantics — the §27.9 required tests.
 *
 * Every assertion here exists because the thing it checks is easy to get wrong
 * and silent when wrong. Where §27.9 says to assert on the request *path*
 * rather than on the arguments, these do.
 */
class ManagementSemanticsTest : ManagementTestBase() {

    /** §27.4 rule 1: a management call with no session fails locally. */
    @Test
    fun `no session makes no wire call`() = runTest {
        val route = mount("GET", "/api/v1/users", 200, pageOf(null))
        AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build().use { anonymous ->
            val thrown = assertThrows(AuthError::class.java) {
                kotlinx.coroutines.runBlocking { anonymous.management().users().list(null) }
            }
            assertTrue(
                thrown.message!!.contains("no active session"),
                "the refusal should name the missing session, got: ${thrown.message}",
            )
        }
        assertEquals(0, route.calls(), "a session-less call must not reach the network")
    }

    /** §27.4 rule 3: the client's org and tenant are interpolated into the path. */
    @Test
    fun `org and tenant come from the client and land in the path`() = runTest {
        val orgRoute = mount("GET", "/api/v1/organizations/$ORG_ID/ca-certificates", 200, pageOf(null))
        val tenantRoute = mount("GET", "/api/v1/tenants/$TENANT_ID/settings", 200, "{}")

        client.management().caCertificates().list(null)
        client.management().settings().getTenantOverride()

        assertEquals(1, orgRoute.calls(), "{org_id} must come from the session's claims")
        assertEquals(1, tenantRoute.calls(), "{tenant_id} must come from the session's claims")
    }

    /** §27.4 rule 3: an override changes the path and leaves the original handle alone. */
    @Test
    fun `an explicit override changes the path`() = runTest {
        val other = UUID.fromString("44444444-4444-4444-8444-444444444444")
        val scoped = mount("GET", "/api/v1/organizations/$other/ca-certificates", 200, pageOf(null))
        val inherited = mount("GET", "/api/v1/organizations/$ORG_ID/ca-certificates", 200, pageOf(null))

        val handle = client.management().caCertificates()
        handle.inOrg(other).list(null)
        handle.list(null)

        assertEquals(1, scoped.calls(), "the override must reach the named organization")
        assertEquals(1, inherited.calls(), "and must not have mutated the handle it came from")
    }

    /** §27.4 rule 3: no resolved tenant UUID means a local refusal, not a 404. */
    @Test
    fun `a client with no resolved tenant refuses without calling`() = runTest {
        val route = mount("GET", "/api/v1/tenants/$TENANT_ID/settings", 200, "{}")
        AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build().use { anonymous ->
            assertThrows(RuntimeException::class.java) {
                kotlinx.coroutines.runBlocking {
                    anonymous.management().settings().getTenantOverride()
                }
            }
        }
        assertEquals(0, route.calls())
    }

    /** §5 rule 2 does not lapse on this surface. */
    @Test
    fun `the tenant header is still present`() = runTest {
        val route = mount("GET", "/api/v1/users", 200, pageOf(null))
        client.management().users().list(null)
        assertEquals(TENANT_SLUG, route.last().headers["X-Tenant-ID"])
    }

    /** §27.4 rule 4: total is the whole set, not the page. */
    @Test
    fun `total is the whole set not the page`() = runTest {
        mount(
            "GET", "/api/v1/users", 200,
            """{"items":[${userBody(1)}],"total":97,"offset":0,"limit":1}""",
        )
        val page = client.management().users().list(PageRequest.of(1))
        assertEquals(1, page.items.size)
        assertEquals(97, page.total, "reading total from the item count is the bug this type prevents")
        assertFalse(page.isLast)
    }

    /** §27.4 rule 4: the auto-paging walk issues exactly the requests the set needs. */
    @Test
    fun `listAll walks every page with the expected offsets`() = runTest {
        mountPaged()
        val all = client.management().users().listAll(PageRequest.of(2))
        assertEquals(5, all.size)
        assertEquals(listOf("0", "2", "4"), offsetsSeen())
    }

    private var pagedRoute: Route? = null

    private fun offsetsSeen(): List<String> =
        pagedRoute!!.requests.map { it.query["offset"] ?: "" }

    private fun mountPaged() {
        // One route, answering differently by offset: the walk's whole point is
        // that it advances, so a queue of fixed responses would pass even if it
        // asked for offset 0 three times.
        val route = object {
            val inner = mount("GET", "/api/v1/users", 200, "")
        }.inner
        pagedRoute = route
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(
                request: okhttp3.mockwebserver.RecordedRequest,
            ): okhttp3.mockwebserver.MockResponse {
                val full = request.path ?: ""
                val offset = full.substringAfter("offset=", "0").substringBefore('&')
                route.requests += Recorded(
                    request.method ?: "", full.substringBefore('?'),
                    mapOf("offset" to offset), "", emptyMap(),
                )
                val items = when (offset) {
                    "0" -> listOf(userBody(1), userBody(2))
                    "2" -> listOf(userBody(3), userBody(4))
                    else -> listOf(userBody(5))
                }
                return okhttp3.mockwebserver.MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("""{"items":[${items.joinToString(",")}],"total":5,"offset":$offset,"limit":2}""")
            }
        }
    }

    /** §27.4 rule 4: a bare-array read is a list, not a page. */
    @Test
    fun `a bare array operation is not a page`() = runTest {
        mount(
            "GET", "/api/v1/resources/$EXAMPLE_ID/scopes", 200,
            """[{"id":"$EXAMPLE_ID","name":"draft","description":"Unpublished",""" +
                """"resource_id":"$EXAMPLE_ID","tenant_id":"$TENANT_ID",""" +
                """"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}]""",
        )
        // The compiler is the assertion: a List<Scope> has no .total, and had
        // the generator modelled this as a page this line would not build.
        val scopes: List<io.axiam.sdk.management.models.Scope> =
            client.management().scopes().list(EXAMPLE_ID)
        assertEquals(1, scopes.size)
    }

    /** §27.4 rule 5: a sparse update sends exactly the key it was given. */
    @Test
    fun `a sparse update sends exactly the one key it was given`() = runTest {
        val route = mount("PUT", "/api/v1/users/$EXAMPLE_ID", 200, userBody(1))

        client.management().users().update(EXAMPLE_ID, UpdateUserRequest(email = "new@example.test"))

        assertEquals(
            listOf("email"), route.last().keys(),
            "asserting the field is present would pass even when every other " +
                "property went along as null",
        )
    }

    /** §27.4 rule 5: a replacement body's constructor takes every field. */
    @Test
    fun `a replacement body cannot be built half filled`() = runTest {
        val route = mount(
            "PUT",
            "/api/v1/organizations/$ORG_ID/ca-certificates/$EXAMPLE_ID/mtls-trust-anchor",
            200, """{"ca_certificate_id":"$EXAMPLE_ID","mtls_trust_anchor":true,""" +
                """"message":"ok","restart_required":false}""",
        )
        // SetMtlsTrustAnchor has no default for its property, so omitting it is
        // a compile error. That is the whole guarantee §27.4 rule 5 asks for on
        // a replacement body.
        client.management().caCertificates()
            .setMtlsTrustAnchor(EXAMPLE_ID, SetMtlsTrustAnchor(enabled = true))
        assertEquals(listOf("enabled"), route.last().keys())
    }

    /** §27.4 rule 7: 404 is a NotFoundError, and still an AuthzError. */
    @Test
    fun `not found is still an authz error`() = runTest {
        mount("GET", "/api/v1/users/$EXAMPLE_ID", 404, """{"message":"no such user"}""")
        val thrown = assertThrows(NotFoundError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().get(EXAMPLE_ID) }
        }
        assertTrue(thrown is AuthzError)
        assertTrue(thrown.message!!.contains("no such user"))
    }

    /** §27.4 rules 7 and 8: 409 is a ConflictError, and the write goes out once. */
    @Test
    fun `a conflict is not retried`() = runTest {
        val route = mount("POST", "/api/v1/roles", 409, """{"message":"role name already taken"}""")
        val thrown = assertThrows(ConflictError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().roles().create(CreateRoleRequest("Edits", false, "Editor"))
            }
        }
        assertTrue(thrown is AuthzError, "§2 maps 409 to AuthzError and §27.4 rule 7 keeps it there")
        assertTrue(thrown.message!!.contains("already taken"))
        assertEquals(1, route.calls(), "a 409 must not be retried")
    }

    /** §27.4 rule 7: 400 is a ValidationError with field detail, and a NetworkError. */
    @Test
    fun `a bad request carries field detail`() = runTest {
        mount(
            "POST", "/api/v1/users", 400,
            """{"message":"invalid","errors":[{"field":"email","message":"is not an address"}]}""",
        )
        val thrown = assertThrows(ValidationError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().users().create(
                    CreateUserRequest("nope", password = Sensitive.of("pw"), username = "someone"),
                )
            }
        }
        assertTrue(thrown is NetworkError)
        assertEquals(1, thrown.fields.size)
        assertEquals("email", thrown.fields[0].field)
    }

    /** §27.4 rule 7: the object-keyed error shape is understood too. */
    @Test
    fun `unprocessable carries object keyed field detail`() = runTest {
        mount(
            "POST", "/api/v1/permissions", 422,
            """{"message":"invalid","errors":{"action":["must be namespaced"]}}""",
        )
        val thrown = assertThrows(ValidationError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().permissions().create(CreatePermissionRequest("read", "Read"))
            }
        }
        assertEquals("action", thrown.fields[0].field)
        assertTrue(thrown.fields[0].message.contains("namespaced"))
    }

    /**
     * §27.4 rule 7's table, pinned whole.
     *
     * Each sub-type keeps the parent §2 already gave its status. Which status
     * maps to which TYPE is asserted by the cases above; this pins the other
     * half, the PARENT, which nothing else here would notice changing — 409 in
     * particular looks like a transport concern and is not one.
     */
    @Test
    fun `every classification keeps the parent section 2 gave it`() {
        assertTrue(AuthzError::class.java.isAssignableFrom(NotFoundError::class.java))
        assertFalse(NetworkError::class.java.isAssignableFrom(NotFoundError::class.java))
        assertTrue(AuthzError::class.java.isAssignableFrom(ConflictError::class.java))
        assertFalse(NetworkError::class.java.isAssignableFrom(ConflictError::class.java))
        assertTrue(NetworkError::class.java.isAssignableFrom(ValidationError::class.java))
        assertFalse(AuthzError::class.java.isAssignableFrom(ValidationError::class.java))
    }

    /** §27 classifies three statuses and widens the taxonomy no further. */
    @Test
    fun `an ordinary forbidden stays a plain authz error`() = runTest {
        mount("GET", "/api/v1/users/$EXAMPLE_ID", 403, """{"message":"nope"}""")
        val thrown = assertThrows(AuthzError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().get(EXAMPLE_ID) }
        }
        assertFalse(thrown is NotFoundError)
        assertFalse(thrown is ConflictError)
    }

    /** A second delete reports the 404 rather than absorbing it (§27.4 rule 6). */
    @Test
    fun `a repeated delete is not swallowed into success`() = runTest {
        mount("DELETE", "/api/v1/users/$EXAMPLE_ID", 404, """{"message":"already gone"}""")
        assertThrows(NotFoundError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().delete(EXAMPLE_ID) }
        }
    }

    /** §27.4 rule 8: a write is issued exactly once, even on a 503. */
    @Test
    fun `a write is issued exactly once on a server error`() = runTest {
        val route = mount("POST", "/api/v1/roles", 503, """{"message":"try later"}""")
        assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().roles().create(CreateRoleRequest("Edits", false, "Editor"))
            }
        }
        assertEquals(1, route.calls(), "a POST is never retried, however transient the failure looks")
    }

    /** §27.5: a returned one-time secret is redacted from every rendering. */
    @Test
    fun `a returned one time secret is redacted`() = runTest {
        mount(
            "POST", "/api/v1/scim-tokens", 201,
            """{"id":"$EXAMPLE_ID","name":"provisioning","provisioning_token":"tok-abcdef",""" +
                """"created_at":"2026-08-26T00:00:00Z","expires_at":"2027-08-26T00:00:00Z",""" +
                """"created_by":"$EXAMPLE_ID","user_id":"$EXAMPLE_ID","status":"active",""" +
                """"tenant_id":"$TENANT_ID"}""",
        )
        val created = client.management().scimTokens()
            .create(CreateScimTokenRequest(name = "provisioning", userId = EXAMPLE_ID))
        val secret = created.provisioningToken

        assertEquals("tok-abcdef", secret.expose(), "the caller must be able to read it exactly once")
        assertEquals("[SENSITIVE]", secret.toString())
        assertFalse(created.toString().contains("tok-abcdef"), "a data class toString must not leak it")
    }

    /** §27.5: a supplied password is redacted locally but still reaches the wire. */
    @Test
    fun `a supplied password is redacted but still sent`() = runTest {
        val route = mount("POST", "/api/v1/users", 201, userBody(1))
        val body = CreateUserRequest(
            email = "alice@example.test",
            password = Sensitive.of("correct-horse-battery"),
            username = "alice",
        )

        assertFalse(body.toString().contains("correct-horse"), "toString must redact")
        client.management().users().create(body)

        assertEquals(
            "correct-horse-battery",
            route.last().json()["password"]!!.jsonPrimitive.content,
            "the server cannot accept a password nobody can get right; the ONE writer " +
                "that exposes a Sensitive is the request path, and this is it",
        )
    }

    /** §27.2 rule 1: acquiring a handle performs no I/O. */
    @Test
    fun `acquiring a handle performs no io`() = runTest {
        val before = totalCalls()
        repeat(5) {
            client.management().users()
            client.management().caCertificates().inOrg(EXAMPLE_ID)
        }
        assertEquals(before, totalCalls(), "a handle is a view, not a connection")
    }

    /** §18.1 rule 4: use-after-close is an error, never a silent reconnect. */
    @Test
    fun `a closed client rejects every operation`() = runTest {
        val route = mount("GET", "/api/v1/users", 200, pageOf(null))
        val closing = AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build()
        login(closing)
        closing.close()

        assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking { closing.management().users().list(null) }
        }
        assertEquals(0, route.calls())
    }

    /** A response that does not match its declared schema is a clear error. */
    @Test
    fun `a response that does not match its schema names the operation`() = runTest {
        mount("POST", "/api/v1/roles", 201, """{"id":"not-a-uuid"}""")
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().roles().create(CreateRoleRequest("Edits", false, "Editor"))
            }
        }
        assertTrue(
            thrown.message!!.contains("roles.create"),
            "the failure should name the operation, got: ${thrown.message}",
        )
    }

    /** A bare-array read that comes back as an object yields nothing, not a crash. */
    @Test
    fun `a bare array read that is not an array is empty`() = runTest {
        mount("GET", "/api/v1/resources/$EXAMPLE_ID/scopes", 200, "{}")
        assertTrue(client.management().scopes().list(EXAMPLE_ID).isEmpty())
    }

    /** A paginated read with no body at all is an empty page, not a null. */
    @Test
    fun `a paginated read with no body is an empty page`() = runTest {
        mount("GET", "/api/v1/users", 204, "")
        val page = client.management().users().list(null)
        assertTrue(page.items.isEmpty())
        assertEquals(0, page.total)
    }

    /** An unparseable success body names the operation rather than leaking an IOException. */
    @Test
    fun `an unparseable success body names the operation`() = runTest {
        mount("GET", "/api/v1/users", 200, "{not json")
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().list(null) }
        }
        assertTrue(thrown.message!!.contains("users.list"), "got: ${thrown.message}")
    }

    /**
     * §27.4 rule 3: an org configured on the client is used, claims or not.
     *
     * The precedence is handle override, then client configuration, then the
     * access token's claim. This pins the middle rung.
     */
    @Test
    fun `a configured org id outranks the token claim`() = runTest {
        val configured = UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val route = mount("GET", "/api/v1/organizations/$configured/ca-certificates", 200, pageOf(null))
        AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).orgId(configured).build()
            .use { scoped ->
                login(scoped)
                scoped.management().caCertificates().list(null)
            }
        assertEquals(1, route.calls(), "the configured org must be the one in the path")
    }

    /** §27.4 rule 3: an unusable org claim refuses locally and says how to fix it. */
    @Test
    fun `an org claim that is not a uuid refuses without calling`() = runTest {
        val route = mount("GET", "/api/v1/organizations/$ORG_ID/ca-certificates", 200, pageOf(null))
        mintOrgClaim("not-a-uuid")
        AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build().use { broken ->
            login(broken)
            val thrown = assertThrows(NetworkError::class.java) {
                kotlinx.coroutines.runBlocking { broken.management().caCertificates().list(null) }
            }
            assertTrue(
                thrown.message!!.contains("inOrg("),
                "the refusal should say how to supply one, got: ${thrown.message}",
            )
        }
        assertEquals(0, route.calls())
    }

    /** §27.4 rule 3: the implicits are readable, for the routes that take them explicitly. */
    @Test
    fun `the resolved org and tenant are readable`() = runTest {
        assertEquals(ORG_ID, client.resolvedOrgId())
        assertEquals(TENANT_ID, client.resolvedTenantId())
        assertEquals(
            TENANT_SLUG, client.tenantId(),
            "tenantId() is what the client was built with, not what login resolved",
        )
        AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build().use { anonymous ->
            assertEquals(null, anonymous.resolvedTenantId())
            assertEquals(null, anonymous.resolvedOrgId())
        }
    }

    private fun userBody(index: Int): String =
        """{"id":"11111111-1111-4111-8111-00000000000$index","username":"user$index",""" +
            """"email":"user$index@example.test","email_verified":true,""" +
            """"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,""" +
            """"status":"Active","tenant_id":"$TENANT_ID","created_at":"2026-08-26T00:00:00Z",""" +
            """"updated_at":"2026-08-26T00:00:00Z"}"""
}
