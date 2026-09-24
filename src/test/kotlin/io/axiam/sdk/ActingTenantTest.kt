package io.axiam.sdk

import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.management.PageRequest
import kotlinx.coroutines.runBlocking
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
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant helper.
 *
 * An organization-level principal acts on another tenant of its organization by
 * sending `X-Axiam-Tenant`. The assertions here are about the wire, not the
 * arguments: the header is sent when set, **absent when not** (the I4 twin — a
 * client that never asked for one must send what it sent before 1.51), never
 * coupled to `X-Tenant-ID` or a `{tenant_id}` path, and refused client-side when
 * a held login result says the server would refuse it. Mirrors the reference
 * (Rust) `tests/acting_tenant_test.rs`.
 */
class ActingTenantTest {

    private lateinit var server: MockWebServer
    private val otherTenant: UUID = UUID.fromString("44444444-4444-4444-8444-444444444444")
    private val thirdTenant: UUID = UUID.fromString("55555555-5555-4555-8555-555555555555")

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    /** Every non-login/-jwks request this server saw, in order. */
    private val seen = mutableListOf<RecordedRequest>()

    /** Routes registered on top of the fixed `/auth/login` response. */
    private val routes = ConcurrentHashMap<String, MockResponse>()

    private fun mount(method: String, path: String, status: Int, body: String) {
        routes["$method $path"] = TestSupport.json(status, body)
    }

    /**
     * Builds a client already logged in against [loginUserJson] (the login
     * response's `user` object, verbatim) and starts the mock server.
     */
    private fun loggedInClient(loginUserJson: String): AxiamClient {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty().substringBefore('?')
                if (path == "/api/v1/auth/login") {
                    return TestSupport.loginOkResponse().setBody("""{"user":$loginUserJson}""")
                }
                seen += request
                return routes["${request.method} $path"]
                    ?: MockResponse().setResponseCode(501).setBody("no route mounted for ${request.method} $path")
            }
        }
        server.start()
        val client = TestSupport.clientFor(server)
        runBlocking { client.login("root@example.com", "hunter2hunter2") }
        return client
    }

    private fun anonymousClient(): AxiamClient {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                val path = request.path.orEmpty().substringBefore('?')
                return routes["${request.method} $path"]
                    ?: MockResponse().setResponseCode(501).setBody("no route mounted for ${request.method} $path")
            }
        }
        server.start()
        return TestSupport.clientFor(server)
    }

    private val orgAdmin = """{"organization_level": true, "username": "root"}"""

    private fun requestsTo(path: String): List<RecordedRequest> = seen.filter { it.path?.substringBefore('?') == path }

    private fun actingHeader(r: RecordedRequest): String? = r.getHeader(AxiamClient.ACTING_TENANT_HEADER)

    // -------------------------------------------------------------------
    // Sent when set, absent when not
    // -------------------------------------------------------------------

    /**
     * The builder form puts `X-Axiam-Tenant` on a management request and
     * leaves `X-Tenant-ID` naming the constructor tenant — the two headers are
     * read by different mechanisms and this SDK does not couple them (§5,
     * §5.2 rule 1).
     */
    @Test
    fun `the builder form sends the header beside an unchanged X-Tenant-ID`() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty().substringBefore('?')
                if (path == "/api/v1/auth/login") {
                    return TestSupport.loginOkResponse().setBody("""{"user":$orgAdmin}""")
                }
                seen += request
                return routes["${request.method} $path"]
                    ?: MockResponse().setResponseCode(501).setBody("no route mounted")
            }
        }
        server.start()
        val client = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .withActingTenant(otherTenant)
            .build()
        runBlocking { client.login("root@example.com", "hunter2hunter2") }
        assertEquals(otherTenant, client.actingTenantId())
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")

        runBlocking { client.groups.list(PageRequest(limit = 50)) }

        val sent = requestsTo("/api/v1/groups")
        assertEquals(1, sent.size)
        assertEquals(otherTenant.toString(), actingHeader(sent[0]))
        assertEquals(TestSupport.TENANT_ID, sent[0].getHeader("X-Tenant-ID"))
        client.close()
    }

    /**
     * The I4 twin, and the assertion that matters most: a client that never
     * set an acting tenant sends **no** `X-Axiam-Tenant` — on management, on
     * `checkAccess`, on a self-service call, on `refresh` and on `logout`.
     *
     * **This is the test a reverted `actingTenantHeader()` turns red**: making
     * it send the header unconditionally makes every assertion below fail.
     */
    @Test
    fun `a client without an acting tenant sends no header anywhere`() {
        val client = loggedInClient("""{"username":"a"}""")
        assertNull(client.actingTenantId())
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")
        mount("POST", "/api/v1/authz/check", 200, """{"allowed":true}""")
        mount(
            "POST", "/api/v1/auth/mfa/enroll", 200,
            """{"secret_base32":"JBSWY3DPEHPK3PXP","totp_uri":"otpauth://totp/x"}""",
        )
        // refresh() needs a fresh Set-Cookie triple, not a bare 200.
        routes["POST /api/v1/auth/refresh"] = TestSupport.loginOkResponse()
        mount("POST", "/api/v1/auth/logout", 204, "")

        runBlocking {
            client.groups.list(PageRequest(limit = 50))
            client.checkAccess("read", UUID.randomUUID().toString())
            client.mfaEnroll()
            client.refresh()
            client.logout()
        }

        assertTrue(seen.size >= 5, "every call reached the mock: ${seen.size}")
        for (request in seen) {
            assertNull(
                actingHeader(request),
                "${request.method} ${request.path} carried X-Axiam-Tenant without being asked to",
            )
        }
    }

    /**
     * The on-client form returns a **new handle**; the original keeps acting
     * on its own tenant, and `clearActingTenant` sends no header — byte for
     * byte the original's request.
     */
    @Test
    fun `acting tenant rebinds a handle and clearing removes the header`() {
        val client = loggedInClient(orgAdmin)
        mount("GET", "/api/v1/groups", 200, """{"items":[],"total":0,"offset":0,"limit":50}""")

        val acting = client.actingTenant(otherTenant)
        val cleared = acting.clearActingTenant()
        assertEquals(otherTenant, acting.actingTenantId())
        assertNull(client.actingTenantId(), "the original is unchanged")
        assertNull(cleared.actingTenantId())

        runBlocking {
            acting.groups.list(PageRequest(limit = 50))
            client.groups.list(PageRequest(limit = 50))
            cleared.groups.list(PageRequest(limit = 50))
        }

        val sent = requestsTo("/api/v1/groups")
        assertEquals(3, sent.size)
        assertEquals(listOf(otherTenant.toString(), null, null), sent.map { actingHeader(it) })
    }

    /**
     * `{tenant_id}` in a path still defaults from the constructor tenant
     * (§27.4 rule 3). The header and the path are different mechanisms.
     */
    @Test
    fun `the acting tenant does not rewrite a tenant_id path segment`() {
        val client = loggedInClient(orgAdmin).actingTenant(otherTenant)
        val route = "/api/v1/tenants/${TestSupport.TENANT_UUID}/settings"
        mount("GET", route, 404, "")

        runBlocking { runCatching { client.settings.getTenantOverride() } }

        val sent = requestsTo(route)
        assertEquals(1, sent.size, "the path names the constructor tenant, with the header beside it")
        assertEquals(otherTenant.toString(), actingHeader(sent[0]))
    }

    // -------------------------------------------------------------------
    // Gating on a held login result
    // -------------------------------------------------------------------

    /**
     * A login that reported `organization_level: false` — or omitted it,
     * which a server older than contract 1.31 does and which reads as
     * `false` — makes the helper refuse client-side, with no wire call.
     */
    @Test
    fun `a tenant principal is refused client side`() {
        // The harness login omits organization_level entirely.
        val client = loggedInClient("""{"username":"a"}""")
        val before = seen.size

        val err = assertThrows(AuthzError::class.java) { client.actingTenant(otherTenant) }
        assertTrue(err.message!!.contains("organization-level"), err.message)
        assertEquals(before, seen.size, "refused before any wire call")
    }

    /** §5.2.3 rule 4: `reachableTenantIds` bounds the choice when present. */
    @Test
    fun `reachable tenant ids bound the acting tenant`() {
        val client = loggedInClient(
            """{"organization_level": true, "reachable_tenant_ids": ["$otherTenant"], "username": "narrow"}""",
        )

        assertTrue(runCatching { client.actingTenant(otherTenant) }.isSuccess, "inside the reach")
        val err = assertThrows(AuthzError::class.java) { client.actingTenant(thirdTenant) }
        assertTrue(err.message!!.contains("reachableTenantIds"), err.message)
    }

    /**
     * A client holding **no** login result — a service account, an injected
     * token, or nothing yet — has nothing to gate on. The handle is returned,
     * the header is sent, and the server's `403` is the answer.
     */
    @Test
    fun `without a login result the server decides`() {
        val client = anonymousClient()
        val acting = client.actingTenant(otherTenant)
        mount("POST", "/api/v1/authz/check", 403, """{"error":"tenant not reachable"}""")

        assertThrows(io.axiam.sdk.errors.AuthzError::class.java) {
            runBlocking { acting.checkAccess("read", UUID.randomUUID().toString()) }
        }
        assertEquals(otherTenant.toString(), actingHeader(requestsTo("/api/v1/authz/check").single()))
    }

    /**
     * Logging out forgets the previous principal's reach: the next principal
     * is not refused on the strength of someone else's login.
     */
    @Test
    fun `logout forgets the gate`() {
        val client = loggedInClient("""{"username":"a"}""")
        mount("POST", "/api/v1/auth/logout", 204, "")

        assertThrows(AuthzError::class.java) { client.actingTenant(otherTenant) }

        runBlocking { client.logout() }
        assertTrue(runCatching { client.actingTenant(otherTenant) }.isSuccess)
    }

    // -------------------------------------------------------------------
    // The decision memo is keyed on it
    // -------------------------------------------------------------------

    /**
     * Two handles over one session share one §17 memo. A decision taken
     * while acting on one tenant must not answer the same check on another —
     * the server can, and does, answer them differently.
     *
     * **This is the test a reverted memo key (dropping the acting tenant)
     * turns red**: the second handle would then read the first's memoized
     * decision instead of issuing its own request.
     */
    @Test
    fun `the decision memo does not answer across acting tenants`() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty().substringBefore('?')
                if (path == "/api/v1/auth/login") {
                    return TestSupport.loginOkResponse().setBody("""{"user":$orgAdmin}""")
                }
                seen += request
                val header = request.getHeader(AxiamClient.ACTING_TENANT_HEADER)
                val allowed = header == null
                return TestSupport.json(200, """{"allowed": $allowed}""")
            }
        }
        server.start()
        val base = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .decisionMemoTtl(java.time.Duration.ofSeconds(5))
            .build()
        runBlocking { base.login("root@example.com", "hunter2hunter2") }
        val acting = base.actingTenant(otherTenant)
        val resourceId = UUID.randomUUID().toString()

        val ownTenantResult = runBlocking { base.checkAccess("read", resourceId) }
        val otherTenantResult = runBlocking { acting.checkAccess("read", resourceId) }

        assertTrue(ownTenantResult.allowed, "the client's own tenant allows")
        assertFalse(otherTenantResult.allowed, "acting on another tenant is answered differently")
        assertEquals(2, requestsTo("/api/v1/authz/check").size, "the memo did not answer the second from the first")
        base.close()
    }
}
