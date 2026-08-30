package io.axiam.sdk

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.management.ManagementSupport
import io.axiam.sdk.management.models.AssignRoleToGroupRequest
import io.axiam.sdk.management.models.AssignRoleToServiceAccountRequest
import io.axiam.sdk.management.models.AssignRoleToUserRequest
import io.axiam.sdk.management.models.UpdateWebhookRequest
import io.axiam.sdk.opaque.FakeOpaqueNative
import io.axiam.sdk.opaque.installFakeOpaque
import io.axiam.sdk.opaque.resetOpaque
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import java.util.UUID

/**
 * Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the
 * principal tenant, and tenant-scoped role assignments.
 *
 * Two of these rules are the kind an SDK breaks silently rather than loudly,
 * which is why they are pinned here rather than left to the generated surface
 * test:
 *
 * - **§5.2.2 rule 2.** A registration record for the caller's *own* password is
 *   sealed against the tenant the account lives in, not the one the client is
 *   pointed at. Get it wrong and the server answers "the OPAQUE session was
 *   issued for a different tenant" — but only for an organization-level
 *   principal that has switched tenant, so it passes every test written against
 *   an ordinary account.
 * - **§5.2.3 rule 1.** `tenant_scope: []` is refused with `400`. A null check
 *   alone does not prevent it: an empty list is the natural thing to build for
 *   "no tenants named", and it is not null.
 */
class Contract135Test {

    private lateinit var server: MockWebServer
    private lateinit var lib: FakeOpaqueNative

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        lib = installFakeOpaque()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        resetOpaque()
    }

    /**
     * Answers `/auth/login` with [user] as the login response's `user` object, and
     * `/auth/opaque/register/start` with a record the fake library can finish.
     */
    private class ScopedServer(private val user: String) : Dispatcher() {

        val registerStartBodies = mutableListOf<String>()

        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path.orEmpty()
            return when {
                path.endsWith("/auth/opaque/register/start") -> {
                    registerStartBodies += request.body.readUtf8()
                    TestSupport.json(
                        200,
                        """{"opaque_session":"reg-handle",""" +
                            """"registration_response":"$WIRE_REGISTRATION_RESPONSE",""" +
                            """"ksf":"argon2id","memory_kib":19456,"iterations":2,"parallelism":1}""",
                    )
                }
                path.endsWith("/auth/login") ->
                    // The cookies matter as much as the body: `buildUser()` reads the
                    // access token, so a login with no `Set-Cookie` never returns a
                    // LoginResult to assert on.
                    TestSupport.loginOkResponse().setBody("""{"user":$user}""")
                else -> MockResponse().setResponseCode(404)
            }
        }
    }

    private fun <T> withClient(fake: Dispatcher, block: suspend (AxiamClient) -> T): T {
        server.dispatcher = fake
        return runBlocking { TestSupport.clientFor(server).use { block(it) } }
    }

    private fun signIn(user: String): LoginResult =
        withClient(ScopedServer(user)) { it.login("alice@example.com", PASSWORD_TEXT) }

    private fun parse(body: String): JsonObject = Json.parseToJsonElement(body).jsonObject

    // -----------------------------------------------------------------
    // §5.2.2 — acting tenant vs principal tenant
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.2 rule 1: an absent principal tenant reads as the acting tenant")
    fun absentPrincipalTenantReadsAsTheActingTenant() {
        // A server older than contract 1.34 omits `principal_tenant_id` and cannot
        // switch the acting tenant either, so reading `tenant_id` there is not a
        // guess — it is the only value the field could have had.
        val result = signIn("""{"tenant_id":"$ACTING_TENANT"}""")

        val scope = result.scope ?: error("the login reported no §5.2.2 scope")
        assertEquals(UUID.fromString(ACTING_TENANT), scope.actingTenantId)
        assertEquals(UUID.fromString(ACTING_TENANT), scope.principalTenantId)
        assertNull(scope.principalTenantSlug)
    }

    @Test
    @DisplayName("§5.2.2: a divergent principal tenant is reported separately")
    fun divergentPrincipalTenantIsReportedSeparately() {
        val result = signIn(
            """{"tenant_id":"$ACTING_TENANT","principal_tenant_id":"$PRINCIPAL_TENANT",""" +
                """"principal_tenant_slug":"organization","org_id":"$ORG_ID",""" +
                """"organization_level":true}""",
        )

        assertTrue(result.organizationLevel)
        val scope = result.scope ?: error("the login reported no §5.2.2 scope")
        assertEquals(UUID.fromString(ACTING_TENANT), scope.actingTenantId)
        assertEquals(UUID.fromString(PRINCIPAL_TENANT), scope.principalTenantId)
        assertEquals("organization", scope.principalTenantSlug)
        // Rule 3: read the organization from the session rather than resolving a
        // slug through the `super-admin`-only GET /api/v1/organizations.
        assertEquals(UUID.fromString(ORG_ID), scope.orgId)
    }

    @Test
    @DisplayName("§5.2.3 rule 3: reachableTenantIds narrows an organization-level principal")
    fun reachableTenantIdsNarrowsAnOrganizationLevelPrincipal() {
        val result = signIn(
            """{"tenant_id":"$ACTING_TENANT","organization_level":true,""" +
                """"reachable_tenant_ids":["$REACHABLE_TENANT"]}""",
        )

        // Still true — which is exactly why gating a tenant switcher on this flag
        // alone offers tenants the server refuses at the header.
        assertTrue(result.organizationLevel)
        val scope = result.scope ?: error("the login reported no §5.2.3 scope")
        assertEquals(listOf(UUID.fromString(REACHABLE_TENANT)), scope.reachableTenantIds)
    }

    @Test
    @DisplayName("§5.2.3: absent reach is unrestricted, and so is an empty one")
    fun absentReachIsUnrestrictedNotEmpty() {
        // `null`, never an empty list: an empty list would read as "reaches
        // nothing", the opposite of what an omitted field means here.
        assertNull(signIn("""{"tenant_id":"$ACTING_TENANT"}""").scope?.reachableTenantIds)
        assertNull(
            signIn("""{"tenant_id":"$ACTING_TENANT","reachable_tenant_ids":[]}""")
                .scope?.reachableTenantIds,
        )
    }

    // -----------------------------------------------------------------
    // §5.2.2 rule 2 — which tenant a registration record is sealed against
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.2 rule 2: enrolment for self seals against the principal tenant")
    fun enrollmentForSelfSealsAgainstThePrincipalTenant() {
        val fake = ScopedServer(
            """{"tenant_id":"$ACTING_TENANT","principal_tenant_id":"$PRINCIPAL_TENANT",""" +
                """"organization_level":true}""",
        )

        val enrollment = withClient(fake) {
            it.login("alice@example.com", PASSWORD_TEXT)
            it.opaqueEnrollmentForSelf(password())
        }

        assertEquals("reg-handle", enrollment.opaqueSession)
        val body = parse(fake.registerStartBodies[0])
        assertEquals(PRINCIPAL_TENANT, body["tenant_id"]?.jsonPrimitive?.content)
        // A slug naming the acting tenant would out-vote the principal tenant id
        // server-side, which is the exact confusion this override exists to avoid.
        assertNull(body["tenant_slug"])
    }

    @Test
    @DisplayName("§5.2.2 rule 2: plain enrolment still seals against the acting tenant")
    fun plainEnrollmentStillSealsAgainstTheActingTenant() {
        // The other call site, unchanged: creating a record for *another* account
        // seals it against the tenant being acted on.
        val fake = ScopedServer(
            """{"tenant_id":"$ACTING_TENANT","principal_tenant_id":"$PRINCIPAL_TENANT",""" +
                """"organization_level":true}""",
        )

        withClient(fake) {
            it.login("alice@example.com", PASSWORD_TEXT)
            it.opaqueEnrollment(password())
        }

        val body = parse(fake.registerStartBodies[0])
        assertEquals(TestSupport.TENANT_ID, body["tenant_slug"]?.jsonPrimitive?.content)
        assertNull(body["tenant_id"])
    }

    @Test
    @DisplayName("§5.2.2 rule 2: enrolment for self refuses before a login")
    fun enrollmentForSelfRefusesBeforeALogin() {
        // There is no principal tenant to seal against yet, and falling back to the
        // acting one is exactly the bug this method exists to prevent.
        server.dispatcher = ScopedServer("{}")
        val error = assertThrows<NetworkError> {
            runBlocking {
                TestSupport.clientFor(server).use { it.opaqueEnrollmentForSelf(password()) }
            }
        }

        assertTrue(error.message.orEmpty().contains("principal tenant"))
        assertEquals(0, server.requestCount)
    }

    // -----------------------------------------------------------------
    // §5.2.3 rules 1 and 2 — tenant_scope on an assignment
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.3 rule 1: an empty tenant_scope never reaches the wire")
    fun anEmptyTenantScopeNeverReachesTheWire() {
        // `[]` is refused with 400, and an empty list is what building the field
        // from a filtered collection produces for "no tenants named", so both
        // spellings of absent must travel the same way: by not appearing.
        val userId = UUID.fromString("77777777-7777-4777-8777-777777777777")

        val omitted = encode(
            AssignRoleToUserRequest.serializer(),
            AssignRoleToUserRequest(userId = userId),
        )
        val empty = encode(
            AssignRoleToUserRequest.serializer(),
            AssignRoleToUserRequest(userId = userId, tenantScope = emptyList()),
        )

        assertNull(omitted["tenant_scope"])
        assertNull(empty["tenant_scope"])
        // ...and the rest of the body is untouched by the removal.
        assertEquals(userId.toString(), empty["user_id"]?.jsonPrimitive?.content)
    }

    @Test
    @DisplayName("§5.2.3 rule 2: a named tenant_scope is sent on all three bodies")
    fun aNamedTenantScopeIsSent() {
        // Dropping a scope the caller *did* name would turn a refusal they need to
        // see into a success that silently applied no restriction.
        val scoped = UUID.fromString("88888888-8888-4888-8888-888888888888")
        val id = UUID.fromString("99999999-9999-4999-8999-999999999999")

        val bodies = listOf(
            encode(
                AssignRoleToUserRequest.serializer(),
                AssignRoleToUserRequest(userId = id, tenantScope = listOf(scoped)),
            ),
            encode(
                AssignRoleToGroupRequest.serializer(),
                AssignRoleToGroupRequest(groupId = id, tenantScope = listOf(scoped)),
            ),
            encode(
                AssignRoleToServiceAccountRequest.serializer(),
                AssignRoleToServiceAccountRequest(
                    serviceAccountId = id,
                    tenantScope = listOf(scoped),
                ),
            ),
        )

        for (body in bodies) {
            val sent = body["tenant_scope"] as JsonArray
            assertEquals(1, sent.size)
            assertEquals(scoped.toString(), sent[0].jsonPrimitive.content)
        }
    }

    @Test
    @DisplayName("§5.2.3 rule 1: the allowlist is one field wide")
    fun otherEmptyListsAreStillSent() {
        // Elsewhere `[]` is meaningful — a replacement body clearing a list — and
        // dropping it would make "remove every entry" inexpressible.
        val body = encode(
            UpdateWebhookRequest.serializer(),
            UpdateWebhookRequest(events = emptyList()),
        )

        assertEquals(0, (body["events"] as JsonArray).size)
    }

    private fun <T> encode(
        serializer: kotlinx.serialization.KSerializer<T>,
        body: T,
    ): JsonObject = parse(ManagementSupport.encodeBody("contract-1.35 test", serializer, body))

    companion object {
        private const val ACTING_TENANT = "33333333-3333-4333-8333-333333333333"
        private const val PRINCIPAL_TENANT = "55555555-5555-4555-8555-555555555555"
        private const val ORG_ID = "11111111-1111-1111-1111-111111111111"
        private const val REACHABLE_TENANT = "66666666-6666-4666-8666-666666666666"

        /** The hex RegistrationResponse the fake server answers with. */
        private const val WIRE_REGISTRATION_RESPONSE = "726573703a"

        /**
         * A throwaway credential, minted once per run rather than written down.
         *
         * Nothing here depends on the value — the login stub answers 200 regardless,
         * so what is under test is which tenant the body names, never whether a
         * credential matched — and a literal that reads like a credential is a
         * finding for every secret scanner that looks at this repository.
         */
        private val PASSWORD_TEXT: String = ByteArray(8)
            .also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
            .let { "fixture-$it" }

        /** A fresh array each time: the enrolment methods take `CharArray` and wipe it. */
        private fun password(): CharArray = PASSWORD_TEXT.toCharArray()
    }
}
