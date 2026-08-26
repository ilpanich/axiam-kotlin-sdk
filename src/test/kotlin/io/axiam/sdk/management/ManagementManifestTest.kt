package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * CONTRACT.md §27.6 — the declarative layer's reconciler.
 *
 * The rules under test, in order: plan writes nothing and is stable across
 * runs; validation precedes every request; ordering is derived; drift is an
 * update and omission is never a deletion; apply converges, and stops at the
 * first failure while reporting what it did not attempt.
 */
class ManagementManifestTest : ManagementTestBase() {

    private val roleId = UUID.fromString("66666666-6666-4666-8666-666666666666")
    private val resourceId = UUID.fromString("77777777-7777-4777-8777-777777777777")
    private val archiveId = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private val permissionId = UUID.fromString("88888888-8888-4888-8888-888888888888")
    private val groupId = UUID.fromString("99999999-9999-4999-8999-999999999999")
    private val memberId = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val scopeId = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

    private val stamps =
        """"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z""""

    private fun mountEmptyTenant() {
        for (path in listOf("resources", "permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/$path", 200, pageOf(null))
        }
    }

    private fun sampleManifest(): ManagementManifest = ManagementManifest.builder()
        .resource("docs", "documents", "collection")
        .scope("docs", "draft", "draft", "Unpublished")
        .childResource("archive", "archive", "collection", "docs")
        .permission("read", "document:read", "Read")
        .role("editor", "Editor", "Edits documents")
        .grant("editor", "read", null, "draft")
        .group("staff", "Staff", "Everyone", "editor")
        .user("alice", "alice", "alice@example.test", Sensitive.of("correct-horse"))
        .assignRole("alice", "editor")
        .addToGroup("alice", "staff")
        .build()

    /** §27.6 rule 1: every request a plan makes is a read. */
    @Test
    fun `plan issues no write`() = runTest {
        mountEmptyTenant()
        client.management().manifest().plan(sampleManifest())
        assertTrue(unmatched().isEmpty(), "plan reached a route it should not have: ${unmatched()}")
    }

    /** §27.6 rule 1: a plan run twice against an unchanged tenant is identical. */
    @Test
    fun `plan is stable across runs`() = runTest {
        mountEmptyTenant()
        val first = client.management().manifest().plan(sampleManifest())
        val second = client.management().manifest().plan(sampleManifest())
        assertEquals(first.actions, second.actions, "a plan that reorders itself is not a plan")
    }

    /** §27.6 rule 2: ordering is derived, so a child declared first still follows its parent. */
    @Test
    fun `ordering is derived`() = runTest {
        mountEmptyTenant()
        val plan = client.management().manifest().plan(
            ManagementManifest(
                resources = listOf(
                    ManagementManifest.ResourceSpec("archive", "archive", "collection", "docs"),
                    ManagementManifest.ResourceSpec("docs", "documents", "collection"),
                ),
            ),
        )
        val keys = plan.actions.filter { it.target == ManagementPlan.Target.RESOURCE }.map { it.key }
        assertEquals(listOf("docs", "archive"), keys, "a parent must be planned before its child")
    }

    /** §27.6 rule 1: a dangling reference is refused before the first request. */
    @Test
    fun `a dangling reference is refused before calling`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        roles = listOf(
                            ManagementManifest.RoleSpec(
                                "editor", "Editor", "Edits", false,
                                listOf(ManagementManifest.GrantSpec("nope")),
                            ),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("which no permission declares"))
        assertEquals(0, totalCalls(), "validation must precede every request")
    }

    /** A resource cycle can never be created in any order, so it is refused rather than looped. */
    @Test
    fun `a resource cycle is refused rather than looped`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        resources = listOf(
                            ManagementManifest.ResourceSpec("a", "a", "collection", "b"),
                            ManagementManifest.ResourceSpec("b", "b", "collection", "a"),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("is its own ancestor"))
    }

    /** Every problem is reported at once, not one build at a time. */
    @Test
    fun `every problem is reported not just the first`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        roles = listOf(
                            ManagementManifest.RoleSpec(
                                "editor", "Editor", "Edits", false,
                                listOf(ManagementManifest.GrantSpec("nope", "sideways")),
                            ),
                        ),
                        groups = listOf(
                            ManagementManifest.GroupSpec("staff", "Staff", "All", listOf("ghost")),
                        ),
                    ),
                )
            }
        }
        val message = thrown.message!!
        assertTrue(message.contains("no permission declares"))
        assertTrue(message.contains("only 'allow' and 'deny' exist"))
        assertTrue(message.contains("no role declares"))
    }

    /** §27.6 rule 1: a user that must be created needs a password, and that is known early. */
    @Test
    fun `a user that must be created needs a password`() = runTest {
        mountEmptyTenant()
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().apply(
                    ManagementManifest(
                        users = listOf(
                            ManagementManifest.UserSpec("alice", "alice", "alice@example.test"),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("no initialPassword"))
    }

    /** The builder catches a forward reference the data-class form cannot. */
    @Test
    fun `the builder refuses a forward reference`() {
        val thrown = assertThrows(NetworkError::class.java) {
            ManagementManifest.builder().scope("docs", "draft", "draft", "Unpublished").build()
        }
        assertTrue(thrown.message!!.contains("which no resource(...) call has declared yet"))
    }

    /** Every builder call that names an earlier key checks it, not just the first. */
    @Test
    fun `every builder back reference is checked`() {
        assertTrue(
            assertThrows(NetworkError::class.java) {
                ManagementManifest.builder().grant("editor", "read").build()
            }.message!!.contains("no role(...) call has declared yet"),
        )
        assertTrue(
            assertThrows(NetworkError::class.java) {
                ManagementManifest.builder().assignRole("alice", "editor").build()
            }.message!!.contains("no user(...) call has declared yet"),
        )
        assertTrue(
            assertThrows(NetworkError::class.java) {
                ManagementManifest.builder().addToGroup("alice", "staff").build()
            }.message!!.contains("no user(...) call has declared yet"),
        )
        assertTrue(
            assertThrows(NetworkError::class.java) {
                ManagementManifest.builder()
                    .childResource("archive", "archive", "collection", "docs").build()
            }.message!!.contains("which no resource(...) call has declared yet"),
        )
    }

    private fun mountTenantWithOneRole(description: String) {
        for (path in listOf("resources", "permissions", "groups", "users")) {
            mount("GET", "/api/v1/$path", 200, pageOf(null))
        }
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(roleId, "Editor", description)))
        for (sub in listOf("permissions", "users", "groups")) {
            mount("GET", "/api/v1/roles/$roleId/$sub", 200, "[]")
        }
    }

    private val oneRole = ManagementManifest(
        roles = listOf(ManagementManifest.RoleSpec("editor", "Editor", "Edits documents")),
    )

    /** §27.6 rule 6: a converged tenant plans nothing. */
    @Test
    fun `a converged tenant plans nothing`() = runTest {
        mountTenantWithOneRole("Edits documents")
        val plan = client.management().manifest().plan(oneRole)
        assertTrue(plan.isConverged, "expected convergence, got ${plan.changes}")
        assertFalse(plan.actions.isEmpty(), "a converged plan still reports its no-op steps")
    }

    /** §27.6 rule 3: a drifted field the manifest states is an update. */
    @Test
    fun `a drifted field is an update`() = runTest {
        mountTenantWithOneRole("something else")
        val changes = client.management().manifest().plan(oneRole).changes
        assertEquals(1, changes.size)
        assertEquals(ManagementPlan.Change.UPDATE, changes[0].change)
        assertEquals(ManagementPlan.Target.ROLE, changes[0].target)
    }

    /** §27.6 rule 4: a role the manifest omits is never deleted. */
    @Test
    fun `a role the manifest omits is never deleted`() = runTest {
        mountTenantWithOneRole("Edits documents")
        val plan = client.management().manifest().plan(ManagementManifest.empty())
        assertTrue(
            plan.actions.isEmpty(),
            "a manifest describes what should exist, not what should not",
        )
    }

    private fun resourceBody(id: UUID, name: String, type: String, parent: UUID?): String =
        """{"id":"$id","name":"$name","resource_type":"$type",""" +
            """"parent_id":${if (parent == null) "null" else "\"$parent\""},""" +
            """"metadata":{},"tenant_id":"$TENANT_ID",$stamps}"""

    private fun permissionBody(description: String): String =
        """{"id":"$permissionId","action":"document:read","description":"$description",""" +
            """"tenant_id":"$TENANT_ID",$stamps}"""

    private fun groupBody(description: String): String =
        """{"id":"$groupId","name":"Staff","description":"$description","metadata":{},""" +
            """"tenant_id":"$TENANT_ID",$stamps}"""

    private fun userBody(email: String): String =
        """{"id":"$memberId","username":"alice","email":"$email","email_verified":true,""" +
            """"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,""" +
            """"status":"Active","tenant_id":"$TENANT_ID",$stamps}"""

    private fun page(vararg items: String): String =
        """{"items":[${items.joinToString(",")}],"total":${items.size},"offset":0,"limit":200}"""

    private fun mountCreates() {
        mount("POST", "/api/v1/resources", 201, resourceBody(resourceId, "documents", "collection", null))
        mount(
            "POST", "/api/v1/resources/$resourceId/scopes", 201,
            """{"id":"$scopeId","name":"draft","description":"Unpublished",""" +
                """"resource_id":"$resourceId","tenant_id":"$TENANT_ID",$stamps}""",
        )
        mount("POST", "/api/v1/permissions", 201, permissionBody("Read"))
        mount("POST", "/api/v1/roles", 201, roleBody(roleId, "Editor", "Edits documents"))
        mount("POST", "/api/v1/groups", 201, groupBody("Everyone"))
        mount("POST", "/api/v1/users", 201, userBody("alice@example.test"))
        mount("POST", "/api/v1/roles/$roleId/permissions", 204, "")
        mount("POST", "/api/v1/roles/$roleId/users", 204, "")
        mount("POST", "/api/v1/roles/$roleId/groups", 204, "")
        mount("POST", "/api/v1/groups/$groupId/members", 204, "")
    }

    /** §27.6: apply creates everything and accounts for every step. */
    @Test
    fun `apply creates everything and reports every step`() = runTest {
        mountEmptyTenant()
        mountCreates()

        val report = client.management().manifest().apply(sampleManifest())

        assertTrue(report.isComplete, "apply stopped at ${report.failure}")
        for (step in report.steps) {
            assertEquals(
                ApplyReport.Status.CREATED, step.outcome.status,
                "step ${step.action.summary} was ${step.outcome.status}",
            )
        }
        assertEquals(report.steps.size, report.changedCount)
    }

    /** §27.6 rule 7: apply stops at the first failure and says what it never tried. */
    @Test
    fun `apply stops at the first failure and says what was not attempted`() = runTest {
        mountEmptyTenant()
        mountCreates()
        mount("POST", "/api/v1/permissions", 409, """{"message":"already exists"}""")

        val report = client.management().manifest().apply(sampleManifest())

        assertFalse(report.isComplete)
        assertEquals(ManagementPlan.Target.PERMISSION, report.failure!!.action.target)

        var seenFailure = false
        for (step in report.steps) {
            if (step.outcome.status == ApplyReport.Status.FAILED) {
                seenFailure = true
                continue
            }
            if (seenFailure) {
                assertEquals(
                    ApplyReport.Status.NOT_ATTEMPTED, step.outcome.status,
                    "everything after the failure must be reported as never attempted",
                )
            }
        }
        assertTrue(seenFailure)
    }

    /** Nothing declared means nothing planned and nothing sent. */
    @Test
    fun `applying an empty manifest is clean`() = runTest {
        mountEmptyTenant()
        val report = client.management().manifest().apply(ManagementManifest.empty())
        assertTrue(report.steps.isEmpty())
        assertTrue(report.isComplete)
        assertEquals(0, report.changedCount)
    }

    /** A config file mentioning a password is not a request to reset one. */
    @Test
    fun `a password is never sent for a user that already exists`() = runTest {
        for (path in listOf("resources", "permissions", "roles", "groups")) {
            mount("GET", "/api/v1/$path", 200, pageOf(null))
        }
        mount("GET", "/api/v1/users", 200, pageOf(userBody("alice@example.test")))
        val created = mount("POST", "/api/v1/users", 201, "")

        val report = client.management().manifest().apply(
            ManagementManifest(
                users = listOf(
                    ManagementManifest.UserSpec(
                        "alice", "alice", "alice@example.test", Sensitive.of("would-be-a-reset"),
                    ),
                ),
            ),
        )

        assertEquals(0, created.calls())
        assertEquals(1, report.steps.size)
        assertEquals(ApplyReport.Status.UNCHANGED, report.steps[0].outcome.status)
    }

    /** A deny grant must travel as deny: AXIAM's RBAC is deny-override. */
    @Test
    fun `a deny grant travels as deny`() = runTest {
        mountEmptyTenant()
        mountCreates()
        val grant = route("POST", "/api/v1/roles/$roleId/permissions")

        client.management().manifest().apply(
            ManagementManifest.builder()
                .permission("purge", "document:purge", "Permanently delete")
                .role("editor", "Editor", "Edits documents")
                .grant("editor", "purge", "deny")
                .build(),
        )

        assertEquals("deny", grant.last().json()["effect"]!!.jsonPrimitive.content)
    }

    /** A global role is a role that is global; the flag reaches the wire as one. */
    @Test
    fun `a global role is created global`() = runTest {
        mountEmptyTenant()
        mountCreates()
        val created = route("POST", "/api/v1/roles")

        client.management().manifest().apply(
            ManagementManifest.builder()
                .globalRole("admin", "Administrator", "Everything, everywhere").build(),
        )

        assertTrue(
            created.last().json()["is_global"]!!.jsonPrimitive.boolean,
            "a role declared global must be created global",
        )
    }

    /**
     * Mounts a tenant that already holds every entity [sampleManifest] declares,
     * with the drift-bearing fields supplied by the caller.
     *
     * Passing the manifest's own values makes the tenant converged; passing
     * anything else makes it drifted. Both cases go through exactly the same
     * reads, which is the point: the reconciler must tell them apart from the
     * response bodies alone.
     */
    private fun mountPopulatedTenant(
        resourceType: String,
        permissionDescription: String,
        roleDescription: String,
        groupDescription: String,
        email: String,
    ) {
        mount(
            "GET", "/api/v1/resources", 200,
            page(
                resourceBody(resourceId, "documents", resourceType, null),
                resourceBody(archiveId, "archive", resourceType, resourceId),
            ),
        )
        mount(
            "GET", "/api/v1/resources/$resourceId/scopes", 200,
            """[{"id":"$scopeId","name":"draft","description":"Unpublished",""" +
                """"resource_id":"$resourceId","tenant_id":"$TENANT_ID",$stamps}]""",
        )
        mount("GET", "/api/v1/resources/$archiveId/scopes", 200, "[]")
        mount("GET", "/api/v1/permissions", 200, page(permissionBody(permissionDescription)))
        mount("GET", "/api/v1/roles", 200, page(roleBody(roleId, "Editor", roleDescription)))
        mount(
            "GET", "/api/v1/roles/$roleId/permissions", 200,
            """[{"effect":"allow","permission":${permissionBody(permissionDescription)},""" +
                """"scope_ids":["$scopeId"],"scopes":[]}]""",
        )
        mount(
            "GET", "/api/v1/roles/$roleId/users", 200,
            """[{"user":${userBody(email)},"resource_id":null}]""",
        )
        mount(
            "GET", "/api/v1/roles/$roleId/groups", 200,
            """[{"group":${groupBody(groupDescription)},"resource_id":null}]""",
        )
        mount("GET", "/api/v1/groups", 200, page(groupBody(groupDescription)))
        mount("GET", "/api/v1/groups/$groupId/members", 200, page(userBody(email)))
        mount("GET", "/api/v1/users", 200, page(userBody(email)))
    }

    /**
     * §27.6 rule 6: applying a manifest a second time writes nothing.
     *
     * The single most important property of the declarative layer, and the one
     * a create-from-empty test cannot show: every entity, grant, role
     * assignment and group membership already matches, so every step must
     * report UNCHANGED and no write route may be reached at all.
     */
    @Test
    fun `a second apply of the same manifest writes nothing`() = runTest {
        mountPopulatedTenant("collection", "Read", "Edits documents", "Everyone", "alice@example.test")
        mountCreates()

        val plan = client.management().manifest().plan(sampleManifest())
        assertTrue(plan.isConverged, "expected convergence, got ${plan.changes}")

        val report = client.management().manifest().apply(sampleManifest())
        assertTrue(report.isComplete, "apply stopped at ${report.failure}")
        assertEquals(0, report.changedCount, "a converged tenant must take no writes")
        for (step in report.steps) {
            assertEquals(
                ApplyReport.Status.UNCHANGED, step.outcome.status,
                "step ${step.action.summary} was ${step.outcome.status}",
            )
        }
    }

    /**
     * §27.6 rule 3: drift is an update in place, never a delete-and-recreate.
     *
     * Every entity the manifest can update is drifted at once, so the case
     * fails if any one of the update paths is missing, targets the wrong
     * identifier, or falls through to a create.
     */
    @Test
    fun `every drifted entity is updated in place`() = runTest {
        mountPopulatedTenant("folder", "stale", "stale", "stale", "stale@example.test")
        mountCreates()
        val resource = mount(
            "PUT", "/api/v1/resources/$resourceId", 200,
            resourceBody(resourceId, "documents", "collection", null),
        )
        val child = mount(
            "PUT", "/api/v1/resources/$archiveId", 200,
            resourceBody(archiveId, "archive", "collection", resourceId),
        )
        val permission = mount("PUT", "/api/v1/permissions/$permissionId", 200, permissionBody("Read"))
        val role = mount("PUT", "/api/v1/roles/$roleId", 200, roleBody(roleId, "Editor", "Edits documents"))
        val group = mount("PUT", "/api/v1/groups/$groupId", 200, groupBody("Everyone"))
        val user = mount("PUT", "/api/v1/users/$memberId", 200, userBody("alice@example.test"))

        val report = client.management().manifest().apply(sampleManifest())

        assertTrue(report.isComplete, "apply stopped at ${report.failure}")
        assertEquals(1, resource.calls())
        assertEquals(1, child.calls())
        assertEquals(1, permission.calls())
        assertEquals(1, role.calls())
        assertEquals(1, group.calls())
        assertEquals(1, user.calls())
        assertEquals(
            6, report.steps.count { it.outcome.status == ApplyReport.Status.UPDATED },
            "six entities drifted, so six updates",
        )

        // §27.4 rule 5 end to end: an update carries the field that drifted and
        // nothing else, so reconciling a description cannot clear an email.
        assertEquals(listOf("resource_type"), resource.last().keys())
        assertEquals(listOf("description"), permission.last().keys())
        assertEquals(listOf("description", "is_global"), role.last().keys())
        assertEquals(listOf("description"), group.last().keys())
        assertEquals(listOf("email"), user.last().keys())
    }
}
