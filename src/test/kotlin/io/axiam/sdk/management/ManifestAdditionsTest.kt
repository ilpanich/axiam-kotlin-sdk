package io.axiam.sdk.management

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.TestSupport
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * CONTRACT.md §27.9 "Manifest additions" (contract 1.51, §27.6.1).
 *
 * These run against a small **stateful** fake of the tenant rather than canned
 * responses, because the property that matters — `apply(m)` then `plan(m)` is
 * all `NoChange` (§27.6 rule 6) — only means something when the second read
 * sees what the first write did. The fake keeps the server's rules the
 * manifest depends on: one assignment per (subject, role), a resource's
 * metadata replaced whole, `{}` for a resource created without any, and a
 * `client_secret` returned by `create` and never again. Mirrors the reference
 * (Rust) `tests/manifest_additions_test.rs`.
 */
class ManifestAdditionsTest {

    private lateinit var server: MockWebServer
    private lateinit var tenant: FakeTenant
    private lateinit var client: AxiamClient
    private val seen = mutableListOf<RecordedRequest>()

    // ---- the fake tenant --------------------------------------------------

    private data class FakeResource(
        val id: UUID,
        var name: String,
        val parentId: UUID?,
        var metadata: JsonObject,
        var resourceType: String = "site",
    )
    private data class FakeRole(val id: UUID, var name: String, var description: String, val isGlobal: Boolean)
    private data class FakeUser(val id: UUID, val username: String)
    private data class FakeGroup(val id: UUID, var name: String, var description: String)
    private data class FakeServiceAccount(val id: UUID, var name: String, var description: String?)
    private data class FakeAssignment(
        val kind: String, // "users" | "groups" | "service-accounts"
        val role: UUID,
        val subject: UUID,
        val resourceId: UUID?,
        val inherit: Boolean,
        val tenantScope: List<UUID>?,
    )

    private class FakeTenant {
        val resources = mutableListOf<FakeResource>()
        val roles = mutableListOf<FakeRole>()
        val groups = mutableListOf<FakeGroup>()
        val users = mutableListOf<FakeUser>()
        val serviceAccounts = mutableListOf<FakeServiceAccount>()
        val assignments = mutableListOf<FakeAssignment>()
        /** Refuse an assign naming this resource, with a 400 — the fault the restore test needs. */
        var refuseAssignAt: UUID? = null

        fun seedResource(name: String, metadata: JsonObject = JsonObject(emptyMap()), resourceType: String = "site"): UUID {
            val id = UUID.randomUUID()
            resources += FakeResource(id, name, null, metadata, resourceType)
            return id
        }

        fun seedRole(name: String, isGlobal: Boolean = false, description: String = name): UUID {
            val id = UUID.randomUUID()
            roles += FakeRole(id, name, description, isGlobal)
            return id
        }

        fun seedUser(username: String): UUID {
            val id = UUID.randomUUID()
            users += FakeUser(id, username)
            return id
        }

        fun seedGroup(name: String, description: String = name): UUID {
            val id = UUID.randomUUID()
            groups += FakeGroup(id, name, description)
            return id
        }

        fun seedServiceAccount(name: String): UUID {
            val id = UUID.randomUUID()
            serviceAccounts += FakeServiceAccount(id, name, null)
            return id
        }

        fun seedAssignment(a: FakeAssignment) {
            assignments += a
        }
    }

    private val now = "2026-09-24T00:00:00Z"

    private fun stamp() = """"created_at":"$now","updated_at":"$now""""

    private fun resourceJson(r: FakeResource): JsonObject = buildJsonObject {
        put("id", r.id.toString())
        put("tenant_id", TestSupport.TENANT_UUID.toString())
        put("name", r.name)
        put("resource_type", r.resourceType)
        put("parent_id", r.parentId?.toString())
        put("metadata", r.metadata)
        put("created_at", now)
        put("updated_at", now)
    }

    private fun roleJson(r: FakeRole): JsonObject = buildJsonObject {
        put("id", r.id.toString())
        put("tenant_id", TestSupport.TENANT_UUID.toString())
        put("name", r.name)
        put("description", r.description)
        put("is_global", r.isGlobal)
        put("created_at", now)
        put("updated_at", now)
    }

    private fun userJson(u: FakeUser): JsonObject = buildJsonObject {
        put("id", u.id.toString())
        put("tenant_id", TestSupport.TENANT_UUID.toString())
        put("username", u.username)
        put("email", "${u.username}@example.com")
        put("status", "Active")
        put("mfa_enabled", false)
        put("email_verified", true)
        put("metadata", JsonObject(emptyMap()))
        put("created_at", now)
        put("updated_at", now)
        put("failed_login_attempts", 0)
        put("is_locked", false)
    }

    private fun groupJson(g: FakeGroup): JsonObject = buildJsonObject {
        put("id", g.id.toString())
        put("tenant_id", TestSupport.TENANT_UUID.toString())
        put("name", g.name)
        put("description", g.description)
        put("metadata", JsonObject(emptyMap()))
        put("created_at", now)
        put("updated_at", now)
    }

    private fun serviceAccountJson(a: FakeServiceAccount, withSecret: Boolean = false): JsonObject = buildJsonObject {
        put("id", a.id.toString())
        put("tenant_id", TestSupport.TENANT_UUID.toString())
        put("name", a.name)
        put("description", a.description)
        put("client_id", "client-${a.id}")
        put("status", "Active")
        put("created_at", now)
        put("updated_at", now)
        if (withSecret) put("client_secret", "secret-of-${a.id}")
    }

    private fun assignmentJson(a: FakeAssignment): JsonObject {
        val subjectField: String
        val subjectJson: JsonObject
        when (a.kind) {
            "users" -> {
                subjectField = "user"
                subjectJson = userJson(tenant.users.first { it.id == a.subject })
            }
            "groups" -> {
                subjectField = "group"
                subjectJson = groupJson(tenant.groups.first { it.id == a.subject })
            }
            else -> {
                subjectField = "service_account"
                subjectJson = serviceAccountJson(tenant.serviceAccounts.first { it.id == a.subject })
            }
        }
        return buildJsonObject {
            put(subjectField, subjectJson)
            put("resource_id", a.resourceId?.toString())
            put("inherit", a.inherit)
            a.tenantScope?.let { scope ->
                put(
                    "tenant_scope",
                    kotlinx.serialization.json.buildJsonArray {
                        scope.forEach { add(kotlinx.serialization.json.JsonPrimitive(it.toString())) }
                    },
                )
            }
        }
    }

    private fun page(items: List<JsonObject>): String {
        val arr = kotlinx.serialization.json.buildJsonArray { items.forEach { add(it) } }
        return buildJsonObject { put("items", arr); put("total", items.size); put("offset", 0); put("limit", 200) }.toString()
    }

    // `RecordedRequest.body` is a live `Buffer`: reading it CONSUMES the
    // bytes. `respond()` reads it once per request to build the fake's
    // response, and test assertions read the SAME `RecordedRequest` again
    // afterward from `seen` -- so every read here is on a `.clone()`, never
    // the original, or the second read finds nothing left.
    private fun body(r: RecordedRequest): JsonObject =
        Json.parseToJsonElement(r.body.clone().readUtf8()).jsonObject

    /** Requests since [mark], excluding GETs and auth. */
    private fun writesSince(mark: Int): List<RecordedRequest> =
        seen.drop(mark).filter { it.method != "GET" && it.path?.startsWith("/api/v1/auth/") != true }

    private fun mark(): Int = seen.size

    @BeforeEach
    fun setUp() {
        tenant = FakeTenant()
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty().substringBefore('?')
                if (path == "/api/v1/auth/login") {
                    return TestSupport.loginOkResponse()
                }
                seen += request
                return respond(request, path)
            }
        }
        server.start()
        client = TestSupport.clientFor(server)
        runBlocking { client.login("admin@example.test", "hunter2hunter2") }
    }

    @AfterEach
    fun tearDown() {
        client.close()
        server.shutdown()
    }

    private fun respond(request: RecordedRequest, path: String): MockResponse {
        val segments = path.removePrefix("/api/v1/").trim('/').split('/')
        val method = request.method
        fun json(code: Int, body: String) = TestSupport.json(code, body)

        return when {
            method == "GET" && segments == listOf("resources") -> json(200, page(tenant.resources.map(::resourceJson)))
            method == "GET" && segments.size == 3 && segments[0] == "resources" && segments[2] == "scopes" ->
                json(200, "[]")
            method == "POST" && segments == listOf("resources") -> {
                val b = body(request)
                val id = UUID.randomUUID()
                val metadata = (b["metadata"] as? JsonObject) ?: JsonObject(emptyMap())
                val parentId = b["parent_id"]?.jsonPrimitive?.contentOrNullSafe()?.let { UUID.fromString(it) }
                val name = b["name"]!!.jsonPrimitive.content
                val resourceType = b["resource_type"]!!.jsonPrimitive.content
                val r = FakeResource(id, name, parentId, metadata, resourceType)
                tenant.resources += r
                json(201, resourceJson(r).toString())
            }
            method == "PUT" && segments.size == 2 && segments[0] == "resources" -> {
                val id = UUID.fromString(segments[1])
                val r = tenant.resources.first { it.id == id }
                val b = body(request)
                (b["metadata"] as? JsonObject)?.let { r.metadata = it }
                b["resource_type"]?.jsonPrimitive?.contentOrNullSafe()?.let { r.resourceType = it }
                json(200, resourceJson(r).toString())
            }
            method == "GET" && segments == listOf("permissions") -> json(200, page(emptyList()))
            method == "GET" && segments == listOf("roles") -> json(200, page(tenant.roles.map(::roleJson)))
            method == "POST" && segments == listOf("roles") -> {
                val b = body(request)
                val id = UUID.randomUUID()
                val role = FakeRole(
                    id,
                    b["name"]!!.jsonPrimitive.content,
                    b["description"]?.jsonPrimitive?.contentOrNullSafe() ?: "",
                    b["is_global"]?.jsonPrimitive?.content?.toBoolean() ?: false,
                )
                tenant.roles += role
                json(201, roleJson(role).toString())
            }
            method == "PUT" && segments.size == 2 && segments[0] == "roles" -> {
                val id = UUID.fromString(segments[1])
                val r = tenant.roles.first { it.id == id }
                val b = body(request)
                b["description"]?.jsonPrimitive?.contentOrNullSafe()?.let { r.description = it }
                json(200, roleJson(r).toString())
            }
            method == "GET" && segments.size == 3 && segments[0] == "roles" && segments[2] == "permissions" ->
                json(200, "[]")
            method == "GET" && segments.size == 3 && segments[0] == "roles" &&
                segments[2] in listOf("users", "groups", "service-accounts") -> {
                val roleId = UUID.fromString(segments[1])
                val kind = segments[2]
                val rows = tenant.assignments.filter { it.role == roleId && it.kind == kind }.map(::assignmentJson)
                json(200, rows.let { kotlinx.serialization.json.buildJsonArray { it.forEach { e -> add(e) } } }.toString())
            }
            method == "POST" && segments.size == 3 && segments[0] == "roles" &&
                segments[2] in listOf("users", "groups", "service-accounts") -> {
                val roleId = UUID.fromString(segments[1])
                val kind = segments[2]
                val b = body(request)
                val subjectField = when (kind) {
                    "users" -> "user_id"
                    "groups" -> "group_id"
                    else -> "service_account_id"
                }
                val subject = UUID.fromString(b[subjectField]!!.jsonPrimitive.content)
                val resourceId = b["resource_id"]?.jsonPrimitive?.contentOrNullSafe()?.let { UUID.fromString(it) }
                if (resourceId != null && resourceId == tenant.refuseAssignAt) {
                    return json(400, "resource refuses this assignment")
                }
                if (tenant.assignments.any { it.role == roleId && it.subject == subject }) {
                    return json(409, "already assigned")
                }
                val inherit = b["inherit"]?.jsonPrimitive?.content?.toBoolean() ?: true
                val tenantScope = (b["tenant_scope"] as? kotlinx.serialization.json.JsonArray)
                    ?.map { UUID.fromString(it.jsonPrimitive.content) }
                tenant.seedAssignment(FakeAssignment(kind, roleId, subject, resourceId, inherit, tenantScope))
                MockResponse().setResponseCode(204)
            }
            method == "DELETE" && segments.size == 4 && segments[0] == "roles" &&
                segments[2] in listOf("users", "groups", "service-accounts") -> {
                val roleId = UUID.fromString(segments[1])
                val kind = segments[2]
                val subject = UUID.fromString(segments[3])
                val resourceParam = request.requestUrl?.queryParameter("resource_id")?.let { UUID.fromString(it) }
                val before = tenant.assignments.size
                tenant.assignments.removeAll {
                    it.role == roleId && it.kind == kind && it.subject == subject && it.resourceId == resourceParam
                }
                if (tenant.assignments.size == before) MockResponse().setResponseCode(404) else MockResponse().setResponseCode(204)
            }
            method == "GET" && segments == listOf("groups") -> json(200, page(tenant.groups.map(::groupJson)))
            method == "GET" && segments.size == 3 && segments[0] == "groups" && segments[2] == "members" ->
                json(200, page(emptyList()))
            method == "POST" && segments == listOf("groups") -> {
                val b = body(request)
                val id = UUID.randomUUID()
                val g = FakeGroup(
                    id,
                    b["name"]!!.jsonPrimitive.content,
                    b["description"]?.jsonPrimitive?.contentOrNullSafe() ?: "",
                )
                tenant.groups += g
                json(201, groupJson(g).toString())
            }
            method == "PUT" && segments.size == 2 && segments[0] == "groups" -> {
                val id = UUID.fromString(segments[1])
                val g = tenant.groups.first { it.id == id }
                val b = body(request)
                b["description"]?.jsonPrimitive?.contentOrNullSafe()?.let { g.description = it }
                json(200, groupJson(g).toString())
            }
            method == "GET" && segments == listOf("users") -> json(200, page(tenant.users.map(::userJson)))
            method == "POST" && segments == listOf("users") -> {
                val b = body(request)
                val id = UUID.randomUUID()
                val u = FakeUser(id, b["username"]!!.jsonPrimitive.content)
                tenant.users += u
                json(201, userJson(u).toString())
            }
            method == "GET" && segments == listOf("service-accounts") ->
                json(200, page(tenant.serviceAccounts.map { serviceAccountJson(it) }))
            method == "POST" && segments == listOf("service-accounts") -> {
                val b = body(request)
                val id = UUID.randomUUID()
                val a = FakeServiceAccount(id, b["name"]!!.jsonPrimitive.content, b["description"]?.jsonPrimitive?.contentOrNullSafe())
                tenant.serviceAccounts += a
                json(201, serviceAccountJson(a, withSecret = true).toString())
            }
            method == "PUT" && segments.size == 2 && segments[0] == "service-accounts" -> {
                val id = UUID.fromString(segments[1])
                val a = tenant.serviceAccounts.first { it.id == id }
                val b = body(request)
                b["description"]?.jsonPrimitive?.contentOrNullSafe()?.let { a.description = it }
                json(200, serviceAccountJson(a).toString())
            }
            else -> MockResponse().setResponseCode(599).setBody("fake: unhandled $method $path")
        }
    }

    private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
        if (this is kotlinx.serialization.json.JsonNull) null else content

    private fun keys(v: JsonObject): List<String> = v.keys.sorted()

    // -------------------------------------------------------------------
    // §27.6.1 item 1 — metadata
    // -------------------------------------------------------------------

    @Test
    fun `metadata round trips and an update sends the whole object`() = runBlocking {
        val first = buildJsonObject { put("region", "eu"); put("floor", 3) }
        val manifest = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("site", "site-1", "site", metadata = first)),
        )

        val report = client.management().manifest().apply(manifest)
        assertTrue(report.isComplete, "${report.failure}")
        val created = writesSince(0)
        assertEquals(first, body(created[0])["metadata"], "sent on Create")
        assertTrue(client.management().manifest().plan(manifest).isConverged, "§27.6 rule 6")

        val second = buildJsonObject { put("region", "eu"); put("floor", 4) }
        val changed = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("site", "site-1", "site", metadata = second)),
        )
        val plan = client.management().manifest().plan(changed)
        assertEquals(ManagementPlan.Change.UPDATE, plan.actions[0].change)

        val at = mark()
        client.management().manifest().apply(changed)
        val update = writesSince(at).first { it.method == "PUT" }
        val sent = body(update)
        assertEquals(listOf("metadata"), keys(sent), "sparse: only the drifted field")
        assertEquals(second, sent["metadata"], "the whole object, never a merge")
        assertTrue(client.management().manifest().plan(changed).isConverged)
    }

    @Test
    fun `an empty or unstated metadata is not drift`() = runBlocking {
        tenant.seedResource("bare", JsonObject(emptyMap()))
        tenant.seedResource("rich", buildJsonObject { put("hand", "made") })

        val plan = client.management().manifest().plan(
            ManagementManifest(
                resources = listOf(
                    ManagementManifest.ResourceSpec("a", "bare", "site", metadata = JsonObject(emptyMap())),
                    ManagementManifest.ResourceSpec("b", "rich", "site"),
                ),
            ),
        )
        assertTrue(plan.isConverged, "a stated {} and an unstated metadata are not drift")
    }

    // -------------------------------------------------------------------
    // §27.6.1 item 2 — two-shape bindings
    // -------------------------------------------------------------------

    @Test
    fun `a scoped binding sends inherit only when false`() = runBlocking {
        val manifest = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("site", "site-1", "site")),
            roles = listOf(
                ManagementManifest.RoleSpec("resident", "Resident", "Lives here"),
                ManagementManifest.RoleSpec("guest", "Guest", "Visits"),
            ),
            groups = listOf(
                ManagementManifest.GroupSpec(
                    "g", "Residents", "All residents",
                    roles = listOf(
                        ManagementManifest.RoleBinding.atOnly("resident", "site"),
                        ManagementManifest.RoleBinding.at("guest", "site"),
                    ),
                ),
            ),
        )

        val report = client.management().manifest().apply(manifest)
        assertTrue(report.isComplete, "${report.failure}")

        val assigns = writesSince(0).filter { it.path!!.endsWith("/groups") && it.path!!.startsWith("/api/v1/roles/") }
            .map(::body)
        assertEquals(2, assigns.size)
        assertEquals(false, assigns[0]["inherit"]?.jsonPrimitive?.content?.toBoolean())
        assertNotNull(assigns[0]["resource_id"])
        assertEquals(listOf("group_id", "resource_id"), keys(assigns[1]), "an inheriting binding carries no inherit key")
        assertTrue(client.management().manifest().plan(manifest).isConverged)
    }

    @Test
    fun `a changed binding is unassign then assign and keeps tenant_scope`() = runBlocking {
        val oldSite = tenant.seedResource("site-1")
        tenant.seedResource("site-2")
        val role = tenant.seedRole("Concierge")
        val user = tenant.seedUser("ann")
        val scope = UUID.randomUUID()
        tenant.seedAssignment(FakeAssignment("users", role, user, oldSite, true, listOf(scope)))
        val manifest = ManagementManifest(
            resources = listOf(
                ManagementManifest.ResourceSpec("s1", "site-1", "site"),
                ManagementManifest.ResourceSpec("s2", "site-2", "site"),
            ),
            roles = listOf(ManagementManifest.RoleSpec("concierge", "Concierge", "Concierge")),
            users = listOf(
                ManagementManifest.UserSpec(
                    "ann", "ann", "ann@example.com",
                    roles = listOf(ManagementManifest.RoleBinding.at("concierge", "s2")),
                ),
            ),
        )

        val plan = client.management().manifest().plan(manifest)
        val binding = plan.actions.first { it.target == ManagementPlan.Target.USER_ROLE }
        assertEquals(ManagementPlan.Change.UPDATE, binding.change)

        val at = mark()
        val report = client.management().manifest().apply(manifest)
        assertTrue(report.isComplete, "${report.failure}")
        val sent = writesSince(at).filter { it.method != "GET" }
        assertEquals(2, sent.size, "one unassign, one assign")
        assertEquals("DELETE", sent[0].method, "unassign first")
        assertTrue(sent[0].requestUrl.toString().contains(oldSite.toString()))
        assertEquals("POST", sent[1].method, "then assign")
        assertEquals(
            kotlinx.serialization.json.buildJsonArray { add(kotlinx.serialization.json.JsonPrimitive(scope.toString())) },
            body(sent[1])["tenant_scope"],
            "§27.6.1: tenant_scope is carried across, not dropped",
        )
        assertTrue(client.management().manifest().plan(manifest).isConverged)
    }

    @Test
    fun `a failed reassignment restores the previous binding`() = runBlocking {
        val oldSite = tenant.seedResource("site-1")
        val newSite = tenant.seedResource("site-2")
        val role = tenant.seedRole("Concierge")
        val user = tenant.seedUser("ann")
        val scope = UUID.randomUUID()
        tenant.seedAssignment(FakeAssignment("users", role, user, oldSite, false, listOf(scope)))
        tenant.refuseAssignAt = newSite
        val manifest = ManagementManifest(
            resources = listOf(
                ManagementManifest.ResourceSpec("s1", "site-1", "site"),
                ManagementManifest.ResourceSpec("s2", "site-2", "site"),
            ),
            roles = listOf(ManagementManifest.RoleSpec("concierge", "Concierge", "Concierge")),
            users = listOf(
                ManagementManifest.UserSpec(
                    "ann", "ann", "ann@example.com",
                    roles = listOf(ManagementManifest.RoleBinding.at("concierge", "s2")),
                ),
            ),
        )

        val report = client.management().manifest().apply(manifest)

        val outcome = report.steps.first { it.action.target == ManagementPlan.Target.USER_ROLE }.outcome
        assertEquals(ApplyReport.Status.BINDING_UPDATE_FAILED, outcome.status)
        assertTrue(outcome.message!!.contains("refuses"), outcome.message!!)
        assertEquals(true, outcome.restoreSucceeded, "the previous binding is back")
        assertFalse(report.isComplete)
        val held = tenant.assignments.first { it.subject == user }
        assertEquals(oldSite, held.resourceId)
        assertFalse(held.inherit, "same inherit")
        assertEquals(listOf(scope), held.tenantScope, "same tenant_scope")
    }

    @Test
    fun `one role bound twice to one subject is refused with no wire call`() = runBlocking {
        val before = mark()
        val manifest = ManagementManifest(
            resources = listOf(
                ManagementManifest.ResourceSpec("s1", "site-1", "site"),
                ManagementManifest.ResourceSpec("s2", "site-2", "site"),
            ),
            roles = listOf(ManagementManifest.RoleSpec("resident", "Resident", "Lives here")),
            users = listOf(
                ManagementManifest.UserSpec(
                    "ann", "ann", "ann@example.com",
                    roles = listOf(
                        ManagementManifest.RoleBinding.at("resident", "s1"),
                        ManagementManifest.RoleBinding.at("resident", "s2"),
                    ),
                ),
            ),
        )

        val err = assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
            runBlocking { client.management().manifest().plan(manifest) }
        }
        assertTrue(err.message!!.contains("'ann'") && err.message!!.contains("'resident'"), err.message!!)
        assertEquals(before, mark(), "zero wire calls")

        val mixed = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("s1", "site-1", "site")),
            roles = listOf(ManagementManifest.RoleSpec("resident", "Resident", "Lives here")),
            groups = listOf(
                ManagementManifest.GroupSpec(
                    "g", "G", "G",
                    roles = listOf(
                        ManagementManifest.RoleBinding.of("resident"),
                        ManagementManifest.RoleBinding.at("resident", "s1"),
                    ),
                ),
            ),
        )
        assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
            runBlocking { client.management().manifest().plan(mixed) }
        }
        assertEquals(before, mark())
    }

    @Test
    fun `a global role bound here only is refused client side`() = runBlocking {
        val before = mark()
        val manifest = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("s1", "site-1", "site")),
            roles = listOf(ManagementManifest.RoleSpec("admin", "Admin", "Everything", global = true)),
            groups = listOf(
                ManagementManifest.GroupSpec(
                    "g", "G", "G",
                    roles = listOf(ManagementManifest.RoleBinding.atOnly("admin", "s1")),
                ),
            ),
        )
        assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
            runBlocking { client.management().manifest().plan(manifest) }
        }
        assertEquals(before, mark())
    }

    @Test
    fun `a plain binding over a scoped assignment is an update`() = runBlocking {
        val site = tenant.seedResource("site-1")
        val role = tenant.seedRole("Resident")
        val user = tenant.seedUser("ann")
        tenant.seedAssignment(FakeAssignment("users", role, user, site, true, null))

        val plan = client.management().manifest().plan(
            ManagementManifest(
                roles = listOf(ManagementManifest.RoleSpec("resident", "Resident", "Resident")),
                users = listOf(
                    ManagementManifest.UserSpec(
                        "ann", "ann", "ann@example.com",
                        roles = listOf(ManagementManifest.RoleBinding.of("resident")),
                    ),
                ),
            ),
        )
        val binding = plan.actions.first { it.target == ManagementPlan.Target.USER_ROLE }
        assertEquals(ManagementPlan.Change.UPDATE, binding.change)
    }

    // -------------------------------------------------------------------
    // §27.6.1 item 3 and §27.5 rule 5 — service accounts
    // -------------------------------------------------------------------

    @Test
    fun `a created service accounts secret survives a later failure and is never rotated`() = runBlocking {
        val site = tenant.seedResource("site-1")
        tenant.refuseAssignAt = site
        val manifest = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("s1", "site-1", "site")),
            roles = listOf(ManagementManifest.RoleSpec("gate", "Gate", "Opens the gate")),
            serviceAccounts = listOf(
                ManagementManifest.ServiceAccountSpec(
                    "ctl", "gate-controller", description = "Opens the gate",
                    roles = listOf(ManagementManifest.RoleBinding.at("gate", "s1")),
                ),
            ),
        )

        val report = client.management().manifest().apply(manifest)

        assertFalse(report.isComplete, "the binding after the account failed")
        val (action, created) = report.createdServiceAccounts().first()
        assertEquals(ManagementPlan.Target.SERVICE_ACCOUNT, action.target)
        assertTrue(created.clientSecret.expose().startsWith("secret-of-"))
        val rendered = report.toString()
        assertFalse(rendered.contains("secret-of-"), "§7: the secret must never reach toString")
        val accountAt = report.steps.indexOfFirst { it.action.target == ManagementPlan.Target.SERVICE_ACCOUNT }
        val bindingAt = report.steps.indexOfFirst { it.action.target == ManagementPlan.Target.SERVICE_ACCOUNT_ROLE }
        assertTrue(accountAt < bindingAt, "§27.6 rule 5: the account before its binding")

        tenant.refuseAssignAt = null
        val report2 = client.management().manifest().apply(manifest)
        assertTrue(report2.isComplete, "${report2.failure}")
        val account = report2.steps.first { it.action.target == ManagementPlan.Target.SERVICE_ACCOUNT }
        assertEquals(ApplyReport.Status.UNCHANGED, account.outcome.status)
        assertTrue(report2.createdServiceAccounts().none())
        assertTrue(seen.none { it.path?.endsWith("/rotate-secret") == true }, "apply never rotates a secret")
        assertTrue(client.management().manifest().plan(manifest).isConverged)
    }

    @Test
    fun `an ambiguous service account name fails plan before any write`() = runBlocking {
        tenant.seedServiceAccount("gate-controller")
        tenant.seedServiceAccount("gate-controller")
        val manifest = ManagementManifest(
            serviceAccounts = listOf(ManagementManifest.ServiceAccountSpec("ctl", "gate-controller")),
        )

        val err = assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
            runBlocking { client.management().manifest().apply(manifest) }
        }
        assertTrue(err.message!!.contains("ambiguous"), err.message!!)
        assertTrue(writesSince(0).isEmpty(), "nothing written")
    }

    @Test
    fun `only a stated description is reconciled`() = runBlocking {
        tenant.seedServiceAccount("gate-controller")

        val silent = ManagementManifest(
            serviceAccounts = listOf(ManagementManifest.ServiceAccountSpec("ctl", "gate-controller")),
        )
        assertTrue(client.management().manifest().plan(silent).isConverged)

        val stated = ManagementManifest(
            serviceAccounts = listOf(
                ManagementManifest.ServiceAccountSpec("ctl", "gate-controller", description = "Opens the gate"),
            ),
        )
        client.management().manifest().apply(stated)
        val update = writesSince(0).first { it.method == "PUT" }
        assertEquals(listOf("description"), keys(body(update)))
        assertTrue(client.management().manifest().plan(stated).isConverged)
    }

    @Test
    fun `apply then plan converges with every addition`() = runBlocking {
        val manifest = ManagementManifest(
            resources = listOf(
                ManagementManifest.ResourceSpec("site", "site-1", "site", metadata = buildJsonObject { put("k", 1) }),
                ManagementManifest.ResourceSpec("flat", "flat-7", "apartment", parent = "site"),
            ),
            roles = listOf(
                ManagementManifest.RoleSpec("resident", "Resident", "Lives here"),
                ManagementManifest.RoleSpec("concierge", "Concierge", "Runs the site"),
            ),
            groups = listOf(
                ManagementManifest.GroupSpec("staff", "Staff", "Staff", roles = listOf(ManagementManifest.RoleBinding.of("concierge"))),
            ),
            users = listOf(
                ManagementManifest.UserSpec(
                    "ann", "ann", "ann@example.com",
                    initialPassword = Sensitive.of(UUID.randomUUID().toString()),
                    roles = listOf(ManagementManifest.RoleBinding.atOnly("resident", "flat")),
                ),
            ),
            serviceAccounts = listOf(
                ManagementManifest.ServiceAccountSpec(
                    "ctl", "gate-controller",
                    roles = listOf(ManagementManifest.RoleBinding.atOnly("concierge", "site")),
                ),
            ),
        )

        val report = client.management().manifest().apply(manifest)
        assertTrue(report.isComplete, "${report.failure}")
        val plan = client.management().manifest().plan(manifest)
        assertTrue(plan.isConverged, "apply then plan must converge (§27.6 rule 6)")
    }

    /** A guard that the fake itself enforces UNIQUE(subject, role), so the tests above are not passing against a fake more permissive than the server. */
    @Test
    fun `the fake enforces one assignment per subject and role`() = runBlocking {
        val role = tenant.seedRole("R")
        val user = tenant.seedUser("u")
        val url = server.url("/api/v1/roles/$role/users")
        val mediaType = "application/json; charset=utf-8".toMediaType()
        val okhttpClient = okhttp3.OkHttpClient()
        val statuses = (0 until 2).map {
            val req = okhttp3.Request.Builder().url(url)
                .post("""{"user_id":"$user"}""".toRequestBody(mediaType))
                .build()
            okhttpClient.newCall(req).execute().use { it.code }
        }
        assertEquals(listOf(204, 409), statuses)
    }

    @Test
    fun `a flipped inherit rebinds groups and service accounts too`() = runBlocking {
        val site = tenant.seedResource("site-1")
        val role = tenant.seedRole("Concierge")
        val sa = tenant.seedServiceAccount("gate-controller")
        val group = tenant.seedGroup("Staff")
        for ((kind, subject) in listOf("groups" to group, "service-accounts" to sa)) {
            tenant.seedAssignment(FakeAssignment(kind, role, subject, site, true, null))
        }
        val manifest = ManagementManifest(
            resources = listOf(ManagementManifest.ResourceSpec("site", "site-1", "site")),
            roles = listOf(ManagementManifest.RoleSpec("concierge", "Concierge", "Concierge")),
            groups = listOf(
                ManagementManifest.GroupSpec(
                    "staff", "Staff", "Staff",
                    roles = listOf(ManagementManifest.RoleBinding.atOnly("concierge", "site")),
                ),
            ),
            serviceAccounts = listOf(
                ManagementManifest.ServiceAccountSpec(
                    "gate", "gate-controller",
                    roles = listOf(ManagementManifest.RoleBinding.atOnly("concierge", "site")),
                ),
            ),
        )

        val at = mark()
        val report = client.management().manifest().apply(manifest)
        assertTrue(report.isComplete, "${report.failure}")

        val deletes = writesSince(at).filter { it.method == "DELETE" }.map { it.requestUrl!!.encodedPath }
        assertEquals(
            listOf("/api/v1/roles/$role/groups/$group", "/api/v1/roles/$role/service-accounts/$sa"),
            deletes,
        )
        assertTrue(tenant.assignments.all { !it.inherit }, "both now stop at the resource")
        assertTrue(client.management().manifest().plan(manifest).isConverged)
    }
}
