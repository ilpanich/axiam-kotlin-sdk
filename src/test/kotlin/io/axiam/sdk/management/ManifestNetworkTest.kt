package io.axiam.sdk.management

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.management.ManagementManifest.NetworkPolicySpec
import io.axiam.sdk.management.ManagementManifest.NetworkProfileSpec
import io.axiam.sdk.management.ManagementManifest.NetworkSegmentSpec
import io.axiam.sdk.management.ManagementManifest.NetworkSpec
import io.axiam.sdk.management.models.NetworkSegmentKind
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * CONTRACT.md §27.9 "Manifest, `network`" (contract 1.62, §27.6.2) — the `network` namespace in a
 * manifest: natural keys, the order policy, segments, profiles, the version-conditional
 * `replace_*` bodies built from the read, the `409` and `403` as the action's failure, and the
 * refusals made before any request.
 *
 * This SDK ships no pruning at all (§27.6 rule 4's opt-in is not implemented for any namespace;
 * the README says so), so the pruning tests are replaced by the one assertion that survives:
 * a segment the manifest does not state is neither reported nor deleted.
 */
class ManifestNetworkTest : ManagementTestBase() {

    private val segments = "/api/v1/network/segments"
    private val profiles = "/api/v1/network/profiles"
    private val policy = "/api/v1/network/policy"
    private val labId: UUID = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val guestId: UUID = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private val newId: UUID = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

    private fun mountEmptyTenant() {
        for (path in listOf("resources", "permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/$path", 200, pageOf(null))
        }
    }

    private fun segmentJson(
        id: UUID = labId,
        name: String = "lab",
        kind: String = "access",
        vlan: Int = 20,
        version: Int = 7,
        rank: String = "1",
        filters: String = """"a","b"""",
        enabled: Boolean = true,
    ) = """{"id":"$id","tenant_id":"$TENANT_ID","path":"/network/zones/default/$name","name":"$name",
        "site_key":"default","kind":"$kind","vlan_id":$vlan,"filter_ids":[$filters],"rank":$rank,
        "enabled":$enabled,"version":$version,"created_by":"$EXAMPLE_ID","updated_by":"$EXAMPLE_ID",
        "created_at":"2026-10-16T00:00:00Z","updated_at":"2026-10-16T00:00:00Z"}"""

    private fun profileJson(
        segment: UUID = labId,
        timeout: Int = 1800,
        clamped: Boolean = false,
        idle: String = "null",
        filter: String = "\"a\"",
        version: Int = 4,
    ) = """{"segment_id":"$segment","tenant_id":"$TENANT_ID","dictionary":"axiam-radius-reply/1",
        "session_timeout_secs":$timeout,"session_timeout_clamped":$clamped,"termination_action":"radius_request",
        "idle_timeout_secs":$idle,"filter_id":$filter,"service_type":null,"version":$version,
        "created_by":"$EXAMPLE_ID","updated_by":"$EXAMPLE_ID",
        "created_at":"2026-10-16T00:00:00Z","updated_at":"2026-10-16T00:00:00Z"}"""

    private fun policyJson(cap: Int = 3600, version: Int = 0) =
        """{"tenant_id":"$TENANT_ID","session_timeout_max_secs":$cap,"version":$version}"""

    private fun page(vararg items: String) =
        """{"items":[${items.joinToString(",")}],"total":${items.size},"offset":0,"limit":200}"""

    private fun lab(
        vlan: Int = 20,
        filters: List<String>? = listOf("a", "b"),
        rank: JsonNullable<Int> = JsonNullable.Value(1),
        enabled: Boolean? = null,
    ) = NetworkSegmentSpec(
        key = "lab", site = "default", kind = NetworkSegmentKind.ACCESS, name = "lab",
        vlanId = vlan, rank = rank, filterIds = filters, enabled = enabled,
    )

    private fun manifest(
        policy: NetworkPolicySpec? = null,
        segments: List<NetworkSegmentSpec> = listOf(lab()),
        profiles: List<NetworkProfileSpec> = emptyList(),
    ) = ManagementManifest(network = NetworkSpec(policy, segments, profiles))

    private fun requestLog(): List<String> {
        val out = mutableListOf<String>()
        while (true) {
            val r = server.takeRequest(50, TimeUnit.MILLISECONDS) ?: break
            out += "${r.method} ${r.path?.substringBefore('?')}"
        }
        return out
    }

    // -- plan -------------------------------------------------------------------------------

    @Test
    fun `plan of a policy, a segment and a profile issues GETs only`() = runTest {
        mountEmptyTenant()
        val getPolicy = mount("GET", policy, 200, policyJson())
        val listSegments = mount("GET", segments, 200, page())
        val listProfiles = mount("GET", profiles, 200, page())

        val plan = client.management().manifest().plan(
            manifest(
                policy = NetworkPolicySpec(7200),
                profiles = listOf(NetworkProfileSpec("lab", 1800)),
            ),
        )

        assertEquals(1, getPolicy.calls())
        assertEquals(1, listSegments.calls())
        assertEquals(1, listProfiles.calls())
        assertTrue(unmatched().isEmpty(), "plan reached a route it should not have: ${unmatched()}")
        assertFalse(requestLog().any { it.startsWith("POST /api/v1/network") || it.startsWith("PUT") || it.startsWith("DELETE") })
        assertEquals(
            listOf(
                ManagementPlan.Target.NETWORK_POLICY to ManagementPlan.Change.UPDATE,
                ManagementPlan.Target.NETWORK_SEGMENT to ManagementPlan.Change.CREATE,
                ManagementPlan.Target.NETWORK_PROFILE to ManagementPlan.Change.CREATE,
            ),
            plan.actions.map { it.target to it.change },
            "the policy, then the segments, then the profiles",
        )
    }

    @Test
    fun `a manifest without a network section reads nothing of the namespace`() = runTest {
        mountEmptyTenant()
        client.management().manifest().plan(ManagementManifest())
        assertTrue(unmatched().isEmpty(), "a manifest with no network section must not read it: ${unmatched()}")
    }

    @Test
    fun `a segment the manifest does not state is neither planned nor deleted`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(), segmentJson(guestId, name = "guest", vlan = 30, rank = "2")))
        val plan = client.management().manifest().plan(manifest())
        assertEquals(listOf(ManagementPlan.Change.NO_CHANGE), plan.actions.map { it.change })
        val report = client.management().manifest().apply(manifest())
        assertEquals(ApplyReport.Status.UNCHANGED, report.steps.single().outcome.status)
        assertTrue(unmatched().isEmpty(), "no DELETE and no other write: ${unmatched()}")
    }

    // -- apply on an empty tenant ------------------------------------------------------------

    @Test
    fun `apply creates the segment and then the profile against the new segment and its version`() = runTest {
        mountEmptyTenant()
        mount("GET", policy, 200, policyJson())
        val listSegments = mountSequence(
            "GET", segments, 200, listOf(page(), page(segmentJson(newId, version = 1))),
        )
        val listProfiles = mountSequence(
            "GET", profiles, 200, listOf(page(), page(profileJson(newId, version = 1))),
        )
        val replacePolicy = mount("PUT", policy, 200, policyJson(7200, 1))
        val createSegment = mount("POST", segments, 201, segmentJson(newId, version = 1))
        val createProfile = mount("POST", profiles, 201, profileJson(newId, version = 1))
        val m = manifest(
            policy = NetworkPolicySpec(7200),
            profiles = listOf(NetworkProfileSpec("lab", 1800, filterId = JsonNullable.Value("a"))),
        )

        val report = client.management().manifest().apply(m)

        assertTrue(report.isComplete, report.failure?.outcome?.message ?: "")
        assertEquals(
            listOf(ApplyReport.Status.UPDATED, ApplyReport.Status.CREATED, ApplyReport.Status.CREATED),
            report.steps.map { it.outcome.status },
        )
        val writes = requestLog().filter { it.startsWith("PUT") || it.startsWith("POST /api/v1/network") }
        assertEquals(listOf("PUT $policy", "POST $segments", "POST $profiles"), writes, "policy, segment, profile")

        assertEquals(JsonPrimitive(3600 * 2), replacePolicy.last().json()["session_timeout_max_secs"])
        assertEquals(JsonPrimitive(0), replacePolicy.last().json()["version"], "the version plan read")
        assertEquals(JsonPrimitive("access"), createSegment.last().json()["kind"], "the wire spelling, never zones")
        // The profile carries the NEW segment's id and the version of the CREATE response.
        val body = createProfile.last().json()
        assertEquals(JsonPrimitive(newId.toString()), body["segment_id"])
        assertEquals(JsonPrimitive(1), body["segment_version"])
        assertEquals(listOf("filter_id", "session_timeout_secs"), body["profile"]!!.jsonObject.keys.sorted())

        // Idempotence (§27.6 rule 6): plan afterwards is all NoChange.
        mount("GET", policy, 200, policyJson(7200, 1))
        val again = client.management().manifest().plan(m)
        assertTrue(again.isConverged, again.actions.toString())
        assertEquals(2, listSegments.calls())
        assertEquals(2, listProfiles.calls())
    }

    // -- updates -----------------------------------------------------------------------------

    @Test
    fun `a segment Update sends the full body from the read with no kind, site or name`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(vlan = 10, version = 7, rank = "2", enabled = false)))
        val replace = mount("PUT", "$segments/$labId", 200, segmentJson(version = 8))

        // Only vlan_id is stated (and a filter set equal to the read's): the rest is carried.
        val report = client.management().manifest().apply(
            manifest(segments = listOf(lab(vlan = 20, filters = null, rank = JsonNullable.Absent))),
        )

        assertTrue(report.isComplete)
        assertEquals(listOf("enabled", "filter_ids", "rank", "version", "vlan_id"), replace.last().keys())
        val body = replace.last().json()
        assertEquals(JsonPrimitive(7), body["version"], "the version plan read, exactly")
        assertEquals(JsonPrimitive(20), body["vlan_id"], "the stated member replaces the read's")
        assertEquals(JsonPrimitive(false), body["enabled"], "an unstated member is carried from the read")
        assertEquals(JsonPrimitive(2), body["rank"], "an unstated member is carried from the read")
        assertEquals(JsonArray(listOf(JsonPrimitive("a"), JsonPrimitive("b"))), body["filter_ids"])
    }

    @Test
    fun `a stated null leaves the key out of the body`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(rank = "2")))
        mount("GET", profiles, 200, page(profileJson(idle = "600", filter = "\"a\"")))
        val replaceSegment = mount("PUT", "$segments/$labId", 200, segmentJson(version = 8))
        val replaceProfile = mount("PUT", "$profiles/$labId", 200, profileJson())

        val report = client.management().manifest().apply(
            manifest(
                segments = listOf(lab(rank = JsonNullable.Null)),
                profiles = listOf(NetworkProfileSpec("lab", 1800, idleTimeoutSecs = JsonNullable.Null)),
            ),
        )

        assertTrue(report.isComplete, report.failure?.outcome?.message ?: "")
        assertFalse("rank" in replaceSegment.last().json(), "a segment's stated null rank is left out")
        val profile = replaceProfile.last().json()["profile"]!!.jsonObject
        assertFalse("idle_timeout_secs" in profile, "a stated null idle_timeout_secs is left out")
        assertEquals(JsonPrimitive("a"), profile["filter_id"], "an unstated member is carried from the read")
        assertEquals(JsonPrimitive("axiam-radius-reply/1"), profile["dictionary"])
    }

    @Test
    fun `a segment and its profile changed in one apply use the segment write's version`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(vlan = 10, version = 7)))
        mount("GET", profiles, 200, page(profileJson(timeout = 900, version = 4)))
        val replaceSegment = mount("PUT", "$segments/$labId", 200, segmentJson(version = 8))
        val replaceProfile = mount("PUT", "$profiles/$labId", 200, profileJson())

        val report = client.management().manifest().apply(
            manifest(
                segments = listOf(lab(vlan = 20)),
                profiles = listOf(NetworkProfileSpec("lab", 1800)),
            ),
        )

        assertTrue(report.isComplete, report.failure?.outcome?.message ?: "")
        val writes = requestLog().filter { it.startsWith("PUT") }
        assertEquals(listOf("PUT $segments/$labId", "PUT $profiles/$labId"), writes)
        assertEquals(JsonPrimitive(7), replaceSegment.last().json()["version"])
        val body = replaceProfile.last().json()
        assertEquals(JsonPrimitive(8), body["segment_version"], "the replace_segment response's version, not the read's 7")
        assertEquals(JsonPrimitive(4), body["version"], "the profile's own version, as read")
        assertEquals(listOf("profile", "segment_version", "version"), replaceProfile.last().keys())
    }

    // -- failures ----------------------------------------------------------------------------

    @Test
    fun `a 409 stale_version stops the apply after one request and exposes the reason code`() = runTest {
        mountEmptyTenant()
        mount("GET", policy, 200, policyJson())
        mount("GET", segments, 200, page())
        val replacePolicy = mount(
            "PUT", policy, 409, """{"error":"conflict","message":"changed","reason_code":"stale_version"}""",
        )
        val createSegment = mount("POST", segments, 201, segmentJson(newId, version = 1))

        val report = client.management().manifest().apply(manifest(policy = NetworkPolicySpec(7200)))

        assertEquals(1, replacePolicy.calls(), "exactly one request: no retry, no re-read")
        assertEquals(0, createSegment.calls(), "later actions are not attempted")
        assertEquals(
            listOf(ApplyReport.Status.FAILED, ApplyReport.Status.NOT_ATTEMPTED),
            report.steps.map { it.outcome.status },
        )
        assertEquals("stale_version", report.failure!!.outcome.reasonCode)
    }

    @Test
    fun `a 409 already_exists duplicate_vlan on a segment create does the same`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page())
        mount("GET", profiles, 200, page())
        val create = mount(
            "POST", segments, 409, """{"error":"already_exists","message":"vlan","reason_code":"duplicate_vlan"}""",
        )
        val createProfile = mount("POST", profiles, 201, profileJson(newId, version = 1))

        val report = client.management().manifest().apply(
            manifest(profiles = listOf(NetworkProfileSpec("lab", 1800))),
        )

        assertEquals(1, create.calls())
        assertEquals(0, createProfile.calls())
        assertEquals("duplicate_vlan", report.failure!!.outcome.reasonCode)
        assertEquals(ApplyReport.Status.NOT_ATTEMPTED, report.steps.last().outcome.status)
    }

    @Test
    fun `a clamped profile is judged on the read and a stated value above the cap is the servers refusal`() = runTest {
        val guest = segmentJson(guestId, name = "guest", vlan = 30, rank = "2")
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(), guest))
        // Both profiles read as the CAP (1800), clamped.
        mount(
            "GET", profiles, 200,
            page(profileJson(labId, timeout = 1800, clamped = true), profileJson(guestId, timeout = 1800, clamped = true)),
        )
        val replaceLab = mount(
            "PUT", "$profiles/$labId", 403,
            """{"error":"authorization_denied","message":"session_timeout_secs is above the tenant's cap of 1800"}""",
        )
        val replaceGuest = mount("PUT", "$profiles/$guestId", 200, profileJson(guestId))
        val guestSegment = NetworkSegmentSpec(
            "guest", "default", NetworkSegmentKind.ACCESS, "guest", 30, JsonNullable.Value(2), listOf("a", "b"),
        )

        // The cap itself is NoChange: the stored value is neither restored nor rewritten.
        val converged = client.management().manifest().plan(
            manifest(
                segments = listOf(lab(), guestSegment),
                profiles = listOf(NetworkProfileSpec("lab", 1800), NetworkProfileSpec("guest", 1800)),
            ),
        )
        assertTrue(converged.isConverged, converged.actions.toString())

        // A value above the cap differs from the read: plan shows an Update.
        val m = manifest(
            segments = listOf(lab(), guestSegment),
            profiles = listOf(NetworkProfileSpec("lab", 7200), NetworkProfileSpec("guest", 900)),
        )
        val plan = client.management().manifest().plan(m)
        assertEquals(
            listOf(ManagementPlan.Change.NO_CHANGE, ManagementPlan.Change.NO_CHANGE, ManagementPlan.Change.UPDATE, ManagementPlan.Change.UPDATE),
            plan.actions.map { it.change },
        )

        val report = client.management().manifest().apply(m)

        assertEquals(1, replaceLab.calls(), "exactly one replace_profile, no retry")
        assertEquals(0, replaceGuest.calls(), "later actions are not attempted")
        val failed = report.failure!!.outcome
        assertEquals(ApplyReport.Status.FAILED, failed.status)
        assertTrue(failed.message!!.contains("session_timeout_secs is above the tenant's cap of 1800"), failed.message)
        assertNull(failed.reasonCode)
        assertEquals(ApplyReport.Status.NOT_ATTEMPTED, report.steps.last().outcome.status)
        assertEquals(JsonPrimitive(7200), replaceLab.last().json()["profile"]!!.jsonObject["session_timeout_secs"], "never lowered to the cap")
    }

    // -- refusals before any request -----------------------------------------------------------

    private fun refused(m: ManagementManifest, withApply: Boolean = false): NetworkError {
        val e = assertThrows(NetworkError::class.java) {
            runBlocking {
                if (withApply) client.management().manifest().apply(m) else client.management().manifest().plan(m)
            }
        }
        assertEquals(0, totalCalls(), "the refusal comes before the first request")
        return e
    }

    @Test
    fun `two segments with one site, kind and name are refused with zero wire calls`() = runTest {
        val twin = lab().copy(key = "lab-2")
        val e = refused(manifest(segments = listOf(lab(), twin)))
        assertTrue(e.message!!.contains("default/access/lab"), e.message)
    }

    @Test
    fun `a profile whose segment names no segment spec is refused with zero wire calls`() = runTest {
        val e = refused(manifest(profiles = listOf(NetworkProfileSpec("nowhere", 1800))))
        assertTrue(e.message!!.contains("which no network segment declares"), e.message)
    }

    @Test
    fun `two profiles for one segment are refused with zero wire calls`() = runTest {
        refused(manifest(profiles = listOf(NetworkProfileSpec("lab", 1800), NetworkProfileSpec("lab", 900))))
    }

    @Test
    fun `a segment listing one Filter-Id twice is refused at plan and at apply`() = runTest {
        val dup = manifest(segments = listOf(lab(filters = listOf("a", "b", "a"))))
        val e = refused(dup)
        assertTrue(e.message!!.contains("Filter-Id 'a' more than once"), e.message)
        refused(dup, withApply = true)
    }

    @Test
    fun `the builder refuses a profile for an undeclared segment and a second policy`() {
        val e = assertThrows(NetworkError::class.java) {
            ManagementManifest.builder()
                .networkPolicy(600)
                .networkPolicy(900)
                .networkProfile(NetworkProfileSpec("nowhere", 1800))
                .build()
        }
        assertTrue(e.message!!.contains("more than once"), e.message)
        assertTrue(e.message!!.contains("nowhere"), e.message)
    }

    // -- the wire spelling and the set ---------------------------------------------------------

    @Test
    fun `kind access is NoChange against a read that says access and no zones value exists`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(kind = "access")))
        val plan = client.management().manifest().plan(manifest())
        assertEquals(ManagementPlan.Change.NO_CHANGE, plan.actions.single().change)
        assertTrue(plan.actions.single().summary.contains("default/access/lab"), plan.actions.single().summary)
        assertEquals(listOf("access", "quarantine"), NetworkSegmentKind.entries.filter { it != NetworkSegmentKind.UNKNOWN }.map { it.wire })
        assertFalse(NetworkSegmentKind.entries.any { it.wire == "zones" })
    }

    @Test
    fun `a reordered filter_ids is NoChange and a write sends them in the stated order`() = runTest {
        mountEmptyTenant()
        mount("GET", segments, 200, page(segmentJson(filters = """"b","a"""")))
        val replace = mount("PUT", "$segments/$labId", 200, segmentJson(version = 8))
        val create = mount("POST", segments, 201, segmentJson(newId, version = 1))

        // Same names, another order: NoChange, and apply makes no write for it.
        val same = manifest(segments = listOf(lab(filters = listOf("a", "b"))))
        assertTrue(client.management().manifest().plan(same).isConverged)
        val report = client.management().manifest().apply(same)
        assertEquals(ApplyReport.Status.UNCHANGED, report.steps.single().outcome.status)
        assertEquals(0, replace.calls())

        // Another member drifts: the Update carries filter_ids in the manifest's order.
        val drifted = manifest(segments = listOf(lab(vlan = 21, filters = listOf("c", "a", "b"))))
        client.management().manifest().apply(drifted)
        assertEquals(
            JsonArray(listOf(JsonPrimitive("c"), JsonPrimitive("a"), JsonPrimitive("b"))),
            replace.last().json()["filter_ids"].let { it!!.jsonArray }.let { JsonArray(it) },
        )

        // A Create does the same: a segment the read does not hold.
        val fresh = lab(filters = listOf("z", "y")).copy(key = "fresh", name = "fresh")
        client.management().manifest().apply(manifest(segments = listOf(fresh)))
        assertEquals(
            JsonArray(listOf(JsonPrimitive("z"), JsonPrimitive("y"))),
            create.last().json()["filter_ids"],
        )
    }
}
