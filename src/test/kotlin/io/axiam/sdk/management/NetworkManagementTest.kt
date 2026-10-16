package io.axiam.sdk.management

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.CreateNetworkReplyProfileRequest
import io.axiam.sdk.management.models.CreateNetworkSegmentRequest
import io.axiam.sdk.management.models.NetworkReplyProfile
import io.axiam.sdk.management.models.NetworkReplyProfileInput
import io.axiam.sdk.management.models.NetworkSegmentKind
import io.axiam.sdk.management.models.NetworkSegmentResponse
import io.axiam.sdk.management.models.RadiusServiceType
import io.axiam.sdk.management.models.RadiusTerminationAction
import io.axiam.sdk.management.models.ReplaceNetworkPolicyRequest
import io.axiam.sdk.management.models.ReplaceNetworkReplyProfileRequest
import io.axiam.sdk.management.models.ReplaceNetworkSegmentRequest
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID
import kotlin.reflect.full.primaryConstructor

/**
 * CONTRACT.md §36.8 — the five required tests of the `network` namespace (contract 1.62),
 * against a mocked HTTP server.
 */
class NetworkManagementTest : ManagementTestBase() {

    private val segments = "/api/v1/network/segments"
    private val profiles = "/api/v1/network/profiles"
    private val policy = "/api/v1/network/policy"
    private val segmentId: UUID = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    private fun segmentJson(
        id: UUID = segmentId,
        kind: String = "access",
        version: Int = 3,
        rank: String = "1",
    ): String =
        """{"id":"$id","tenant_id":"$TENANT_ID","path":"/network/zones/default/lab","name":"lab",
            "site_key":"default","kind":"$kind","vlan_id":20,"filter_ids":["lab-in"],"rank":$rank,
            "enabled":true,"version":$version,"created_by":"$EXAMPLE_ID","updated_by":"$EXAMPLE_ID",
            "created_at":"2026-10-16T00:00:00Z","updated_at":"2026-10-16T00:00:00Z"}"""

    private fun profileJson(
        terminationAction: String = "radius_request",
        serviceType: String = "null",
        clamped: Boolean = false,
        timeout: Int = 1800,
    ): String =
        """{"segment_id":"$segmentId","tenant_id":"$TENANT_ID","dictionary":"axiam-radius-reply/1",
            "session_timeout_secs":$timeout,"session_timeout_clamped":$clamped,
            "termination_action":"$terminationAction","idle_timeout_secs":null,"filter_id":"lab-in",
            "service_type":${if (serviceType == "null") "null" else "\"$serviceType\""},"version":4,
            "created_by":"$EXAMPLE_ID","updated_by":"$EXAMPLE_ID",
            "created_at":"2026-10-16T00:00:00Z","updated_at":"2026-10-16T00:00:00Z"}"""

    private val policyJson =
        """{"tenant_id":"$TENANT_ID","session_timeout_max_secs":3600,"version":0}"""

    private fun page(vararg items: String, total: Int = items.size, offset: Int = 0, limit: Int = 200): String =
        """{"items":[${items.joinToString(",")}],"total":$total,"offset":$offset,"limit":$limit}"""

    private fun replaceSegmentBody() = ReplaceNetworkSegmentRequest(
        enabled = true, filterIds = listOf("lab-in"), version = 3, vlanId = 20,
    )

    private fun profileInput() = NetworkReplyProfileInput(sessionTimeoutSecs = 1800)

    // -- 1. The surface ----------------------------------------------------------------------

    @Test
    fun `the twelve operations exist with the paths and methods of 36_1 and none reaches decide`() = runTest {
        val registry = Json.parseToJsonElement(java.io.File("management-registry.json").readText()).jsonObject
        val network = registry["namespaces"]!!.jsonObject["network"]!!.jsonObject["operations"]!!.jsonObject
        val shape = network.entries.associate { (name, op) ->
            name to (op.jsonObject["method"]!!.jsonPrimitive.content + " " + op.jsonObject["path"]!!.jsonPrimitive.content)
        }
        assertEquals(
            mapOf(
                "list_segments" to "GET $segments",
                "create_segment" to "POST $segments",
                "get_segment" to "GET $segments/{id}",
                "replace_segment" to "PUT $segments/{id}",
                "delete_segment" to "DELETE $segments/{id}",
                "list_profiles" to "GET $profiles",
                "create_profile" to "POST $profiles",
                "get_profile" to "GET $profiles/{segment_id}",
                "replace_profile" to "PUT $profiles/{segment_id}",
                "delete_profile" to "DELETE $profiles/{segment_id}",
                "get_policy" to "GET $policy",
                "replace_policy" to "PUT $policy",
            ),
            shape,
        )

        // The handle carries exactly those twelve (plus the two auto-pagers), and nothing
        // whose name or path could reach the placement decision.
        val declared = NetworkApi::class.java.declaredMethods
            .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) && !it.isSynthetic && '$' !in it.name }
            .map { it.name }.toSet()
        assertEquals(
            setOf(
                "listSegments", "listSegmentsAll", "createSegment", "getSegment", "replaceSegment", "deleteSegment",
                "listProfiles", "listProfilesAll", "createProfile", "getProfile", "replaceProfile", "deleteProfile",
                "getPolicy", "replacePolicy",
            ),
            declared,
        )
        assertTrue(registry["excluded_operations"]!!.jsonObject.containsKey("POST /api/v1/network/decide"))
        assertTrue(network.values.none { it.jsonObject["path"]!!.jsonPrimitive.content.endsWith("/decide") })

        // Each reaches its route (the generated suite covers the paths; this covers the handle).
        mount("GET", segments, 200, page(segmentJson()))
        mount("GET", "$segments/$segmentId", 200, segmentJson())
        mount("GET", profiles, 200, page(profileJson()))
        mount("GET", "$profiles/$segmentId", 200, profileJson())
        mount("GET", policy, 200, policyJson)
        assertEquals(1, client.network.listSegments(null, null).items.size)
        assertEquals(NetworkSegmentKind.ACCESS, client.network.getSegment(segmentId).kind)
        assertEquals(1, client.network.listProfiles(null).items.size)
        assertEquals(1800, client.network.getProfile(segmentId).sessionTimeoutSecs)
        assertEquals(0L, client.network.getPolicy().version)
    }

    // -- 2. Versions ---------------------------------------------------------------------------

    @Test
    fun `every write sends the version it was given, exactly`() = runTest {
        val replaceSegment = mount("PUT", "$segments/$segmentId", 200, segmentJson(version = 4))
        val deleteSegment = mount("DELETE", "$segments/$segmentId", 204, "")
        val createProfile = mount("POST", profiles, 201, profileJson())
        val replaceProfile = mount("PUT", "$profiles/$segmentId", 200, profileJson())
        val deleteProfile = mount("DELETE", "$profiles/$segmentId", 204, "")
        val replacePolicy = mount("PUT", policy, 200, policyJson)

        client.network.replaceSegment(segmentId, replaceSegmentBody())
        assertEquals(JsonPrimitive(3), replaceSegment.last().json()["version"])

        client.network.deleteSegment(segmentId, 3L)
        assertEquals("3", deleteSegment.last().query["version"])
        client.network.deleteProfile(segmentId, 4L)
        assertEquals("4", deleteProfile.last().query["version"])

        client.network.createProfile(
            CreateNetworkReplyProfileRequest(profile = profileInput(), segmentId = segmentId, segmentVersion = 5),
        )
        assertEquals(JsonPrimitive(5), createProfile.last().json()["segment_version"])
        assertEquals(JsonPrimitive(segmentId.toString()), createProfile.last().json()["segment_id"])

        client.network.replaceProfile(
            segmentId, ReplaceNetworkReplyProfileRequest(profile = profileInput(), segmentVersion = 6, version = 4),
        )
        assertEquals(JsonPrimitive(4), replaceProfile.last().json()["version"])
        assertEquals(JsonPrimitive(6), replaceProfile.last().json()["segment_version"])

        client.network.replacePolicy(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs = 7200, version = 0))
        assertEquals(JsonPrimitive(0), replacePolicy.last().json()["version"])
        assertEquals(JsonPrimitive(7200), replacePolicy.last().json()["session_timeout_max_secs"])
    }

    @Test
    fun `a delete cannot be called without its version`() {
        // §36.8 test 2: the version is a required, non-null argument, not an optional filter.
        for (name in listOf("deleteSegment", "deleteProfile")) {
            val method = NetworkApi::class.java.declaredMethods.single { it.name == name }
            assertEquals(java.util.UUID::class.java, method.parameterTypes[0])
            assertEquals(
                java.lang.Long.TYPE, method.parameterTypes[1],
                "$name takes `version` as a primitive long: it cannot be null or omitted",
            )
        }
    }

    @Test
    fun `a 409 is a ConflictError after one request and exposes its reason code`() = runTest {
        val stale = """{"error":"conflict","message":"the segment changed","reason_code":"stale_version"}"""
        val dup = """{"error":"already_exists","message":"vlan taken","reason_code":"duplicate_vlan"}"""
        val routes = listOf(
            mount("PUT", "$segments/$segmentId", 409, stale),
            mount("DELETE", "$segments/$segmentId", 409, stale),
            mount("POST", profiles, 409, stale),
            mount("PUT", "$profiles/$segmentId", 409, stale),
            mount("DELETE", "$profiles/$segmentId", 409, stale),
            mount("PUT", policy, 409, stale),
        )
        val calls: List<suspend () -> Unit> = listOf(
            { client.network.replaceSegment(segmentId, replaceSegmentBody()) },
            { client.network.deleteSegment(segmentId, 3) },
            {
                client.network.createProfile(
                    CreateNetworkReplyProfileRequest(profile = profileInput(), segmentId = segmentId, segmentVersion = 3),
                )
            },
            {
                client.network.replaceProfile(
                    segmentId, ReplaceNetworkReplyProfileRequest(profile = profileInput(), segmentVersion = 3, version = 4),
                )
            },
            { client.network.deleteProfile(segmentId, 4) },
            { client.network.replacePolicy(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs = 600, version = 0)) },
        )
        for ((route, call) in routes.zip(calls)) {
            val e = assertThrows<ConflictError> { runBlocking { call() } }
            assertEquals("stale_version", e.reasonCode)
            assertEquals(1, route.calls(), "a 409 is never retried")
            assertTrue(AuthzError::class.java.isInstance(e), "still catchable as AuthzError (§27.4 rule 7)")
        }

        val create = mount("POST", segments, 409, dup)
        val e = assertThrows<ConflictError> {
            runBlocking {
                client.network.createSegment(
                    CreateNetworkSegmentRequest(
                        kind = NetworkSegmentKind.ACCESS, name = "lab", siteKey = "default", vlanId = 20, rank = 1,
                    ),
                )
            }
        }
        assertEquals("duplicate_vlan", e.reasonCode)
        assertEquals(1, create.calls())
    }

    @Test
    fun `an unknown reason code is surfaced verbatim and an absent one is null`() = runTest {
        mount("PUT", policy, 409, """{"error":"conflict","message":"x","reason_code":"a_code_from_the_future"}""")
        val e = assertThrows<ConflictError> {
            runBlocking { client.network.replacePolicy(ReplaceNetworkPolicyRequest(300, 0)) }
        }
        assertEquals("a_code_from_the_future", e.reasonCode)

        mount("PUT", "$segments/$segmentId", 409, """{"error":"conflict","message":"older server"}""")
        val older = assertThrows<ConflictError> { runBlocking { client.network.replaceSegment(segmentId, replaceSegmentBody()) } }
        assertNull(older.reasonCode, "a server predating the member omits it")

        mount("PUT", "$profiles/$segmentId", 409, "not json")
        val garbage = assertThrows<ConflictError> {
            runBlocking {
                client.network.replaceProfile(
                    segmentId, ReplaceNetworkReplyProfileRequest(profile = profileInput(), segmentVersion = 1, version = 1),
                )
            }
        }
        assertNull(garbage.reasonCode)
    }

    // -- 3. Closed bodies --------------------------------------------------------------------

    private fun encode(body: String): JsonObject = Json.parseToJsonElement(body) as JsonObject

    @Test
    fun `request bodies carry exactly the keys 36_2 names for the members set`() = runTest {
        val create = mount("POST", segments, 201, segmentJson())
        client.network.createSegment(
            CreateNetworkSegmentRequest(
                kind = NetworkSegmentKind.QUARANTINE, name = "q", siteKey = "default", vlanId = 99,
            ),
        )
        assertEquals(listOf("kind", "name", "site_key", "vlan_id"), create.last().keys(), "unset rank, filter_ids and enabled are absent")
        assertEquals(JsonPrimitive("quarantine"), create.last().json()["kind"])

        client.network.createSegment(
            CreateNetworkSegmentRequest(
                kind = NetworkSegmentKind.ACCESS, name = "lab", siteKey = "default", vlanId = 20,
                rank = 1, filterIds = listOf("b", "a"), enabled = false,
            ),
        )
        assertEquals(listOf("enabled", "filter_ids", "kind", "name", "rank", "site_key", "vlan_id"), create.last().keys())
        assertEquals(JsonArray(listOf(JsonPrimitive("b"), JsonPrimitive("a"))), create.last().json()["filter_ids"])

        val replace = mount("PUT", "$segments/$segmentId", 200, segmentJson())
        client.network.replaceSegment(segmentId, replaceSegmentBody())
        assertEquals(
            listOf("enabled", "filter_ids", "version", "vlan_id"), replace.last().keys(),
            "the replace has no kind, site_key or name, and an unset rank is absent",
        )

        val createProfile = mount("POST", profiles, 201, profileJson())
        client.network.createProfile(
            CreateNetworkReplyProfileRequest(profile = profileInput(), segmentId = segmentId, segmentVersion = 2),
        )
        assertEquals(listOf("profile", "segment_id", "segment_version"), createProfile.last().keys())
        val profile = createProfile.last().json()["profile"]!!.jsonObject
        assertEquals(listOf("session_timeout_secs"), profile.keys.sorted(), "an unset idle_timeout_secs, filter_id, service_type is absent, not null")
        assertFalse(profile.keys.any { "vlan" in it }, "there is no VLAN member on a profile")

        val policyRoute = mount("PUT", policy, 200, policyJson)
        client.network.replacePolicy(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs = 900, version = 2))
        assertEquals(listOf("session_timeout_max_secs", "version"), policyRoute.last().keys())
    }

    @Test
    fun `the replace types cannot be built without their required members`() {
        // Kotlin's compile-time check: a required member is a constructor parameter with no
        // default, so leaving it out does not compile. Asserted over the primary constructors.
        fun required(type: kotlin.reflect.KClass<*>): Set<String> =
            type.primaryConstructor!!.parameters.filter { !it.isOptional }.map { it.name!! }.toSet()
        assertEquals(setOf("version", "vlanId", "filterIds", "enabled"), required(ReplaceNetworkSegmentRequest::class))
        assertEquals(setOf("version", "segmentVersion", "profile"), required(ReplaceNetworkReplyProfileRequest::class))
        assertEquals(setOf("sessionTimeoutMaxSecs", "version"), required(ReplaceNetworkPolicyRequest::class))
        assertEquals(setOf("segmentId", "segmentVersion", "profile"), required(CreateNetworkReplyProfileRequest::class))
        assertEquals(setOf("sessionTimeoutSecs"), required(NetworkReplyProfileInput::class))
    }

    // -- 4. Open decoding and pagination ---------------------------------------------------

    @Test
    fun `an unknown enumeration value decodes and is never sent back`() {
        val segment = ManagementTransport.READER.decodeFromString(
            NetworkSegmentResponse.serializer(), segmentJson(kind = "a-future-kind"),
        )
        assertEquals(NetworkSegmentKind.UNKNOWN, segment.kind)

        val profile = ManagementTransport.READER.decodeFromString(
            NetworkReplyProfile.serializer(),
            profileJson(terminationAction = "a-future-action", serviceType = "nas_prompt_user", clamped = true, timeout = 600),
        )
        assertEquals(RadiusTerminationAction.UNKNOWN, profile.terminationAction)
        assertEquals(RadiusServiceType.UNKNOWN, profile.serviceType)
        assertTrue(profile.sessionTimeoutClamped)
        assertEquals(600, profile.sessionTimeoutSecs)

        // Never re-sent: replacing the unknown is refused locally, before any request.
        assertThrows<ValidationError> {
            runBlocking {
                client.network.createProfile(
                    CreateNetworkReplyProfileRequest(
                        profile = NetworkReplyProfileInput(
                            sessionTimeoutSecs = 600, terminationAction = profile.terminationAction,
                        ),
                        segmentId = segmentId, segmentVersion = 1,
                    ),
                )
            }
        }
    }

    @Test
    fun `both lists return a page with its total and the auto-pager carries search and site`() = runTest {
        val firstPage = page(segmentJson(), total = 3, offset = 0, limit = 2).replace(
            "\"items\":[", "\"items\":[" + segmentJson(UUID.randomUUID()) + ",",
        )
        val secondPage = page(segmentJson(UUID.randomUUID()), total = 3, offset = 2, limit = 2)
        // The single call below takes the first body; the walk then takes the first and the second.
        val first = mountSequence("GET", segments, 200, listOf(firstPage, firstPage, secondPage))
        val page = client.network.listSegments("default", PageRequest.of(2))
        assertEquals(3, page.total, "total is the whole set, not this page")
        assertEquals(2, page.items.size)

        val all = client.network.listSegmentsAll("default", PageRequest.matching(2, "lab"))
        assertEquals(3, all.size)
        val walk = first.requests.drop(1)
        assertEquals(2, walk.size, "the walk issued exactly two requests")
        assertEquals(listOf("0", "2"), walk.map { it.query["offset"] })
        assertTrue(walk.all { it.query["search"] == "lab" }, "search on every request of the walk")
        assertTrue(walk.all { it.query["site"] == "default" }, "site on every request of the walk")

        val profilePage = mount("GET", profiles, 200, page(profileJson(), total = 1))
        assertEquals(1, client.network.listProfiles(PageRequest.matching(10, "lab-in")).total)
        assertEquals("lab-in", profilePage.last().query["search"])
    }

    // -- 5. Errors ----------------------------------------------------------------------------

    @Test
    fun `statuses map per section 27_4 and 36_4`() = runTest {
        mount("POST", segments, 403, """{"error":"authorization_denied","message":"no","action":"network:grant","resource_id":"$segmentId"}""")
        val denied = assertThrows<AuthzError> {
            runBlocking {
                client.network.createSegment(
                    CreateNetworkSegmentRequest(kind = NetworkSegmentKind.ACCESS, name = "x", siteKey = "default", vlanId = 5, rank = 1),
                )
            }
        }
        assertEquals("network:grant", denied.action)
        assertEquals(segmentId.toString(), denied.resourceId)
        assertFalse(denied is ConflictError || denied is NotFoundError)

        mount("PUT", policy, 400, """{"error":"validation_error","message":"session_timeout_max_secs: must be at least 300"}""")
        val invalid = assertThrows<ValidationError> {
            runBlocking { client.network.replacePolicy(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs = 5, version = 0)) }
        }
        assertTrue(invalid.message.orEmpty().contains("at least 300"))

        mount("GET", "$profiles/$segmentId", 404, """{"error":"not_found","message":"no profile"}""")
        assertThrows<NotFoundError> { runBlocking { client.network.getProfile(segmentId) } }

        // 401: the service-account token's answer, which no refresh can cure.
        mount("GET", policy, 401, """{"error":"unauthorized","message":"human only"}""")
        assertThrows<AuthError> { runBlocking { client.network.getPolicy() } }
    }

    @Test
    fun `a 429 and a 503 on each write are a NetworkError after exactly one request`() = runTest {
        for (status in listOf(429, 503)) {
            val routes = listOf(
                mount("POST", segments, status, """{"error":"unavailable","message":"later"}"""),
                mount("PUT", "$segments/$segmentId", status, """{"error":"unavailable","message":"later"}"""),
                mount("DELETE", "$segments/$segmentId", status, """{"error":"unavailable","message":"later"}"""),
                mount("POST", profiles, status, """{"error":"unavailable","message":"later"}"""),
                mount("PUT", "$profiles/$segmentId", status, """{"error":"unavailable","message":"later"}"""),
                mount("DELETE", "$profiles/$segmentId", status, """{"error":"unavailable","message":"later"}"""),
                mount("PUT", policy, status, """{"error":"unavailable","message":"later"}"""),
            )
            val calls: List<suspend () -> Unit> = listOf(
                {
                    client.network.createSegment(
                        CreateNetworkSegmentRequest(kind = NetworkSegmentKind.ACCESS, name = "x", siteKey = "d", vlanId = 5, rank = 1),
                    )
                },
                { client.network.replaceSegment(segmentId, replaceSegmentBody()) },
                { client.network.deleteSegment(segmentId, 3) },
                {
                    client.network.createProfile(
                        CreateNetworkReplyProfileRequest(profile = profileInput(), segmentId = segmentId, segmentVersion = 3),
                    )
                },
                {
                    client.network.replaceProfile(
                        segmentId, ReplaceNetworkReplyProfileRequest(profile = profileInput(), segmentVersion = 3, version = 4),
                    )
                },
                { client.network.deleteProfile(segmentId, 4) },
                { client.network.replacePolicy(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs = 600, version = 0)) },
            )
            for ((route, call) in routes.zip(calls)) {
                assertThrows<NetworkError> { runBlocking { call() } }
                assertEquals(1, route.calls(), "status $status: a write is never retried")
            }
        }
        assertNotNull(client.network)
    }
}
