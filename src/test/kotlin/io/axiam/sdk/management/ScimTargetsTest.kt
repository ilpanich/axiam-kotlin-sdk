package io.axiam.sdk.management

import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.DeprovisionPolicy
import io.axiam.sdk.management.models.ScimTargetAuth
import io.axiam.sdk.management.models.ScimTargetAuthBearer
import io.axiam.sdk.management.models.ScimTargetAuthOauth2ClientCredentials
import io.axiam.sdk.management.models.ScimTargetInput
import io.axiam.sdk.management.models.ScimTargetResponse
import io.axiam.sdk.management.models.ScimTargetScope
import io.axiam.sdk.management.models.ScimTargetScopeAllUsers
import io.axiam.sdk.management.models.ScimTargetScopeGroups
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/**
 * The `scim_targets` management namespace — CONTRACT.md §31.8's six required
 * tests. The credential is generated at run time.
 */
class ScimTargetsTest : ManagementTestBase() {

    private val targets = "/api/v1/scim-targets"

    private val healthy = """{"last_success_at":null,"last_failure_at":null,"last_failure_reason":null,
        "consecutive_failures":0,"dead_lettered_total":0,"last_reconciled_at":null}"""

    private fun targetBody(
        extra: String = "",
        auth: String = """{"type":"bearer"}""",
        deprovision: String = "deactivate",
        userNameFrom: String = "username",
        state: String = healthy,
    ): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","name":"Downstream",
            "base_url":"https://idp.example/scim/v2","enabled":true,
            "auth":$auth,"scope":{"type":"all_users"},
            "push_groups":false,"user_name_from":"$userNameFrom","deprovision":"$deprovision",
            "created_at":"2026-10-05T00:00:00Z","updated_at":"2026-10-05T00:00:00Z",
            "state":$state$extra}"""

    private fun input(credential: String?) = ScimTargetInput(
        auth = ScimTargetAuthBearer(),
        baseUrl = "https://idp.example/scim/v2",
        credential = credential?.let { Sensitive.of(it) },
        name = "Downstream",
        scope = ScimTargetScopeAllUsers(),
    )

    private fun wire(value: Any): String = when (value) {
        is ScimTargetAuth -> ManagementSupport.encodeBody("t", ScimTargetAuth.serializer(), value)
        is ScimTargetScope -> ManagementSupport.encodeBody("t", ScimTargetScope.serializer(), value)
        else -> error("unsupported")
    }

    // -- 1. Redaction --------------------------------------------------------------

    @Test
    fun `the credential is on the wire and in no rendering`() = runTest {
        val credential = Redaction.secret("scim-")
        val body = input(credential)
        Redaction.assertNoFragment(body.toString(), credential, "toString")
        Redaction.assertNoFragment(
            ManagementTransport.READER.encodeToString(ScimTargetInput.serializer(), body),
            credential,
            "serialized for logs",
        )
        val route = mount("POST", targets, 400, """{"error":"validation_error","message":"base_url: refused"}""")
        val e = assertThrows<ValidationError> { runBlocking { client.scimTargets.create(body) } }
        Redaction.assertNoFragment(e.toString(), credential, "error")
        assertEquals(JsonPrimitive(credential), route.last().json()["credential"])
    }

    // -- 2. No credential on the response ----------------------------------------------

    @Test
    fun `a credential in a response is dropped`() = runTest {
        val leaked = Redaction.secret("scim-")
        val id = UUID.randomUUID()
        mount("GET", "$targets/$id", 200, targetBody(""","credential":"$leaked","credential_set":true"""))
        val t = client.scimTargets.get(id)
        Redaction.assertNoFragment(t.toString(), leaked, "toString")
        Redaction.assertNoFragment(
            ManagementTransport.READER.encodeToString(ScimTargetResponse.serializer(), t),
            leaked,
            "serialized",
        )
        assertFalse(ScimTargetResponse::class.members.any { it.name == "credential" })
        assertEquals("Downstream", t.name)
    }

    // -- 3. Replacement and the omitted credential ----------------------------------------

    @Test
    fun `update without a credential sends no key and the variants keep their shape`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$targets/$id", 200, targetBody())
        val credential = Redaction.secret("scim-")
        client.scimTargets.update(id, input(null))
        client.scimTargets.update(id, input(credential))
        assertFalse("credential" in route.requests[0].json(), "no credential key")
        assertEquals(JsonPrimitive(credential), route.requests[1].json()["credential"])

        val shapes = listOf(
            wire(ScimTargetAuthBearer()) to """{"type":"bearer"}""",
            wire(ScimTargetAuthOauth2ClientCredentials("axiam", "scim", "https://idp.example/token")) to
                """{"type":"oauth2_client_credentials","client_id":"axiam","scope":"scim","token_url":"https://idp.example/token"}""",
            wire(ScimTargetScopeAllUsers()) to """{"type":"all_users"}""",
            wire(ScimTargetScopeGroups(listOf(UUID(0, 0)))) to
                """{"type":"groups","group_ids":["00000000-0000-0000-0000-000000000000"]}""",
        )
        for ((got, want) in shapes) {
            assertEquals(Json.parseToJsonElement(want), Json.parseToJsonElement(got))
        }
    }

    // -- 4. Open decoding and pagination ----------------------------------------------------

    @Test
    fun `unknown values decode and the pager carries search`() = runTest {
        val odd = targetBody(
            auth = """{"type":"mtls","certificate_id":"${UUID.randomUUID()}"}""",
            deprovision = "archive",
            userNameFrom = "employee_number",
            state = "null",
        )
        val failing = targetBody(
            state = """{"last_success_at":null,"last_failure_at":"2026-10-05T01:00:00Z",
                "last_failure_reason":"a reason this SDK has never seen","consecutive_failures":3,
                "dead_lettered_total":1,"last_reconciled_at":null}""",
        )
        val page0 = """{"items":[$odd],"total":2,"offset":0,"limit":1}"""
        val page1 = """{"items":[$failing],"total":2,"offset":1,"limit":1}"""
        val route = mountSequence("GET", targets, 200, listOf(page0, page0, page1))

        val page = client.scimTargets.list(PageRequest.matching(1, "downstream"))
        assertEquals(2, page.total)
        val first = page.items[0]
        assertEquals(ScimTargetAuth.Unknown("mtls"), first.auth)
        assertEquals(DeprovisionPolicy.UNKNOWN, first.deprovision)
        assertNull(first.state)
        val all = client.scimTargets.listAll(PageRequest.matching(1, "downstream"))
        assertEquals("a reason this SDK has never seen", all[1].state?.lastFailureReason)
        for (request in route.requests) {
            assertEquals("downstream", request.query["search"])
        }
        // An unknown arm decodes but is never sent: encoding it fails locally.
        val refused = assertThrows<NetworkError> { wire(first.auth) }
        assertTrue(refused.message.orEmpty().contains("never sent"))
        val updates = mount("PUT", "$targets/${first.id}", 200, targetBody())
        assertThrows<NetworkError> { runBlocking { client.scimTargets.update(first.id, first.toInput()) } }
        assertEquals(0, updates.calls(), "the unknown arm never reached the wire")
    }

    // -- 5. No retry --------------------------------------------------------------------------

    @Test
    fun `no write is retried on 503`() = runTest {
        val id = UUID.randomUUID()
        val routes = listOf(
            mount("POST", targets, 503, ""),
            mount("PUT", "$targets/$id", 503, ""),
            mount("DELETE", "$targets/$id", 503, ""),
            mount("POST", "$targets/$id/reconcile", 503, ""),
        )
        val t = client.scimTargets // the default client: retry ENABLED
        assertThrows<NetworkError> { runBlocking { t.create(input(Redaction.secret("scim-"))) } }
        assertThrows<NetworkError> { runBlocking { t.update(id, input(null)) } }
        assertThrows<NetworkError> { runBlocking { t.delete(id) } }
        assertThrows<NetworkError> { runBlocking { t.reconcile(id) } }
        for (route in routes) assertEquals(1, route.calls())
    }

    // -- 6. Errors and reconcile ------------------------------------------------------------------

    @Test
    fun `statuses map and reconcile is a bodiless 202`() = runTest {
        val id = UUID.randomUUID()
        val other = UUID.randomUUID()
        mount("POST", targets, 400, """{"error":"validation_error","message":"credential: required on create"}""")
        mount("PUT", "$targets/$id", 409, """{"error":"conflict","message":"the SCIM target changed since it was read"}""")
        mount("POST", "$targets/$other/reconcile", 409, """{"error":"conflict","message":"a run holds the claim"}""")
        mount("GET", "$targets/$id", 404, """{"error":"not_found","message":"no"}""")
        mount("DELETE", "$targets/$id", 401, """{"error":"unauthorized","message":"human only"}""")
        val reconcile = mount("POST", "$targets/$id/reconcile", 202, """{"target_id":"$id","status":"started"}""")

        val t = client.scimTargets
        val e = assertThrows<ValidationError> { runBlocking { t.create(input(null)) } }
        assertTrue(e.message.orEmpty().contains("credential"))
        assertThrows<ConflictError> { runBlocking { t.update(id, input(null)) } }
        assertThrows<ConflictError> { runBlocking { t.reconcile(other) } }
        assertThrows<NotFoundError> { runBlocking { t.get(id) } }
        assertThrows<AuthError> { runBlocking { t.delete(id) } }

        val accepted = t.reconcile(id)
        assertEquals(id, accepted.targetId)
        assertEquals("started", accepted.status)
        assertTrue(reconcile.last().body.isEmpty(), "reconcile sends no body")
    }

    @Test
    fun `a read converts into the replacement body without a credential`() {
        val t = ManagementTransport.READER.decodeFromString(ScimTargetResponse.serializer(), targetBody())
        val body = t.toInput()
        assertNull(body.credential, "absent keeps the stored credential")
        assertEquals(t.baseUrl, body.baseUrl)
        assertEquals(true, body.enabled)
    }
}
