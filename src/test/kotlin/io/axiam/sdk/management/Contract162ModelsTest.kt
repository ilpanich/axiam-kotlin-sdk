package io.axiam.sdk.management

import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.CertificateType
import io.axiam.sdk.management.models.CreateCertificateRequest
import io.axiam.sdk.management.models.KeyAlgorithm
import io.axiam.sdk.management.models.ScimTargetInput
import io.axiam.sdk.management.models.SignCertificateCsrRequest
import io.axiam.sdk.management.models.SsfDeliveryMethod
import io.axiam.sdk.management.models.SsfEventType
import io.axiam.sdk.management.models.SsfStream
import io.axiam.sdk.management.models.SsfStreamInput
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant
import java.util.UUID

/**
 * CONTRACT.md contract 1.62 (§34.6 items e, f, g, h, i): the change-taking read-modify-write form
 * for a stream (§32.8 test 7), an assigned `null` as "none" (§27.11 rule 5), `expected_updated_at`
 * as the server's own string (§32.2), the three meanings of `events_requested` at the
 * `update_stream` call site, and the request `user_id` as an untyped string.
 */
class Contract162ModelsTest : ManagementTestBase() {

    private val streams = "/api/v1/tenants/$TENANT_ID/ssf/streams"
    private val revoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    private val credential = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    private val level = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

    /** A `+00:00` offset and nine fraction digits: what `Instant.toString()` can never give back. */
    private val rawUpdatedAt = "2026-10-05T02:00:00.123456789+00:00"

    private fun streamJson(requested: String, allowed: String, updatedAt: String = rawUpdatedAt): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","receiver_client_id":"rp-1",
            "audience":"https://rp.example","description":"the RP","delivery_method":"push",
            "endpoint_url":"https://rp.example/ssf","authorization_header_set":true,
            "events_allowed":[$allowed],"events_requested":$requested,"events_delivered":[],
            "subject_format":"iss_sub","status":"enabled","status_reason":null,"status_actor":"admin",
            "last_verification_at":null,"created_at":"2026-10-04T00:00:00Z","updated_at":"$updatedAt",
            "transmitter_active":true}"""

    private val three = "\"$revoked\",\"$credential\",\"$level\""

    /** Reads the stream through the client, the way a caller does, so the raw string is kept. */
    private suspend fun read(requested: String, allowed: String = three, updatedAt: String = rawUpdatedAt): SsfStream {
        val id = UUID.randomUUID()
        mount("GET", "$streams/$id", 200, streamJson(requested, allowed, updatedAt))
        return client.ssf.getStream(id)
    }

    // -- (g): the response's own string ----------------------------------------------------------

    @Test
    fun `the stream keeps the server's own updated_at string next to the parsed value`() = runTest {
        val stream = read("[\"$revoked\"]")
        assertEquals(rawUpdatedAt, stream.updatedAtRaw)
        assertEquals(Instant.parse("2026-10-05T02:00:00.123456789Z"), stream.updatedAt)
        assertNotNull(stream.updatedAtRaw)
        // What Instant renders again is NOT the server's spelling.
        assertFalse(stream.updatedAt.toString() == rawUpdatedAt)
    }

    @Test
    fun `the plain converter and the change-taking form send the raw string byte for byte`() = runTest {
        val stream = read("[\"$revoked\",\"$credential\"]")
        assertEquals(rawUpdatedAt, stream.toInput().expectedUpdatedAt)
        assertEquals(rawUpdatedAt, stream.toInput(SsfStreamChanges()).expectedUpdatedAt)

        // ... and it is what reaches the wire.
        val route = mount("PUT", "$streams/${UUID.randomUUID()}", 200, streamJson("[]", three))
        val id = UUID.randomUUID()
        val put = mount("PUT", "$streams/$id", 200, streamJson("[]", three))
        client.ssf.updateStream(id, stream.toInput(SsfStreamChanges()))
        assertEquals(JsonPrimitive(rawUpdatedAt), put.last().json()["expected_updated_at"])
        assertEquals(0, route.calls())
    }

    @Test
    fun `a stream decoded other than through the client has no raw string and the converter says so`() {
        val decoded = ManagementTransport.READER.decodeFromString(
            SsfStream.serializer(), streamJson("[]", three, "2026-10-05T00:00:00Z"),
        )
        assertNull(decoded.updatedAtRaw, "the raw string is filled in by the client's decode, not by a bare Json")
        assertEquals("2026-10-05T00:00:00Z", decoded.toInput().expectedUpdatedAt)
    }

    // -- (e): the change-taking form, §32.8 test 7 -------------------------------------------------

    @Test
    fun `lowering events_allowed cuts events_requested to the new ceiling`() = runTest {
        // Three allowed, two requested; the change lowers the ceiling to one of the two.
        val stream = read("[\"$revoked\",\"$credential\"]")
        val body = stream.toInput(SsfStreamChanges(eventsAllowed = listOf(SsfEventType.CREDENTIAL_CHANGE)))
        assertEquals(listOf(SsfEventType.CREDENTIAL_CHANGE), body.eventsAllowed)
        assertEquals(listOf(SsfEventType.CREDENTIAL_CHANGE), body.eventsRequested, "only what is in the new ceiling")

        // Order is the read's.
        val kept = stream.toInput(SsfStreamChanges(eventsAllowed = listOf(SsfEventType.CREDENTIAL_CHANGE, SsfEventType.SESSION_REVOKED)))
        assertEquals(listOf(SsfEventType.SESSION_REVOKED, SsfEventType.CREDENTIAL_CHANGE), kept.eventsRequested)

        // A ceiling that leaves none of the requested ones cuts to [] (sent as []), never omitted.
        val none = stream.toInput(SsfStreamChanges(eventsAllowed = listOf(SsfEventType.ASSURANCE_LEVEL_CHANGE)))
        assertEquals(emptyList<SsfEventType>(), none.eventsRequested)
        val id = UUID.randomUUID()
        val put = mount("PUT", "$streams/$id", 200, streamJson("[]", three))
        client.ssf.updateStream(id, none)
        assertEquals(JsonArray(emptyList()), put.last().json()["events_requested"])
    }

    @Test
    fun `a change that touches no events sends events_requested as read, and an empty list as an empty list`() = runTest {
        val id = UUID.randomUUID()
        val put = mount("PUT", "$streams/$id", 200, streamJson("[]", three))

        val two = read("[\"$revoked\",\"$credential\"]")
        client.ssf.updateStream(id, two.toInput(SsfStreamChanges(audience = "https://other.example")))
        assertEquals(
            JsonArray(listOf(JsonPrimitive(revoked), JsonPrimitive(credential))),
            put.last().json()["events_requested"],
        )
        assertEquals(JsonPrimitive("https://other.example"), put.last().json()["audience"])
        assertEquals(JsonPrimitive(rawUpdatedAt), put.last().json()["expected_updated_at"], "the response's own string, byte for byte")

        val none = read("[]")
        client.ssf.updateStream(id, none.toInput(SsfStreamChanges(description = JsonNullable.Value("renamed"))))
        assertEquals(JsonArray(emptyList()), put.last().json()["events_requested"], "[] stays [] and is never omitted")
        assertEquals(JsonPrimitive("renamed"), put.last().json()["description"])
    }

    @Test
    fun `an events_requested named in the changes is sent as given and the server judges it`() = runTest {
        val stream = read("[\"$revoked\"]")
        val outside = stream.toInput(
            SsfStreamChanges(
                eventsAllowed = listOf(SsfEventType.SESSION_REVOKED),
                eventsRequested = JsonNullable.Value(listOf(SsfEventType.CREDENTIAL_CHANGE)),
            ),
        )
        assertEquals(listOf(SsfEventType.CREDENTIAL_CHANGE), outside.eventsRequested, "not cut: the server answers 400")

        // "None" for events_requested leaves the key out (which resets the stream, §32.2).
        val reset = stream.toInput(SsfStreamChanges(eventsRequested = JsonNullable.Null))
        assertNull(reset.eventsRequested)
    }

    @Test
    fun `an assigned null for expected_updated_at leaves the key out`() = runTest {
        val stream = read("[\"$revoked\"]")
        val body = stream.toInput(SsfStreamChanges(expectedUpdatedAt = JsonNullable.Null))
        assertNull(body.expectedUpdatedAt)

        val id = UUID.randomUUID()
        val put = mount("PUT", "$streams/$id", 200, streamJson("[]", three))
        client.ssf.updateStream(id, body)
        assertFalse("expected_updated_at" in put.last().json(), "none: the key is omitted and null is never sent")
        assertTrue(put.last().body.contains("\"events_requested\""), "the events it read still go back")

        // A named value replaces the read's.
        assertEquals("2026-10-06T00:00:00Z", stream.toInput(SsfStreamChanges(expectedUpdatedAt = JsonNullable.Value("2026-10-06T00:00:00Z"))).expectedUpdatedAt)
    }

    @Test
    fun `the change-taking form carries the authorization header only when it is named`() = runTest {
        val stream = read("[\"$revoked\"]")
        assertNull(stream.toInput(SsfStreamChanges()).authorizationHeader)
        assertNull(stream.toInput(SsfStreamChanges()).clearAuthorizationHeader)
        val cleared = stream.toInput(SsfStreamChanges(clearAuthorizationHeader = JsonNullable.Value(true)))
        assertEquals(true, cleared.clearAuthorizationHeader)
    }

    // -- (h): the three meanings at the call site (a documentation check, not a mock) --------------

    @Test
    fun `the update_stream documentation states the three meanings`() {
        val source = java.io.File("src/main/kotlin/io/axiam/sdk/management/SsfApi.kt").readText()
        val doc = source.substring(0, source.indexOf("suspend fun updateStream"))
            .substringAfterLast("/**")
        for (phrase in listOf(
            "three meanings of `events_requested`",
            "*absent* **resets** the stream to every event of `events_allowed`",
            // KDoc escapes the brackets (`[` would open a link), so the empty list is written `&#91;&#93;`.
            "`&#91;&#93;` is stored as the receiver's \"none\"",
            "a list of event types is stored as given and refused `400` if any is outside `events_allowed`",
            "takes its default on every update",
            "SsfStream.toInput(changes)",
        )) {
            assertTrue(doc.replace(Regex("\\s*\n\\s*\\*\\s*"), " ").contains(phrase), "update_stream's KDoc lacks: $phrase")
        }
    }

    @Test
    fun `the plain converter's documentation names the caller's duty`() {
        val source = java.io.File("src/main/kotlin/io/axiam/sdk/management/ReplacementBodies.kt").readText()
        val doc = source.substringBefore("fun SsfStream.toInput(): SsfStreamInput").substringAfterLast("/**")
            .replace(Regex("\\s*\n\\s*\\*\\s*"), " ")
        assertTrue(doc.contains("The caller's duty"), doc)
        assertTrue(doc.contains("cutting `eventsRequested` to the new `eventsAllowed` is yours to do"), doc)
        assertTrue(doc.contains("the three meanings"), doc)
    }

    // -- (f) and (i): user_id --------------------------------------------------------------------------

    private fun generate(userId: String?) = CreateCertificateRequest(
        certType = CertificateType.USER, issuerCaId = EXAMPLE_ID, keyAlgorithm = KeyAlgorithm.RSA4096,
        subject = "example", userId = userId, validityDays = 365,
    )

    private fun sign(userId: String?) = SignCertificateCsrRequest(
        certType = CertificateType.USER, csrPem = "example", issuerCaId = EXAMPLE_ID,
        userId = userId, validityDays = 365,
    )

    @Test
    fun `a request user_id that is not a uuid reaches the server and its 400 is surfaced`() = runTest {
        val generate = mount(
            "POST", "/api/v1/certificates", 400,
            """{"error":"validation_error","message":"user_id: not a user of this tenant"}""",
        )
        val sign = mount(
            "POST", "/api/v1/certificates/sign-csr", 400,
            """{"error":"validation_error","message":"user_id: not a user of this tenant"}""",
        )
        for (junk in listOf("not-a-uuid", "", "  ", "11111111-1111-1111-1111")) {
            val e = assertThrows<ValidationError> { runBlocking { client.certificates.generate(generate(junk)) } }
            assertTrue(e.message.orEmpty().contains("not a user of this tenant"), "the server's 400, verbatim")
            assertEquals(JsonPrimitive(junk), generate.last().json()["user_id"], "sent exactly as given, never judged client-side")
            assertThrows<ValidationError> { runBlocking { client.certificates.signCsr(sign(junk)) } }
            assertEquals(JsonPrimitive(junk), sign.last().json()["user_id"])
        }
        assertEquals(4, generate.calls())
        assertEquals(4, sign.calls())
    }

    @Test
    fun `an assigned null user_id is the same as never setting it and null is never sent`() = runTest {
        val generate = mount("POST", "/api/v1/certificates", 400, """{"message":"x"}""")
        val sign = mount("POST", "/api/v1/certificates/sign-csr", 400, """{"message":"x"}""")
        val assigned: String? = null
        assertThrows<ValidationError> { runBlocking { client.certificates.generate(generate(assigned)) } }
        assertThrows<ValidationError> { runBlocking { client.certificates.signCsr(sign(assigned)) } }
        assertFalse("user_id" in generate.last().json())
        assertFalse("user_id" in sign.last().json())
        assertFalse(generate.last().body.contains("null"), generate.last().body)
        assertFalse(sign.last().body.contains("null"), sign.last().body)
    }

    @Test
    fun `an assigned null expected_updated_at is omitted on ssf update and on scim update`() = runTest {
        val streamId = UUID.randomUUID()
        val put = mount("PUT", "$streams/$streamId", 200, streamJson("[]", three))
        client.ssf.updateStream(
            streamId,
            SsfStreamInput(
                audience = "https://rp.example", deliveryMethod = SsfDeliveryMethod.PUSH,
                eventsAllowed = listOf(SsfEventType.SESSION_REVOKED), receiverClientId = "rp-1",
                expectedUpdatedAt = null,
            ),
        )
        assertFalse("expected_updated_at" in put.last().json())
        assertFalse(put.last().body.contains("null"), put.last().body)

        val scim = ManagementSupport.encodeBody(
            "scim_targets.update",
            ScimTargetInput.serializer(),
            ScimTargetInput(
                auth = io.axiam.sdk.management.models.ScimTargetAuthBearer(),
                baseUrl = "https://scim.example/v2",
                name = "t",
                scope = io.axiam.sdk.management.models.ScimTargetScopeAllUsers(),
                expectedUpdatedAt = null,
            ),
        )
        assertFalse(scim.contains("expected_updated_at"), scim)
        assertFalse(scim.contains("null"), scim)
    }
}
