package io.axiam.sdk.management

import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.SsfDeliveryMethod
import io.axiam.sdk.management.models.SsfEventType
import io.axiam.sdk.management.models.SsfStatusActor
import io.axiam.sdk.management.models.SsfStream
import io.axiam.sdk.management.models.SsfStreamInput
import io.axiam.sdk.management.models.SsfStreamStatus
import io.axiam.sdk.management.models.SsfSubjectFormat
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
import java.util.UUID

/**
 * The `ssf` management namespace — CONTRACT.md §32.8's six management tests.
 * (The receiver helper's are in `io.axiam.sdk.ssf.SsfReceiverTest`.)
 */
class SsfManagementTest : ManagementTestBase() {

    private val streams = "/api/v1/tenants/$TENANT_ID/ssf/streams"
    private val revoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

    private fun headerValue() = "Bearer " + Redaction.secret()

    private fun streamBody(
        extra: String = "",
        status: String = "enabled",
        delivery: String = "push",
        subjectFormat: String = "iss_sub",
        actor: String = "admin",
        allowed: String = revoked,
        transmitterActive: Boolean = true,
    ): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","receiver_client_id":"rp-1",
            "audience":"https://rp.example","description":null,"delivery_method":"$delivery",
            "endpoint_url":"https://rp.example/ssf","authorization_header_set":true,
            "events_allowed":["$allowed"],"events_requested":["$revoked"],"events_delivered":["$revoked"],
            "subject_format":"$subjectFormat","status":"$status","status_reason":null,
            "status_actor":"$actor","last_verification_at":null,
            "created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z",
            "transmitter_active":$transmitterActive$extra}"""

    private fun input(header: String?) = SsfStreamInput(
        audience = "https://rp.example",
        authorizationHeader = header?.let { Sensitive.of(it) },
        deliveryMethod = SsfDeliveryMethod.PUSH,
        description = "the RP",
        endpointUrl = "https://rp.example/ssf",
        eventsAllowed = listOf(SsfEventType.SESSION_REVOKED),
        receiverClientId = "rp-1",
    )

    private fun decode(body: String): SsfStream =
        ManagementTransport.READER.decodeFromString(SsfStream.serializer(), body)

    // -- 1. Replacement ----------------------------------------------------------

    @Test
    fun `update_stream puts every member it models`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$streams/$id", 200, streamBody())
        val body = input(null).copy(
            eventsRequested = listOf(SsfEventType.SESSION_REVOKED),
            subjectFormat = SsfSubjectFormat.ISS_SUB,
            status = SsfStreamStatus.ENABLED,
            statusReason = "ok",
            clearAuthorizationHeader = false,
        )
        val stream = client.ssf.updateStream(id, body)
        assertTrue(stream.transmitterActive)
        val sent = route.last().json()
        for (member in listOf(
            "receiver_client_id", "audience", "delivery_method", "events_allowed", "description",
            "endpoint_url", "events_requested", "subject_format", "status", "status_reason",
            "clear_authorization_header",
        )) {
            assertTrue(member in sent, member)
        }
        assertEquals(JsonArray(listOf(JsonPrimitive(revoked))), sent["events_allowed"])
        assertFalse("authorization_header" in sent, "absent keeps the stored header")
        // The four required members are constructor parameters with no default.
    }

    // -- 2. The header is Sensitive ------------------------------------------------

    @Test
    fun `the push header is sent and never rendered or decoded`() = runTest {
        val header = headerValue()
        val body = input(header)
        Redaction.assertNoFragment(body.toString(), header, "input toString")
        Redaction.assertNoFragment(
            ManagementTransport.READER.encodeToString(SsfStreamInput.serializer(), body),
            header,
            "input serialized for logs",
        )
        val route = mount("POST", streams, 201, streamBody(""","authorization_header":"$header""""))
        val created = client.ssf.createStream(body)
        assertEquals(JsonPrimitive(header), route.last().json()["authorization_header"])
        Redaction.assertNoFragment(created.toString(), header, "stream toString")
        Redaction.assertNoFragment(
            ManagementTransport.READER.encodeToString(SsfStream.serializer(), created),
            header,
            "stream serialized",
        )
        assertFalse(SsfStream::class.members.any { it.name == "authorizationHeader" })
        assertTrue(created.authorizationHeaderSet)
    }

    // -- 3. Open decoding -------------------------------------------------------------

    @Test
    fun `unknown values and both transmitter states decode`() {
        val odd = decode(
            streamBody(
                status = "quarantined",
                delivery = "websocket",
                subjectFormat = "opaque",
                actor = "policy",
                allowed = "https://example.test/event-type/new",
            ),
        )
        assertEquals(SsfStreamStatus.UNKNOWN, odd.status)
        assertEquals(SsfDeliveryMethod.UNKNOWN, odd.deliveryMethod)
        assertEquals(SsfSubjectFormat.UNKNOWN, odd.subjectFormat)
        assertEquals(SsfStatusActor.UNKNOWN, odd.statusActor)
        assertEquals(SsfEventType.UNKNOWN, odd.eventsAllowed[0])

        val inactive = decode(
            streamBody(
                ""","transmitter_inactive_reason":"per-tenant issuers are off in a multi-tenant deployment"""",
                transmitterActive = false,
            ),
        )
        assertFalse(inactive.transmitterActive)
        assertNotNull(inactive.transmitterInactiveReason)
        assertNull(decode(streamBody()).transmitterInactiveReason)
        // URI-valued constants are named by the URI's last segment; the URI is the wire value.
        assertEquals(revoked, SsfEventType.SESSION_REVOKED.wire)
    }

    // -- 4. Pagination ------------------------------------------------------------------

    @Test
    fun `list_streams pages and the walk carries search`() = runTest {
        val page0 = """{"items":[${streamBody()}],"total":2,"offset":0,"limit":1}"""
        val page1 = """{"items":[${streamBody()}],"total":2,"offset":1,"limit":1}"""
        val route = mountSequence("GET", streams, 200, listOf(page0, page0, page1))
        val page = client.ssf.listStreams(PageRequest.matching(1, "rp.example"))
        assertEquals(2, page.total)
        val all = client.ssf.listStreamsAll(PageRequest.matching(1, "rp.example"))
        assertEquals(2, all.size)
        assertEquals(3, route.calls())
        for (request in route.requests) assertEquals("rp.example", request.query["search"])
    }

    // -- 5. No retry ----------------------------------------------------------------------

    @Test
    fun `none of the three writes is retried on 503`() = runTest {
        val id = UUID.randomUUID()
        val routes = listOf(
            mount("POST", streams, 503, ""),
            mount("PUT", "$streams/$id", 503, ""),
            mount("DELETE", "$streams/$id", 503, ""),
        )
        val s = client.ssf // the default client: retry ENABLED
        assertThrows<NetworkError> { runBlocking { s.createStream(input(headerValue())) } }
        assertThrows<NetworkError> { runBlocking { s.updateStream(id, input(null)) } }
        assertThrows<NetworkError> { runBlocking { s.deleteStream(id) } }
        for (route in routes) assertEquals(1, route.calls())
    }

    @Test
    fun `none of the three writes is re-sent after a dropped connection`() = runTest {
        val id = UUID.randomUUID()
        val s = client.ssf // the default client: retry ENABLED
        assertSentOnceOverDroppedConnection("create", mountDropped("POST", streams)) { s.createStream(input(headerValue())) }
        assertSentOnceOverDroppedConnection("update", mountDropped("PUT", "$streams/$id")) { s.updateStream(id, input(null)) }
        assertSentOnceOverDroppedConnection("delete", mountDropped("DELETE", "$streams/$id")) { s.deleteStream(id) }
    }

    // -- 6. Errors -------------------------------------------------------------------------

    @Test
    fun `statuses map per section 2`() = runTest {
        val id = UUID.randomUUID()
        mount("PUT", "$streams/$id", 400, """{"error":"validation_error","message":"endpoint_url: must be https"}""")
        mount("POST", streams, 409, """{"error":"conflict","message":"audience"}""")
        mount("GET", "$streams/$id", 404, """{"error":"not_found","message":"no"}""")
        mount("DELETE", "$streams/$id", 401, """{"error":"unauthorized","message":"human only"}""")
        val s = client.ssf
        val e = assertThrows<ValidationError> { runBlocking { s.updateStream(id, input(null)) } }
        assertTrue(e.message.orEmpty().contains("https"))
        assertThrows<ConflictError> { runBlocking { s.createStream(input(null)) } }
        assertThrows<NotFoundError> { runBlocking { s.getStream(id) } }
        assertThrows<AuthError> { runBlocking { s.deleteStream(id) } }
    }

    @Test
    fun `a read converts into the replacement body without the header`() {
        val stream = decode(streamBody())
        val body = stream.toInput()
        assertNull(body.authorizationHeader)
        assertNull(body.clearAuthorizationHeader)
        assertEquals(stream.eventsRequested, body.eventsRequested)
    }
}
