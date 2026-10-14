package io.axiam.sdk.management

import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.Certificate
import io.axiam.sdk.management.models.CertificateType
import io.axiam.sdk.management.models.CreateCertificateRequest
import io.axiam.sdk.management.models.GeneratedCertificate
import io.axiam.sdk.management.models.KeyAlgorithm
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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/**
 * CONTRACT.md contract 1.61 — `Certificate.user_id` and its two request members (§27.11 rule 5's
 * required test), and `SsfStreamInput.expected_updated_at` with the three meanings of
 * `events_requested` on an update (§32.2, §32.3 rule 4, §32.8 test 1).
 *
 * `CibaPendingList` (§33.3 rule 16) is not modelled here: no registry operation returns it and the
 * generator emits only the models its operations carry.
 */
class Contract161ModelsTest : ManagementTestBase() {

    private val streams = "/api/v1/tenants/$TENANT_ID/ssf/streams"
    private val revoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    private val credential = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

    private fun certJson(userId: String? = null, withMember: Boolean = true, extra: String = ""): String {
        val member = when {
            !withMember -> ""
            userId == null -> ""","user_id":null"""
            else -> ""","user_id":"$userId""""
        }
        return """{"cert_type":"User","created_at":"2026-10-13T00:00:00Z","fingerprint":"example",
            "id":"${UUID.randomUUID()}","issuer_ca_id":"$EXAMPLE_ID","key_algorithm":"Rsa4096","metadata":{},
            "not_after":"2027-10-13T00:00:00Z","not_before":"2026-10-13T00:00:00Z","public_cert_pem":"example",
            "status":"Active","subject":"example","tenant_id":"$TENANT_ID"$member$extra}"""
    }

    // -- §27.11 rule 5: the required test --------------------------------------------------

    @Test
    fun `generate and sign_csr send user_id exactly as given and no key without one`() = runTest {
        val user = UUID.randomUUID()
        val generate = mount("POST", "/api/v1/certificates", 201, certJson(user.toString(), extra = ""","private_key_pem":"example""""))
        val sign = mount("POST", "/api/v1/certificates/sign-csr", 201, certJson(user.toString()))
        fun generateRequest(userId: UUID?) = CreateCertificateRequest(
            certType = CertificateType.USER, issuerCaId = EXAMPLE_ID, keyAlgorithm = KeyAlgorithm.RSA4096,
            subject = "example", userId = userId, validityDays = 365,
        )
        fun signRequest(userId: UUID?) = SignCertificateCsrRequest(
            certType = CertificateType.USER, csrPem = "example", issuerCaId = EXAMPLE_ID,
            userId = userId, validityDays = 365,
        )

        client.certificates.generate(generateRequest(user))
        assertEquals(JsonPrimitive(user.toString()), generate.last().json()["user_id"])
        client.certificates.generate(generateRequest(null))
        assertFalse("user_id" in generate.last().json(), "no account named: no key, and never null")

        client.certificates.signCsr(signRequest(user))
        assertEquals(JsonPrimitive(user.toString()), sign.last().json()["user_id"])
        client.certificates.signCsr(signRequest(null))
        assertFalse("user_id" in sign.last().json(), "no account named: no key, and never null")
    }

    @Test
    fun `a certificate body with a uuid, a null and no member all decode`() = runTest {
        val user = UUID.randomUUID()
        val a = ManagementTransport.READER.decodeFromString(Certificate.serializer(), certJson(user.toString()))
        val b = ManagementTransport.READER.decodeFromString(Certificate.serializer(), certJson(null))
        val c = ManagementTransport.READER.decodeFromString(Certificate.serializer(), certJson(null, withMember = false))
        assertEquals(user, a.userId)
        assertNull(b.userId, "null: no account named")
        assertNull(c.userId, "absent (a server before 1.0.1): no account named")

        // Inside GeneratedCertificate: the same member, the same rule.
        val withKey = certJson(user.toString(), extra = ""","private_key_pem":"example"""")
        assertEquals(
            user,
            ManagementTransport.READER.decodeFromString(GeneratedCertificate.serializer(), withKey).userId,
        )
        assertNull(
            ManagementTransport.READER.decodeFromString(
                GeneratedCertificate.serializer(),
                certJson(null, withMember = false, extra = ""","private_key_pem":"example""""),
            ).userId,
        )

        // Never synthesised from the metadata or the subject.
        val legacy = certJson(null, withMember = false).replace("\"metadata\":{}", "\"metadata\":{\"user_id\":\"$user\"}")
        assertNull(ManagementTransport.READER.decodeFromString(Certificate.serializer(), legacy).userId)
    }

    // -- §32.8 test 1: expected_updated_at and events_requested -----------------------------

    private fun streamJson(requested: String, updatedAt: String = "2026-10-04T00:00:00Z", allowed: String = "\"$revoked\""): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","receiver_client_id":"rp-1",
            "audience":"https://rp.example","description":null,"delivery_method":"push",
            "endpoint_url":"https://rp.example/ssf","authorization_header_set":false,
            "events_allowed":[$allowed],"events_requested":$requested,"events_delivered":[],
            "subject_format":"iss_sub","status":"enabled","status_reason":null,"status_actor":"admin",
            "last_verification_at":null,"created_at":"2026-10-04T00:00:00Z","updated_at":"$updatedAt",
            "transmitter_active":true}"""

    private fun input(requested: List<SsfEventType>? = null, expectedUpdatedAt: String? = null) = SsfStreamInput(
        audience = "https://rp.example",
        deliveryMethod = SsfDeliveryMethod.PUSH,
        endpointUrl = "https://rp.example/ssf",
        eventsAllowed = listOf(SsfEventType.SESSION_REVOKED),
        eventsRequested = requested,
        expectedUpdatedAt = expectedUpdatedAt,
        receiverClientId = "rp-1",
    )

    @Test
    fun `expected_updated_at is sent exactly as given and events_requested keeps its three meanings`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$streams/$id", 200, streamJson("[\"$revoked\"]"))

        // A non-UTC offset and a trailing-zero fraction a re-formatting client would lose.
        val read = "2026-10-05T02:00:00.120000+02:00"
        client.ssf.updateStream(id, input(expectedUpdatedAt = read))
        assertEquals(JsonPrimitive(read), route.last().json()["expected_updated_at"])
        assertTrue(route.last().json()["expected_updated_at"] is JsonPrimitive)

        client.ssf.updateStream(id, input())
        assertFalse("expected_updated_at" in route.last().json(), "absent when unset, never null")
        assertFalse("events_requested" in route.last().json(), "unset: absent (resets to all of events_allowed)")

        client.ssf.updateStream(id, input(requested = emptyList()))
        assertEquals(JsonArray(emptyList()), route.last().json()["events_requested"], "[] is sent as []")

        client.ssf.updateStream(id, input(requested = listOf(SsfEventType.SESSION_REVOKED)))
        assertEquals(JsonArray(listOf(JsonPrimitive(revoked))), route.last().json()["events_requested"])
    }

    @Test
    fun `a 409 on update is surfaced once and not retried`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$streams/$id", 409, """{"error":"conflict","message":"the stream changed since it was read"}""")
        assertThrows<ConflictError> { runBlocking { client.ssf.updateStream(id, input(expectedUpdatedAt = "2026-10-04T00:00:00Z")) } }
        assertEquals(1, route.calls(), "a 409 is the caller's to resolve: one request")
        assertEquals(JsonPrimitive("2026-10-04T00:00:00Z"), route.last().json()["expected_updated_at"])
    }

    @Test
    fun `the read-modify-write helper sends back what it read`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$streams/$id", 200, streamJson("[]"))

        // The receiver narrowed the stream to "none": [] goes back as [], never omitted.
        val none = ManagementTransport.READER.decodeFromString(SsfStream.serializer(), streamJson("[]", "2026-10-05T00:00:00Z"))
        assertEquals(emptyList<SsfEventType>(), none.eventsRequested)
        val body = none.toInput()
        assertEquals("2026-10-05T00:00:00Z", body.expectedUpdatedAt, "the version it read")
        client.ssf.updateStream(id, body)
        assertEquals(JsonArray(emptyList()), route.last().json()["events_requested"])
        assertEquals(JsonPrimitive("2026-10-05T00:00:00Z"), route.last().json()["expected_updated_at"])

        // A list the receiver chose goes back as given.
        val two = ManagementTransport.READER.decodeFromString(
            SsfStream.serializer(),
            streamJson("[\"$revoked\",\"$credential\"]", allowed = "\"$revoked\",\"$credential\""),
        )
        client.ssf.updateStream(id, two.toInput())
        assertEquals(
            JsonArray(listOf(JsonPrimitive(revoked), JsonPrimitive(credential))),
            route.last().json()["events_requested"],
        )
    }
}
