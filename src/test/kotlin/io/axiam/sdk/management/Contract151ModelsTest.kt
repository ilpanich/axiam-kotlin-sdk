package io.axiam.sdk.management

import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.AssignRoleToUserRequest
import io.axiam.sdk.management.models.CertificateType
import io.axiam.sdk.management.models.CreateCertificateRequest
import io.axiam.sdk.management.models.KeyAlgorithm
import io.axiam.sdk.management.models.RoleAssignment
import io.axiam.sdk.management.models.SignCertificateCsrRequest
import io.axiam.sdk.management.models.SubjectAltName
import io.axiam.sdk.management.models.inherits
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * CONTRACT.md §27.13 (contract 1.51) — the model changes of the dogfooding
 * remediation, as a decoder and an encoder see them.
 *
 * The regenerated types pick up every new field for free. What they do not pick
 * up by themselves is the behaviour §27.13 asks for at the edges: a `cert_type`
 * this SDK does not know must not fail `certificates.list`, a `subject_alt_names`
 * entry must reach the wire in the shape the server parses, and an `inherit` a
 * server does not send must read as `true`. Mirrors the reference (Rust)
 * `tests/contract_151_models_test.rs`.
 */
class Contract151ModelsTest : ManagementTestBase() {

    private fun certificateJson(certType: String, id: UUID = UUID.randomUUID()): String =
        """{"cert_type": "$certType", "created_at": "2026-09-24T00:00:00Z",
            "fingerprint": "ab", "id": "$id", "issuer_ca_id": "$EXAMPLE_ID",
            "key_algorithm": "Ed25519", "metadata": {},
            "not_after": "2027-09-24T00:00:00Z", "not_before": "2026-09-24T00:00:00Z",
            "public_cert_pem": "pem", "status": "Active", "subject": "device-001",
            "tenant_id": "$TENANT_ID"}"""

    // -----------------------------------------------------------------------
    // S-7 rule 2 — CertificateType decodes openly
    // -----------------------------------------------------------------------

    /**
     * One certificate of a type this SDK has never heard of must not take the
     * page down with it (§27.13 S-7 rule 2). Re-vendoring taught the enum
     * `SERVER`; this is the rule for the value after that.
     */
    @Test
    fun `certificates list survives a cert_type this SDK does not know`() = runTest {
        mount(
            "GET", "/api/v1/certificates", 200,
            """{"items": [${certificateJson("Device")}, ${certificateJson("Server")},
                ${certificateJson("Gateway")}], "total": 3, "offset": 0, "limit": 50}""",
        )

        val page = client.certificates.list(PageRequest(limit = 50))

        val types = page.items.map { it.certType }
        assertEquals(
            listOf(CertificateType.DEVICE, CertificateType.SERVER, CertificateType.UNKNOWN),
            types,
            "one server certificate must not fail certificates.list",
        )
    }

    /**
     * An unrecognised value decodes to [CertificateType.UNKNOWN] rather than
     * throwing and failing the whole response (§27.11 rule 1); this SDK's open
     * enum -- unlike the Rust reference's `Unknown(String)` -- does not carry
     * the raw spelling forward (`UNKNOWN.wire` is `""`, deliberately no server
     * value, so an unrecognised value can never be written back as a spelling
     * the server never used). The known values are the I4 twin: they decode
     * AND re-encode to the exact spelling the server uses.
     */
    @Test
    fun `an unknown cert_type decodes to UNKNOWN rather than failing`() {
        val decoded = Json.decodeFromString(CertificateType.serializer(), "\"Gateway\"")
        assertEquals(CertificateType.UNKNOWN, decoded)
        assertEquals("", decoded.wire, "UNKNOWN's own wire spelling is empty -- no server value")

        // The I4 twin: the known values are the ones the server spells, and
        // round-trip exactly.
        for ((wire, known) in listOf(
            "User" to CertificateType.USER,
            "Service" to CertificateType.SERVICE,
            "Device" to CertificateType.DEVICE,
            "Server" to CertificateType.SERVER,
        )) {
            assertEquals(known, Json.decodeFromString(CertificateType.serializer(), "\"$wire\""))
            assertEquals(
                "\"$wire\"",
                Json.encodeToString(CertificateType.serializer(), known),
            )
        }
    }

    // -----------------------------------------------------------------------
    // S-7 rule 1 — subject_alt_names
    // -----------------------------------------------------------------------

    /**
     * `SubjectAltName` is externally tagged: `{"dns": ...}` or `{"ip": ...}`.
     *
     * The generator used to emit this `oneOf` as a data class with no fields,
     * which compiled, serialized as `{}`, and was refused by the server. This
     * pins the shape on the wire through a real `generate` call, not only
     * through direct serialization, so the request path cannot re-shape it
     * either. **This is the test a reverted generator fix turns red**: see
     * `externally_tagged`/`emit_externally_tagged` in `scripts/gen_management.py`.
     */
    @Test
    fun `a Server certificate sends its names externally tagged`() = runTest {
        mount(
            "POST", "/api/v1/certificates", 201,
            certificateJson("Server").replaceFirst("{", "{\"private_key_pem\": \"k\", "),
        )

        client.certificates.generate(
            CreateCertificateRequest(
                certType = CertificateType.SERVER,
                issuerCaId = EXAMPLE_ID,
                keyAlgorithm = KeyAlgorithm.ED25519,
                subject = "api.lakeside.internal",
                subjectAltNames = listOf(
                    SubjectAltName.SubjectAltNameDns("api.lakeside.internal"),
                    SubjectAltName.SubjectAltNameIp("10.0.0.5"),
                ),
                validityDays = 90,
            ),
        )

        val sent = route("POST", "/api/v1/certificates").last().json()
        assertEquals(
            """[{"dns":"api.lakeside.internal"},{"ip":"10.0.0.5"}]""",
            sent["subject_alt_names"].toString(),
        )
    }

    /**
     * The I4 twin: a request with no names sends **no** `subject_alt_names` key
     * -- not `null`, not `[]` (§27.13 S-7 rule 1: "SHOULD omit the key") -- on
     * both leaf paths, so a pre-1.51 body is byte-for-byte what it was.
     */
    @Test
    fun `a leaf request without names omits the key`() {
        val generate = ManagementTransport.WIRE.encodeToJsonElement(
            CreateCertificateRequest.serializer(),
            CreateCertificateRequest(
                certType = CertificateType.DEVICE,
                issuerCaId = EXAMPLE_ID,
                keyAlgorithm = KeyAlgorithm.ED25519,
                subject = "device-001",
                subjectAltNames = null,
                validityDays = 90,
            ),
        ) as JsonObject
        val sign = ManagementTransport.WIRE.encodeToJsonElement(
            SignCertificateCsrRequest.serializer(),
            SignCertificateCsrRequest(
                certType = CertificateType.DEVICE,
                csrPem = "csr",
                issuerCaId = EXAMPLE_ID,
                subjectAltNames = null,
                validityDays = 90,
            ),
        ) as JsonObject

        assertFalse("subject_alt_names" in generate, "generate: $generate")
        assertFalse("subject_alt_names" in sign, "sign_csr: $sign")
    }

    /** And a name decodes back from the shape the server documents. */
    @Test
    fun `a SubjectAltName decodes from the documented shape`() {
        val names = Json.decodeFromString(
            kotlinx.serialization.builtins.ListSerializer(SubjectAltName.serializer()),
            """[{"dns": "a.example"}, {"ip": "fd00::1"}]""",
        )
        assertEquals(
            listOf(
                SubjectAltName.SubjectAltNameDns("a.example"),
                SubjectAltName.SubjectAltNameIp("fd00::1"),
            ),
            names,
        )
    }

    // -----------------------------------------------------------------------
    // S-10 — inherit
    // -----------------------------------------------------------------------

    /**
     * Rule 1: the key is sent only when it is `false`. `null` -- the default --
     * and an inheritable assignment's body stay a pre-1.51 body.
     */
    @Test
    fun `an assign request carries inherit only when stated`() {
        val base = AssignRoleToUserRequest(userId = EXAMPLE_ID, inherit = null, resourceId = EXAMPLE_ID)
        val omitted = ManagementTransport.WIRE.encodeToJsonElement(
            AssignRoleToUserRequest.serializer(), base,
        ) as JsonObject
        assertEquals(listOf("resource_id", "user_id"), omitted.keys.sorted())

        val stopped = ManagementTransport.WIRE.encodeToJsonElement(
            AssignRoleToUserRequest.serializer(), base.copy(inherit = false),
        ) as JsonObject
        assertEquals(false, stopped["inherit"]?.jsonPrimitive?.boolean)
    }

    /**
     * Rule 3, role side. The field is required there, but a server older than
     * contract 1.51 does not send it -- and failing the listing over it would
     * take the manifest's planning read down with it. Absent reads as `true`;
     * a stated `false` is kept. **This is the test a reverted generator fix
     * turns red**: `DEFAULT_TRUE_FIELDS` in `scripts/gen_management.py`.
     */
    @Test
    fun `a role-side listing reads an absent inherit as true`() = runTest {
        fun user(extra: String) = """{${extra}"user": {"created_at": "2026-09-24T00:00:00Z",
            "email": "a@example.com", "email_verified": true, "failed_login_attempts": 0,
            "id": "${UUID.randomUUID()}", "is_locked": false, "metadata": {},
            "mfa_enabled": false, "status": "Active", "tenant_id": "$TENANT_ID",
            "updated_at": "2026-09-24T00:00:00Z", "username": "a"}}"""

        mount(
            "GET", "/api/v1/roles/$EXAMPLE_ID/users", 200,
            "[${user("")}, ${user("\"inherit\": false, ")}]",
        )

        val rows = client.roles.listUsers(EXAMPLE_ID)
        assertTrue(rows[0].inherit, "absent must read as true, never false")
        assertFalse(rows[1].inherit, "a stated false is kept")
    }

    /**
     * Rule 3, subject side: `RoleAssignment.inherit` is optional, and
     * [io.axiam.sdk.management.models.inherits] is the one place the default is
     * decided.
     */
    @Test
    fun `a subject-side assignment reads absent as inheriting`() = runTest {
        fun role(extra: String) = """{${extra}"role": {"created_at": "2026-09-24T00:00:00Z",
            "description": "d", "id": "${UUID.randomUUID()}", "is_global": false, "name": "r",
            "tenant_id": "$TENANT_ID", "updated_at": "2026-09-24T00:00:00Z"}}"""

        mount(
            "GET", "/api/v1/users/$EXAMPLE_ID/roles", 200,
            "[${role("")}, ${role("\"inherit\": true, ")}, ${role("\"inherit\": false, ")}]",
        )

        val rows = client.users.listRoles(EXAMPLE_ID)
        assertEquals(null, rows[0].inherit, "the wire value is not invented")
        assertEquals(listOf(true, true, false), rows.map(RoleAssignment::inherits))
    }
}
