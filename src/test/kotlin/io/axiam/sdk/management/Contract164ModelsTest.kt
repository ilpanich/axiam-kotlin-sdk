package io.axiam.sdk.management

import io.axiam.sdk.management.models.NetworkReplyProfile
import io.axiam.sdk.management.models.RadiusServiceType
import io.axiam.sdk.management.models.RadiusTerminationAction
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * Contract 1.64 (§34.8 (c); C163-10): a reply profile keeps the server's own text of its two open
 * enumerations, so that the refusal at `plan` can quote a value the enumeration decoded to `UNKNOWN`.
 */
class Contract164ModelsTest {

    private fun profile(action: String, service: String) = Json.parseToJsonElement(
        """{"segment_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222",
            "dictionary":"axiam-radius-reply/1","session_timeout_secs":900,"session_timeout_clamped":false,
            "termination_action":"$action","idle_timeout_secs":null,"filter_id":null,"service_type":$service,
            "version":1,"created_by":"33333333-3333-3333-3333-333333333333",
            "updated_by":"33333333-3333-3333-3333-333333333333",
            "created_at":"2026-10-16T00:00:00Z","updated_at":"2026-10-16T00:00:00Z"}""",
    )

    @Test
    fun `an unknown open-enumeration value decodes to UNKNOWN and its text is kept`() {
        val p = ManagementSupport.decode(
            "get_profile", NetworkReplyProfile.serializer(), profile("future", "\"also-future\""),
        )
        assertEquals(RadiusTerminationAction.UNKNOWN, p.terminationAction)
        assertEquals("future", p.terminationActionRaw)
        assertEquals(RadiusServiceType.UNKNOWN, p.serviceType)
        assertEquals("also-future", p.serviceTypeRaw)
    }

    @Test
    fun `a known value keeps its text too, and an absent service_type has none`() {
        val p = ManagementSupport.decode(
            "get_profile", NetworkReplyProfile.serializer(), profile("radius_request", "null"),
        )
        assertEquals(RadiusTerminationAction.RADIUS_REQUEST, p.terminationAction)
        assertEquals("radius_request", p.terminationActionRaw)
        assertNull(p.serviceType)
        assertNull(p.serviceTypeRaw)
    }

    @Test
    fun `the generator and the decoder declare the same raw members`() {
        val script = Files.readString(Path.of("scripts/gen_management.py"))
        for ((serial, pairs) in ManagementSupport.RAW_STRINGS) {
            val schema = serial.substringAfterLast('.')
            for ((wire, rawWire) in pairs) {
                assertTrue(
                    script.contains("(\"$schema\", \"$wire\"): \"$rawWire\""),
                    "scripts/gen_management.py does not declare ($schema, $wire) -> $rawWire",
                )
            }
        }
    }
}
