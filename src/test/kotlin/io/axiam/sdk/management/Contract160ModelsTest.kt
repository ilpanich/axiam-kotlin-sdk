package io.axiam.sdk.management

import io.axiam.sdk.management.models.CreateFederationConfigRequest
import io.axiam.sdk.management.models.CreateNotificationRuleRequest
import io.axiam.sdk.management.models.NotificationEventType
import io.axiam.sdk.management.models.UpdateFederationConfigRequest
import io.axiam.sdk.management.models.UpdateNotificationRuleRequest
import io.axiam.sdk.Sensitive
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §27.15 (contract 1.60) — the three additive members and the
 * `federation.update_config` null rule, as a decoder and an encoder see them.
 *
 * The regenerated types carry the members; what this pins is the behaviour
 * §27.15 asks for at the edges: `window_minutes` is passed through and never
 * clamped, `allow_sha1_signatures` absent from a response reads `false`, and
 * each of the ten clearable members of `UpdateFederationConfigRequest` tells
 * "omitted, keep it" from "`null`, clear it" on the wire.
 */
class Contract160ModelsTest : ManagementTestBase() {

    private val rules = "/api/v1/notification-rules"
    private val configs = "/api/v1/federation-configs"

    private fun ruleJson(window: Int): String =
        """{"created_at":"2026-10-05T00:00:00Z","description":"d","enabled":true,
            "events":["login_failed"],"id":"$EXAMPLE_ID","name":"n","recipient_emails":["ops@example.com"],
            "tenant_id":"$TENANT_ID","updated_at":"2026-10-05T00:00:00Z","window_minutes":$window}"""

    /** A pre-1.0.0 server's response: neither `allow_sha1_signatures` nor `idp_metadata_signing_cert_pem`. */
    private val olderConfig =
        """{"allow_tenant_inheritance":false,"allowed_algorithms":[],"allowed_issuer_tenants":[],
            "attribute_map":null,"client_id":"rp","created_at":"2026-10-05T00:00:00Z","effective_scopes":[],
            "enabled":true,"has_bundled_mark":false,"id":"$EXAMPLE_ID","mints_client_secret":false,
            "pkce_required":true,"protocol":"Saml","provider":"idp","provider_kind":"saml","scopes":[],
            "tenant_id":"$TENANT_ID","updated_at":"2026-10-05T00:00:00Z",
            "token_exchange":{"accepted_audiences":[],"enabled":false,"max_token_age_secs":300,
            "scope_map":{},"subject_mapping":"email"}}"""

    private fun create(window: Int? = null) = CreateNotificationRuleRequest(
        description = "d",
        events = listOf(NotificationEventType.entries.first()),
        name = "n",
        recipientEmails = listOf("ops@example.com"),
        windowMinutes = window,
    )

    // -- note 1: window_minutes ------------------------------------------------------------

    /** §27.15 note 1's required test: sent as given, absent when unset, decoded from a response. */
    @Test
    fun `window_minutes is passed through, never clamped, and decoded`() = runTest {
        val route = mount("POST", rules, 201, ruleJson(45))
        val created = client.notificationRules.create(create(45))
        assertEquals(JsonPrimitive(45), route.last().json()["window_minutes"])
        assertEquals(45, created.windowMinutes)

        client.notificationRules.create(create())
        assertFalse("window_minutes" in route.last().json(), "unset: no key, the server stores 15")

        // Out of 1..1440: the server answers 400; the SDK sends the value unchanged.
        for (outOfRange in listOf(0, 5000)) {
            client.notificationRules.create(create(outOfRange))
            assertEquals(JsonPrimitive(outOfRange), route.last().json()["window_minutes"])
        }

        val update = mount("PUT", "$rules/$EXAMPLE_ID", 200, ruleJson(1441))
        val updated = client.notificationRules.update(EXAMPLE_ID, UpdateNotificationRuleRequest(windowMinutes = 1441))
        assertEquals(setOf("window_minutes"), update.last().json().keys)
        assertEquals(JsonPrimitive(1441), update.last().json()["window_minutes"])
        assertEquals(1441, updated.windowMinutes)
    }

    // -- notes 6 and 7: allow_sha1_signatures, idp_metadata_signing_cert_pem ----------------

    /** A response without either member (an older server) decodes: `false` and `null`. */
    @Test
    fun `a response without the 1_0_0 members decodes as false and null`() = runTest {
        mount("GET", "$configs/$EXAMPLE_ID", 200, olderConfig)
        val config = client.federation.getConfig(EXAMPLE_ID)
        assertFalse(config.allowSha1Signatures, "absent allow_sha1_signatures reads false")
        assertNull(config.idpMetadataSigningCertPem)
    }

    /** Both members are sent only when the caller sets them. */
    @Test
    fun `create sends the 1_0_0 members only when set`() = runTest {
        val route = mount("POST", configs, 201, olderConfig)
        val base = CreateFederationConfigRequest(
            clientId = "rp",
            clientSecret = Sensitive.of(io.axiam.sdk.Redaction.secret("fed-")),
            protocol = "Saml",
            provider = "idp",
        )
        client.federation.createConfig(base)
        assertFalse("allow_sha1_signatures" in route.last().json())
        assertFalse("idp_metadata_signing_cert_pem" in route.last().json())

        client.federation.createConfig(base.copy(allowSha1Signatures = false, idpMetadataSigningCertPem = "PEM"))
        assertEquals(JsonPrimitive(false), route.last().json()["allow_sha1_signatures"])
        assertEquals(JsonPrimitive("PEM"), route.last().json()["idp_metadata_signing_cert_pem"])
    }

    // -- note 8: an explicit null clears ------------------------------------------------------

    /** §27.4 rule 5's exact key-set test, for one cleared member beside one set member. */
    @Test
    fun `update_config clears with null and leaves omitted members alone`() = runTest {
        val route = mount("PUT", "$configs/$EXAMPLE_ID", 200, olderConfig)

        client.federation.updateConfig(
            EXAMPLE_ID,
            UpdateFederationConfigRequest(idpMetadataSigningCertPem = JsonNullable.Null),
        )
        assertEquals(mapOf("idp_metadata_signing_cert_pem" to JsonNull), route.last().json().toMap())

        client.federation.updateConfig(
            EXAMPLE_ID,
            UpdateFederationConfigRequest(
                buttonIcon = JsonNullable.Null,
                metadataUrl = JsonNullable.Value("https://idp.example/metadata"),
                allowSha1Signatures = true,
            ),
        )
        assertEquals(
            mapOf(
                "button_icon" to JsonNull,
                "metadata_url" to JsonPrimitive("https://idp.example/metadata"),
                "allow_sha1_signatures" to JsonPrimitive(true),
            ),
            route.last().json().toMap(),
        )

        client.federation.updateConfig(EXAMPLE_ID, UpdateFederationConfigRequest(enabled = false))
        assertEquals(setOf("enabled"), route.last().json().keys, "every clearable member omitted: kept")
    }

    /** `JsonNullable.of` is the "set to what I hold, clear when I hold nothing" spelling. */
    @Test
    fun `JsonNullable of a null clears and of a value sets`() = runTest {
        val route = mount("PUT", "$configs/$EXAMPLE_ID", 200, olderConfig)
        val held: String? = null
        client.federation.updateConfig(
            EXAMPLE_ID,
            UpdateFederationConfigRequest(appleTeamId = JsonNullable.of(held), appleKeyId = JsonNullable.of(held)),
        )
        assertEquals(mapOf("apple_team_id" to JsonNull, "apple_key_id" to JsonNull), route.last().json().toMap())
    }
}
