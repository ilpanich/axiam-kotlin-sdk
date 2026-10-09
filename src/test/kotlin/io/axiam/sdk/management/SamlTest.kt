package io.axiam.sdk.management

import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.AcsEndpoint
import io.axiam.sdk.management.models.IssueSamlIdpCredential
import io.axiam.sdk.management.models.ParseSamlSpMetadata
import io.axiam.sdk.management.models.SamlBinding
import io.axiam.sdk.management.models.SamlIdpCredential
import io.axiam.sdk.management.models.SamlIdpCredentialStatus
import io.axiam.sdk.management.models.SamlIdpInfo
import io.axiam.sdk.management.models.SamlIdpSlot
import io.axiam.sdk.management.models.SamlServiceProvider
import io.axiam.sdk.management.models.SamlServiceProviderInput
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/** The `saml` management namespace — CONTRACT.md §29.8's eight required tests. */
class SamlTest : ManagementTestBase() {

    private val saml = "/api/v1/tenants/$TENANT_ID/saml"

    private fun spBody(extra: String = "", binding: String = "http_post"): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","enabled":true,
            "display_name":"Payroll","entity_id":"https://payroll.example/sp",
            "acs_urls":[{"url":"https://payroll.example/acs","binding":"$binding","index":0,"is_default":true}],
            "slo_url":null,"slo_binding":null,"name_id_format":"persistent",
            "sign_responses":true,"encrypt_assertions":false,
            "sp_signing_cert_pem":null,"sp_encryption_cert_pem":null,
            "want_authn_requests_signed":false,"allow_idp_initiated":false,
            "attribute_mappings":[],"allowed_groups":[],
            "created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"$extra}"""

    private fun credentialBody(status: String, extra: String = ""): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","issuer_ca_id":"${UUID.randomUUID()}",
            "certificate_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "serial":"0a1b","fingerprint":"${"ab".repeat(32)}",
            "not_before":"2026-10-04T00:00:00Z","not_after":"2027-10-04T00:00:00Z",
            "status":"$status","created_at":"2026-10-04T00:00:00Z","retired_at":null$extra}"""

    private fun input() = SamlServiceProviderInput(
        acsUrls = listOf(AcsEndpoint(SamlBinding.HTTP_POST, 0, true, "https://payroll.example/acs")),
        displayName = "Payroll",
        entityId = "https://payroll.example/sp",
    )

    private fun decode(body: String): SamlServiceProvider =
        ManagementTransport.READER.decodeFromString(SamlServiceProvider.serializer(), body)

    // -- 1. Replacement ----------------------------------------------------------

    @Test
    fun `update_service_provider puts the whole registration`() = runTest {
        val id = UUID.randomUUID()
        val route = mount("PUT", "$saml/service-providers/$id", 200, spBody())
        // The read-modify-write form: every member of a read carried over.
        val body = decode(spBody()).toInput().copy(displayName = "Payroll (EU)")
        val sp = client.saml.updateServiceProvider(id, body)
        assertEquals("https://payroll.example/sp", sp.entityId)

        val sent = route.last().json()
        for (member in listOf(
            "acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings", "display_name",
            "enabled", "encrypt_assertions", "entity_id", "name_id_format", "sign_responses",
            "want_authn_requests_signed",
        )) {
            assertTrue(member in sent, "$member not sent")
        }
        assertEquals(JsonPrimitive("Payroll (EU)"), sent["display_name"])
        // display_name, entity_id and acs_urls are constructor parameters with
        // no default: an input without them does not compile.
    }

    // -- 2. No signing switch, open decoding -----------------------------------------

    @Test
    fun `sign_assertions does not exist and unknown values decode`() = runTest {
        val id = UUID.randomUUID()
        mount(
            "GET", "$saml/service-providers/$id", 200,
            spBody(""","sign_assertions":false,"some_future_member":1""", binding = "http_artifact"),
        )
        val route = mount("PUT", "$saml/service-providers/$id", 200, spBody())
        val sp = client.saml.getServiceProvider(id)
        assertEquals(SamlBinding.UNKNOWN, sp.acsUrls[0].binding)
        assertFalse(SamlServiceProvider::class.members.any { it.name == "signAssertions" })
        assertFalse(SamlServiceProviderInput::class.members.any { it.name == "signAssertions" })

        // An unknown enum value decodes, but is never written back as-is:
        // replace it before writing.
        val input = sp.toInput().let { it.copy(acsUrls = listOf(it.acsUrls[0].copy(binding = SamlBinding.HTTP_POST))) }
        client.saml.updateServiceProvider(id, input)
        val sent = route.last().json()
        assertFalse("sign_assertions" in sent)
        assertFalse("some_future_member" in sent)
    }

    // -- 3. Draft round trip ---------------------------------------------------------------

    @Test
    fun `parse_sp_metadata sends exactly one member and the draft creates`() = runTest {
        val draft = """{"service_provider":{"display_name":"Imported","entity_id":"https://imported.example/sp",
            "acs_urls":[{"url":"https://imported.example/acs","binding":"http_post","index":1,"is_default":false}],
            "want_authn_requests_signed":true,
            "sp_signing_cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
            "signing_certificate_fingerprint":"${"cd".repeat(32)}",
            "encryption_certificate_fingerprint":null,
            "warnings":["the metadata's signature was not evaluated"]}"""
        val parsed = mount("POST", "$saml/parse-sp-metadata", 200, draft)
        val created = mount("POST", "$saml/service-providers", 201, spBody())

        val fromUrl = client.saml.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://imported.example/metadata"))
        client.saml.parseSpMetadata(ParseSamlSpMetadata.fromXml("<EntityDescriptor/>"))
        for (bothOrNeither in listOf(
            ParseSamlSpMetadata(metadataUrl = "https://a", metadataXml = "<x/>"),
            ParseSamlSpMetadata(),
        )) {
            assertThrows<ValidationError> { runBlocking { client.saml.parseSpMetadata(bothOrNeither) } }
        }
        assertEquals(2, parsed.calls(), "the refused calls sent nothing")
        assertEquals(
            JsonObject(mapOf("metadata_url" to JsonPrimitive("https://imported.example/metadata"))),
            parsed.requests[0].json(),
        )
        assertEquals(JsonObject(mapOf("metadata_xml" to JsonPrimitive("<EntityDescriptor/>"))), parsed.requests[1].json())

        client.saml.createServiceProvider(fromUrl.serviceProvider)
        assertEquals(
            Json.parseToJsonElement(draft).jsonObject["service_provider"],
            created.last().json(),
            "the draft is sent unchanged",
        )
    }

    // -- 4. Credentials carry no key ----------------------------------------------------------

    @Test
    fun `a credential has no key member and promotion may retire nothing`() = runTest {
        val leaked = "-----BEGIN " + "PRIVATE KEY-----" + UUID.randomUUID().toString().replace("-", "")
        val id = UUID.randomUUID()
        mount(
            "POST", "$saml/idp-credentials/$id/retire", 200,
            credentialBody("retired", ""","private_key_pem":"$leaked""""),
        )
        mount(
            "POST", "$saml/idp-credentials/$id/promote", 200,
            """{"active":${credentialBody("active")},"retired":null}""",
        )
        val credential = client.saml.retireIdpCredential(id)
        for (rendering in listOf(
            credential.toString(),
            ManagementTransport.READER.encodeToString(SamlIdpCredential.serializer(), credential),
        )) {
            assertFalse(rendering.contains(leaked), "the leaked key value appears in a rendering")
            assertFalse(rendering.contains("private_key_pem"), "the member name appears in a rendering")
        }
        assertFalse(SamlIdpCredential::class.members.any { it.name.contains("privateKey", ignoreCase = true) })
        val promotion = client.saml.promoteIdpCredential(id)
        assertNull(promotion.retired)
        assertEquals(SamlIdpCredentialStatus.ACTIVE, promotion.active.status)
    }

    // -- 5. Pagination --------------------------------------------------------------------------

    @Test
    fun `service providers page with search and credentials are a plain list`() = runTest {
        val page0 = """{"items":[${spBody()}],"total":2,"offset":0,"limit":1}"""
        val page1 = """{"items":[${spBody()}],"total":2,"offset":1,"limit":1}"""
        val route = mountSequence("GET", "$saml/service-providers", 200, listOf(page0, page0, page1))
        mount("GET", "$saml/idp-credentials", 200, "[${credentialBody("next")},${credentialBody("active")}]")

        val page = client.saml.listServiceProviders(PageRequest.matching(1, "payroll"))
        assertEquals(2, page.total)
        val all = client.saml.listServiceProvidersAll(PageRequest.matching(1, "payroll"))
        assertEquals(2, all.size)
        assertEquals(3, route.calls(), "one page, then a two-page walk")
        for (request in route.requests) {
            assertEquals("payroll", request.query["search"], "search is carried on every page")
        }
        val credentials: List<SamlIdpCredential> = client.saml.listIdpCredentials()
        assertEquals(2, credentials.size)
    }

    // -- 6. No retry ------------------------------------------------------------------------------

    @Test
    fun `none of the seven writes is retried on 503`() = runTest {
        val id = UUID.randomUUID()
        val routes = listOf(
            mount("POST", "$saml/service-providers", 503, ""),
            mount("PUT", "$saml/service-providers/$id", 503, ""),
            mount("DELETE", "$saml/service-providers/$id", 503, ""),
            mount("POST", "$saml/parse-sp-metadata", 503, ""),
            mount("POST", "$saml/idp-credentials", 503, ""),
            mount("POST", "$saml/idp-credentials/$id/promote", 503, ""),
            mount("POST", "$saml/idp-credentials/$id/retire", 503, ""),
        )
        val s = client.saml // the default client: retry ENABLED
        assertThrows<NetworkError> { runBlocking { s.createServiceProvider(input()) } }
        assertThrows<NetworkError> { runBlocking { s.updateServiceProvider(id, input()) } }
        assertThrows<NetworkError> { runBlocking { s.deleteServiceProvider(id) } }
        assertThrows<NetworkError> { runBlocking { s.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://m")) } }
        assertThrows<NetworkError> {
            runBlocking { s.issueIdpCredential(IssueSamlIdpCredential(UUID.randomUUID(), SamlIdpSlot.NEXT)) }
        }
        assertThrows<NetworkError> { runBlocking { s.promoteIdpCredential(id) } }
        assertThrows<NetworkError> { runBlocking { s.retireIdpCredential(id) } }
        for (route in routes) assertEquals(1, route.calls(), "exactly one request")
    }

    // -- 7. Errors --------------------------------------------------------------------------------

    @Test
    fun `statuses map per section 2`() = runTest {
        val id = UUID.randomUUID()
        mount("POST", "$saml/service-providers", 409, """{"error":"conflict","message":"entity_id"}""")
        mount(
            "PUT", "$saml/service-providers/$id", 400,
            """{"error":"validation_error","message":"entity_id is immutable: register a new service provider"}""",
        )
        mount("GET", "$saml/service-providers/$id", 404, """{"error":"not_found","message":"no"}""")
        mount("POST", "$saml/idp-credentials/$id/promote", 409, """{"error":"conflict","message":"not next"}""")
        mount("POST", "$saml/parse-sp-metadata", 503, """{"error":"service_unavailable","message":"saml"}""")

        val s = client.saml
        assertThrows<ConflictError> { runBlocking { s.createServiceProvider(input()) } }
        val e = assertThrows<ValidationError> { runBlocking { s.updateServiceProvider(id, input()) } }
        assertTrue(e.message.orEmpty().contains("immutable"))
        assertThrows<NotFoundError> { runBlocking { s.getServiceProvider(id) } }
        assertThrows<ConflictError> { runBlocking { s.promoteIdpCredential(id) } }
        val unavailable = assertThrows<NetworkError> {
            runBlocking { s.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://m")) }
        }
        assertFalse(unavailable is ValidationError)
    }

    // -- 8. Readiness is read, not cached -------------------------------------------------------------

    @Test
    fun `get_idp is never cached and keeps null apart from absent`() = runTest {
        val active = UUID.randomUUID()
        // The configured tenant, in the path: getIdp takes no tenant argument.
        val route = mount(
            "GET", "$saml/idp", 200,
            """{"tenant_id":"$TENANT_ID","saml_available":true,"saml_idp_enabled":false,
                "metadata_served":true,"entity_id":"https://iam.example/saml/v2/t",
                "metadata_url":"https://iam.example/saml/v2/t/metadata",
                "sso_url":"https://iam.example/saml/v2/t/sso","slo_url":"https://iam.example/saml/v2/t/slo",
                "active_credential_id":"$active","next_credential_id":null}""",
        )
        val info = client.saml.getIdp()
        client.saml.getIdp()
        assertEquals(2, route.calls(), "two calls, two requests")
        assertEquals(JsonNullable.Value(active), info.activeCredentialId)
        assertEquals(JsonNullable.Null, info.nextCredentialId, "null, not absent")
        assertTrue(info.samlAvailable && info.metadataServed && !info.samlIdpEnabled)

        val without = ManagementTransport.READER.decodeFromString(
            SamlIdpInfo.serializer(),
            """{"tenant_id":"$TENANT_ID","saml_available":true,"saml_idp_enabled":false,
                "metadata_served":false,"entity_id":"e","metadata_url":"m","sso_url":"s","slo_url":"l"}""",
        )
        assertEquals(JsonNullable.Absent, without.nextCredentialId, "absent stays absent")
    }
}
