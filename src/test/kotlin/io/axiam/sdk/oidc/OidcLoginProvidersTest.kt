package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * The four public "Sign in with X" operations added by contract 1.38 —
 * `ssoProviders`, `ssoStartOauth2`, `ssoCompleteOauth2` and
 * `ssoCompleteHandoff` (CONTRACT.md §12.1).
 *
 * Two kinds of assertion live here, and both are needed.
 *
 * The **wire-shape** tests read the vendored `openapi.json` and assert the
 * method, path, content type and — for `ssoProviders` — the *parameter
 * location* the server declares, then assert that what this SDK actually puts
 * on the wire matches. Asserting only against the mock would pin the SDK to the
 * test's own idea of the endpoint; asserting only against the spec would not
 * notice an SDK that agrees with the spec and calls something else.
 *
 * The **rule** tests cover the four §12.1 notes easiest to get quietly wrong:
 * note 9 (an empty provider list is a success, not a not-found), note 10
 * (`protocol` selects the start operation), note 12 (a handoff `401` is
 * terminal and is never retried) and rule 12a (a `400` from a start call is a
 * configuration refusal, not something to retry).
 */
class OidcLoginProvidersTest {

    private lateinit var server: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        val signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun findRequest(pathPrefix: String) =
        generateSequence { server.takeRequest(1, TimeUnit.SECONDS) }
            .first { it.path!!.startsWith(pathPrefix) }

    private fun client(tenant: String = TENANT_ID, orgId: UUID? = ORG_ID): AxiamClient {
        val builder = AxiamClient.builder(server.url("/").toString(), tenant)
        if (orgId != null) builder.orgId(orgId)
        return builder.oidcClientId(OidcTestKit.CLIENT_ID).build()
    }

    private companion object {
        const val TENANT_ID = "22222222-2222-2222-2222-222222222222"
        val ORG_ID: UUID = UUID.fromString("44444444-4444-4444-4444-444444444444")
        const val CONFIG_ID = "55555555-5555-5555-5555-555555555555"
        const val REDIRECT_URI = "https://app.example.com/sso-cb"

        const val PROVIDERS_PATH = "/api/v1/auth/federation/providers"
        const val OIDC_START_PATH = "/api/v1/auth/federation/oidc/start"
        const val OAUTH2_START_PATH = "/api/v1/auth/federation/oauth2/start"
        const val OAUTH2_CALLBACK_PATH = "/api/v1/auth/federation/oauth2/callback"
        const val HANDOFF_PATH = "/api/v1/auth/federation/handoff"

        const val START_BODY =
            """{"authorize_url": "https://upstream.example.com/authorize", "state": "s-1", "expires_in_secs": 600}"""
        const val SESSION_BODY =
            """{"user_id": "99999999-8888-7777-6666-555555555555",
                "session_id": "12121212-3434-5656-7878-909090909090",
                "expires_in": 900, "redirect_uri": "https://app.example.com/sso-cb"}"""

        /** The vendored spec, parsed once — these tests only read it. */
        val SPEC: JsonObject by lazy {
            Json.parseToJsonElement(File("openapi.json").readText()).jsonObject
        }

        fun operation(path: String, method: String): JsonObject =
            SPEC["paths"]!!.jsonObject[path]!!.jsonObject[method]!!.jsonObject

        fun schema(name: String): JsonObject =
            SPEC["components"]!!.jsonObject["schemas"]!!.jsonObject[name]!!.jsonObject

        fun responseRef(operation: JsonObject): String =
            operation["responses"]!!.jsonObject["200"]!!.jsonObject["content"]!!.jsonObject[
                "application/json",
            ]!!.jsonObject["schema"]!!.jsonObject["\$ref"]!!.jsonPrimitive.content

        fun requestRef(operation: JsonObject): String =
            operation["requestBody"]!!.jsonObject["content"]!!.jsonObject[
                "application/json",
            ]!!.jsonObject["schema"]!!.jsonObject["\$ref"]!!.jsonPrimitive.content

        fun provider(id: String, kind: String, protocol: String): String =
            """{"id": "$id", "provider_kind": "$kind", "display_name": "$kind",
                "protocol": "$protocol", "has_bundled_mark": true, "inherited": false}"""
    }

    // -----------------------------------------------------------------------
    // Wire shape, against openapi.json
    // -----------------------------------------------------------------------

    @Test
    fun `openapi declares ssoProviders as a GET with no request body`() {
        val op = operation(PROVIDERS_PATH, "get")
        assertNull(op["requestBody"], "ssoProviders is a GET and must have no request body (§12.1)")
        assertEquals("#/components/schemas/PublicFederationProvidersResponse", responseRef(op))
    }

    @Test
    fun `openapi declares the three POSTs with the schemas section 12_1 names`() {
        val cases = listOf(
            Triple(OAUTH2_START_PATH, "OAuth2StartRequest", "OAuth2StartResponse"),
            Triple(OAUTH2_CALLBACK_PATH, "OAuth2CallbackRequest", "SsoLoginSuccessResponse"),
            Triple(HANDOFF_PATH, "SsoHandoffRequest", "SsoLoginSuccessResponse"),
        )
        for ((path, request, response) in cases) {
            val op = operation(path, "post")
            assertEquals("#/components/schemas/$request", requestRef(op), "$path request schema")
            assertEquals("#/components/schemas/$response", responseRef(op), "$path response schema")
        }
    }

    /**
     * §12.1: the provider identifiers are **query** parameters. Asserted
     * because the neighbouring start operations take the same four in a JSON
     * body, and the two are one copy-paste apart.
     */
    @Test
    fun `openapi puts the provider identifiers in the query string`() {
        val params = operation(PROVIDERS_PATH, "get")["parameters"]!!.jsonArray
        val names = params.map { parameter ->
            val entry = parameter.jsonObject
            assertEquals(
                "query",
                entry["in"]!!.jsonPrimitive.content,
                "${entry["name"]!!.jsonPrimitive.content} must be a query parameter, not a body field",
            )
            entry["name"]!!.jsonPrimitive.content
        }.sorted()
        assertEquals(listOf("org_id", "org_slug", "tenant_id", "tenant_slug"), names)
    }

    /**
     * The six required fields plus the nullable `button_icon`, and none of the
     * configuration a narrowed admin response would have leaked (§12.1 note 9).
     */
    @Test
    fun `openapi public provider shape matches the SDK data class`() {
        val schema = schema("PublicFederationProvider")
        val required = schema["required"]!!.jsonArray.map { it.jsonPrimitive.content }.sorted()
        assertEquals(
            listOf("display_name", "has_bundled_mark", "id", "inherited", "protocol", "provider_kind"),
            required,
        )

        val properties = schema["properties"]!!.jsonObject
        val iconType = properties["button_icon"]!!.jsonObject["type"]!!.jsonArray
            .map { it.jsonPrimitive.content }
        assertTrue("null" in iconType, "button_icon must be nullable — absent for most providers")

        for (absent in listOf("client_id", "client_secret", "metadata_url", "token_endpoint")) {
            assertNull(properties[absent], "the unauthenticated response must not carry $absent")
        }
    }

    /**
     * §12.1 note 11: the verifier is generated and held server-side, so neither
     * schema carries PKCE material and neither may the SDK.
     */
    @Test
    fun `openapi oauth2 start carries no PKCE material`() {
        for (name in listOf("OAuth2StartRequest", "OAuth2StartResponse")) {
            val properties = schema(name)["properties"]!!.jsonObject
            for (pkce in listOf("code_verifier", "code_challenge", "code_challenge_method")) {
                assertNull(properties[pkce], "$name must not carry $pkce: PKCE is server-side here")
            }
        }
    }

    // -----------------------------------------------------------------------
    // ssoProviders — wire shape and §12.1 note 9
    // -----------------------------------------------------------------------

    @Test
    fun `ssoProviders sends the identifiers as query parameters and no body`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 200, """{"providers": []}""")
        // A slug-configured client, so the slug forms are what resolve.
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant")
            .orgSlug("acme-org")
            .build()

        client.ssoProviders(SsoProvidersParams(orgSlug = "other-org", tenantSlug = "engineering"))

        val request = findRequest(PROVIDERS_PATH)
        assertEquals("GET", request.method)
        val url = request.requestUrl!!
        assertEquals("other-org", url.queryParameter("org_slug"))
        assertEquals("engineering", url.queryParameter("tenant_slug"))
        assertNull(url.queryParameter("org_id"), "an unset identifier is omitted, not sent empty")
        assertEquals(0L, request.bodySize, "ssoProviders is a GET with no body (§12.1)")
    }

    @Test
    fun `ssoProviders defaults the workspace from the client configuration`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 200, """{"providers": []}""")

        client().ssoProviders()

        val url = findRequest(PROVIDERS_PATH).requestUrl!!
        assertEquals(ORG_ID.toString(), url.queryParameter("org_id"))
        assertEquals(TENANT_ID, url.queryParameter("tenant_id"))
    }

    /**
     * §12.1 note 9. The three cases the endpoint makes indistinguishable —
     * unknown organization, known-but-empty, and no workspace named — are all
     * ordinary successes. Mapping any of them to an error would restore the
     * two-valued answer the empty list removes, and with it the
     * organization-slug oracle.
     */
    @Test
    fun `an empty provider list is a success, not an error`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 200, """{"providers": []}""")
        val client = client()

        val cases = listOf(
            SsoProvidersParams(orgSlug = "no-such-organization"),
            SsoProvidersParams(orgId = ORG_ID.toString(), tenantId = TENANT_ID),
            SsoProvidersParams(),
        )
        for (params in cases) {
            assertTrue(
                client.ssoProviders(params).providers.isEmpty(),
                "an empty provider list is a normal success (§12.1 note 9)",
            )
        }
    }

    /**
     * The consequence of note 9 easiest to get wrong: unlike the start
     * operations, a request resolving no organization is **sent** rather than
     * refused client-side. A `400` for "you named nothing" against a `200 []`
     * for an unknown slug would be that same two-valued answer by another
     * route.
     */
    @Test
    fun `ssoProviders sends the request even with no organization context`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 200, """{"providers": []}""")
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant").build()

        // ssoStart refuses this same client, client-side.
        assertThrows(AuthError::class.java) {
            runBlocking { client.ssoStart(SsoStartParams(CONFIG_ID, REDIRECT_URI)) }
        }
        assertTrue(client.ssoProviders().providers.isEmpty())
        assertEquals(PROVIDERS_PATH, findRequest(PROVIDERS_PATH).path!!.substringBefore('?'))
    }

    @Test
    fun `ssoProviders maps every field including the nullable button icon`(): Unit = runBlocking {
        dispatcher.onJson(
            PROVIDERS_PATH,
            200,
            """{"providers": [
                {"id": "11111111-1111-1111-1111-111111111111", "provider_kind": "google",
                 "display_name": "Google", "protocol": "OidcConnect", "has_bundled_mark": true,
                 "inherited": true, "button_icon": null},
                {"id": "22222222-2222-2222-2222-222222222222", "provider_kind": "generic_oauth2",
                 "display_name": "Acme SSO", "protocol": "OAuth2", "has_bundled_mark": false,
                 "inherited": false, "button_icon": "data:image/png;base64,iVBORw0KGgo="}]}""",
        )

        val providers = client().ssoProviders().providers
        assertEquals(2, providers.size)

        val google = providers[0]
        assertEquals("google", google.providerKind)
        assertEquals(PROTOCOL_OIDC_CONNECT, google.protocol)
        assertTrue(google.hasBundledMark)
        // Reported so an admin surface can show that a provider is not the
        // tenant's to edit; nothing here computes it (§12.1 note 13).
        assertTrue(google.inherited)
        assertNull(google.buttonIcon, "button_icon is absent for most providers")

        val acme = providers[1]
        assertEquals(PROTOCOL_OAUTH2, acme.protocol)
        assertFalse(acme.hasBundledMark)
        assertEquals("data:image/png;base64,iVBORw0KGgo=", acme.buttonIcon)
    }

    // -----------------------------------------------------------------------
    // §12.1 note 10 — protocol selects the start operation
    // -----------------------------------------------------------------------

    /**
     * All three branches, asserted on which endpoint the resulting call
     * reached.
     *
     * `provider_kind` is deliberately misleading in this fixture: the `Saml`
     * row is `google`, the kind whose OIDC connector everybody assumes. A
     * dispatch that read the kind would send it to the OIDC start endpoint and
     * be caught by the per-endpoint call counts.
     */
    @Test
    fun `protocol selects the start operation for all three branches`(): Unit = runBlocking {
        dispatcher.onJson(
            PROVIDERS_PATH,
            200,
            """{"providers": [
                ${provider("11111111-1111-1111-1111-111111111111", "microsoft", PROTOCOL_OIDC_CONNECT)},
                ${provider("22222222-2222-2222-2222-222222222222", "github", PROTOCOL_OAUTH2)},
                ${provider("33333333-3333-3333-3333-333333333333", "google", PROTOCOL_SAML)}]}""",
        )
        var oidcStarts = 0
        var oauth2Starts = 0
        dispatcher.on(OIDC_START_PATH) {
            oidcStarts++
            okhttp3.mockwebserver.MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json").setBody(START_BODY)
        }
        dispatcher.on(OAUTH2_START_PATH) {
            oauth2Starts++
            okhttp3.mockwebserver.MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json").setBody(START_BODY)
        }
        val client = client()

        var samlSeen = false
        for (p in client.ssoProviders().providers) {
            when (p.protocol) {
                PROTOCOL_OIDC_CONNECT -> client.ssoStart(SsoStartParams(p.id, REDIRECT_URI))
                PROTOCOL_OAUTH2 -> client.ssoStartOauth2(SsoStartOauth2Params(p.id, REDIRECT_URI))
                // Saml goes to the SAML login endpoint, which §12.1 note 10
                // says is NOT a §12 vocabulary operation. The branch exists so
                // a Saml provider is never quietly handed to one of the other
                // two.
                PROTOCOL_SAML -> samlSeen = true
                else -> throw AssertionError("unknown protocol ${p.protocol}")
            }
        }

        assertTrue(samlSeen, "the Saml branch must be reachable")
        assertEquals(1, oidcStarts, "OidcConnect must reach the OIDC start endpoint exactly once")
        assertEquals(1, oauth2Starts, "OAuth2 must reach the OAuth2 start endpoint exactly once")
    }

    // -----------------------------------------------------------------------
    // ssoStartOauth2
    // -----------------------------------------------------------------------

    @Test
    fun `ssoStartOauth2 posts the OAuth2StartRequest body and sends no PKCE`(): Unit = runBlocking {
        dispatcher.onJson(OAUTH2_START_PATH, 200, START_BODY)

        val result = client().ssoStartOauth2(SsoStartOauth2Params(CONFIG_ID, REDIRECT_URI))
        assertEquals("s-1", result.state)
        assertEquals(600L, result.expiresInSecs)

        val request = findRequest(OAUTH2_START_PATH)
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"federation_config_id\":\"$CONFIG_ID\""))
        assertTrue(body.contains("\"redirect_uri\":\"$REDIRECT_URI\""))
        assertTrue(body.contains("\"tenant_id\":\"$TENANT_ID\""))
        assertTrue(body.contains(ORG_ID.toString()))
        // §12.1 note 11: the verifier is server-side. Its absence is the contract.
        for (pkce in listOf("code_verifier", "code_challenge", "code_challenge_method")) {
            assertFalse(body.contains(pkce), "the SDK must not send $pkce")
        }
    }

    @Test
    fun `ssoStartOauth2 refuses client-side, with no wire call, without org context`(): Unit = runBlocking {
        val client = AxiamClient.builder(server.url("/").toString(), "acme-tenant").build()

        val error = assertThrows(AuthError::class.java) {
            runBlocking { client.ssoStartOauth2(SsoStartOauth2Params(CONFIG_ID, REDIRECT_URI)) }
        }
        assertTrue(error.message!!.contains("organization context"))
        assertEquals(0, server.requestCount, "no wire call may be made")
    }

    // -----------------------------------------------------------------------
    // §12.1 rule 12a — a 400 from a start call is a configuration refusal
    // -----------------------------------------------------------------------

    /**
     * On the SAML and Apple flows the identity provider never validates the SPA
     * `redirect_uri`, so the server confines it to its own issuer origin plus
     * `AXIAM__AUTH__SSO_SPA_ORIGINS` and answers `400` otherwise.
     *
     * That `400` is a **configuration** refusal — §2's `400` row, whose
     * taxonomy member in this SDK is [NetworkError], as distinct from the
     * [AuthError] an unknown workspace gets. It must not be retried: the
     * deployment will refuse the same origin every time.
     *
     * Asserted on both start operations, because Apple arrives over the OIDC
     * one and a caller can reach the refusal from either entry point.
     */
    @Test
    fun `a 400 from either start call is a configuration error and is not retried`(): Unit = runBlocking {
        var oidcCalls = 0
        var oauth2Calls = 0
        dispatcher.on(OIDC_START_PATH) {
            oidcCalls++
            okhttp3.mockwebserver.MockResponse().setResponseCode(400).setBody("redirect_uri origin refused")
        }
        dispatcher.on(OAUTH2_START_PATH) {
            oauth2Calls++
            okhttp3.mockwebserver.MockResponse().setResponseCode(400).setBody("redirect_uri origin refused")
        }
        val client = client()

        assertThrows(NetworkError::class.java) {
            runBlocking { client.ssoStart(SsoStartParams(CONFIG_ID, "https://attacker.example/")) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.ssoStartOauth2(SsoStartOauth2Params(CONFIG_ID, "https://attacker.example/")) }
        }

        assertEquals(1, oidcCalls, "rule 12a: the refusal must not be retried")
        assertEquals(1, oauth2Calls, "rule 12a: the refusal must not be retried")
    }

    /**
     * A `401` is the uniform "unknown workspace or provider" answer, and a
     * *different* taxonomy member from the rule-12a `400`. Asserted so the two
     * cannot quietly collapse into one.
     */
    @Test
    fun `a 401 from a start call stays an AuthError`(): Unit = runBlocking {
        dispatcher.onJson(OAUTH2_START_PATH, 401, """{"message": "unauthorized"}""")

        assertThrows(AuthError::class.java) {
            runBlocking { client().ssoStartOauth2(SsoStartOauth2Params(CONFIG_ID, REDIRECT_URI)) }
        }
    }

    // -----------------------------------------------------------------------
    // The two completions, and §12.1 note 12
    // -----------------------------------------------------------------------

    @Test
    fun `ssoCompleteOauth2 posts state and code and maps the success body`(): Unit = runBlocking {
        dispatcher.onJson(OAUTH2_CALLBACK_PATH, 200, SESSION_BODY)

        val result = client().ssoCompleteOauth2(SsoCompleteOauth2Params(state = "abc", code = "provider-code"))

        assertEquals("99999999-8888-7777-6666-555555555555", result.userId)
        assertEquals(900L, result.expiresIn)
        assertEquals(REDIRECT_URI, result.redirectUri)

        val body = findRequest(OAUTH2_CALLBACK_PATH).body.readUtf8()
        assertTrue(body.contains("\"state\":\"abc\""))
        assertTrue(body.contains("\"code\":\"provider-code\""))
    }

    @Test
    fun `ssoCompleteHandoff posts just the code`(): Unit = runBlocking {
        dispatcher.onJson(HANDOFF_PATH, 200, SESSION_BODY)

        val result = client().ssoCompleteHandoff(SsoCompleteHandoffParams(code = "handoff-code"))
        assertEquals("12121212-3434-5656-7878-909090909090", result.sessionId)

        assertEquals("""{"code":"handoff-code"}""", findRequest(HANDOFF_PATH).body.readUtf8())
    }

    /**
     * §12.1 note 12. Unknown, expired and already-redeemed all answer the same
     * `401`, on purpose. The code is spent either way, so a retry cannot
     * succeed and would only widen the window in which it sits in a log.
     */
    @Test
    fun `a handoff 401 is terminal and is not retried`(): Unit = runBlocking {
        var calls = 0
        dispatcher.on(HANDOFF_PATH) {
            calls++
            okhttp3.mockwebserver.MockResponse().setResponseCode(401).setBody("unauthorized")
        }

        assertThrows(AuthError::class.java) {
            runBlocking {
                client().ssoCompleteHandoff(SsoCompleteHandoffParams("spent-or-expired-or-never-existed"))
            }
        }
        assertEquals(1, calls, "the redemption must not be retried: the code is gone either way")
    }

    /**
     * The two values a caller codes against: it reads the code out of
     * `?axiam_handoff=` and has 60 seconds to spend it.
     */
    @Test
    fun `the handoff parameter and TTL are what the contract says`() {
        assertEquals("axiam_handoff", HANDOFF_QUERY_PARAM)
        assertEquals(60L, HANDOFF_CODE_TTL_SECONDS)
    }

    /** A non-2xx from the providers endpoint still maps through the §2 taxonomy. */
    @Test
    fun `a 500 from ssoProviders maps to NetworkError`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 500, """{"message": "boom"}""")

        assertThrows(NetworkError::class.java) {
            runBlocking { client().ssoProviders() }
        }
    }

    /** An absent `providers` key is an empty list, not a crash. */
    @Test
    fun `a body without a providers key reads as an empty list`(): Unit = runBlocking {
        dispatcher.onJson(PROVIDERS_PATH, 200, """{}""")

        assertTrue(client().ssoProviders().providers.isEmpty())
    }
}
