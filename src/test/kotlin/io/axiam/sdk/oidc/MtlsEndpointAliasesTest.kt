package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Collections

/**
 * RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
 *
 * The rule has one sentence and three named ways to get it wrong, and this
 * class is organised around them rather than around the SDK's method list:
 *
 *  * a call going over mTLS prefers the alias;
 *  * a call NOT going over mTLS keeps the top-level entry;
 *  * an ABSENT member means "no separate mTLS host", never "unsupported";
 *  * only the six listed endpoints are ever aliased — not
 *    `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`;
 *  * `issuer` is not an endpoint, does not move, and still governs `iss`
 *    validation by exact string.
 *
 * Two [MockWebServer]s stand in for the two listeners a deployment runs. The
 * §6.1 identity is a throwaway `HeldCertificate`; both servers speak plain
 * HTTP, so no handshake occurs — what is under test is *which URL the SDK
 * chooses*, which the configured identity and the document decide, not the
 * socket.
 */
class MtlsEndpointAliasesTest {

    private val tenantId = "22222222-2222-2222-2222-222222222222"

    private lateinit var conventional: MockWebServer
    private lateinit var mtls: MockWebServer
    private val conventionalHits = Collections.synchronizedList(mutableListOf<String>())
    private val mtlsHits = Collections.synchronizedList(mutableListOf<String>())

    /** The document the conventional host serves; set per test before any call. */
    private var document: () -> String = { "{}" }

    @BeforeEach
    fun setUp() {
        mtls = MockWebServer().apply {
            dispatcher = recordingDispatcher(mtlsHits)
            start()
        }
        conventional = MockWebServer().apply {
            dispatcher = recordingDispatcher(conventionalHits)
            start()
        }
    }

    @AfterEach
    fun tearDown() {
        conventional.shutdown()
        mtls.shutdown()
    }

    private fun recordingDispatcher(hits: MutableList<String>) = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.requestUrl?.encodedPath ?: ""
            if (path == "/.well-known/openid-configuration") {
                return MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json").setBody(document())
            }
            hits.add(path)
            return oauth2Response(path)
        }
    }

    /** The reply each OAuth2 endpoint's caller will accept. */
    private fun oauth2Response(path: String): MockResponse = when (path) {
        "/oauth2/device_authorization" -> MockResponse().setResponseCode(200)
            .addHeader("Content-Type", "application/json")
            .setBody(
                """{"device_code":"d","user_code":"WDJB-MJHT",""" +
                    """"verification_uri":"https://example.test/device","expires_in":30,"interval":1}""",
            )
        // RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
        "/oauth2/par" -> MockResponse().setResponseCode(201)
            .addHeader("Content-Type", "application/json")
            .setBody("""{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}""")
        "/oauth2/introspect" -> MockResponse().setResponseCode(200)
            .addHeader("Content-Type", "application/json").setBody("""{"active":true}""")
        "/oauth2/revoke" -> MockResponse().setResponseCode(200)
            .addHeader("Content-Type", "application/json").setBody("{}")
        else -> MockResponse().setResponseCode(200)
            .addHeader("Content-Type", "application/json")
            .setBody("""{"access_token":"a","token_type":"Bearer","expires_in":900}""")
    }

    /** All six aliases on the mTLS origin. */
    private fun allAliases(): String {
        val m = mtls.url("/").toString().trimEnd('/')
        return """
            {
              "token_endpoint": "$m/oauth2/token",
              "userinfo_endpoint": "$m/oauth2/userinfo",
              "revocation_endpoint": "$m/oauth2/revoke",
              "introspection_endpoint": "$m/oauth2/introspect",
              "device_authorization_endpoint": "$m/oauth2/device_authorization",
              "pushed_authorization_request_endpoint": "$m/oauth2/par"
            }
        """.trimIndent()
    }

    /** The discovery document, optionally carrying `aliasesJson` verbatim. */
    private fun discovery(aliasesJson: String? = null): String {
        val base = OidcTestKit.discoveryJson(conventional.url("/").toString())
        return if (aliasesJson == null) {
            base
        } else {
            base.trimEnd().removeSuffix("}").trimEnd() + ",\n  \"mtls_endpoint_aliases\": $aliasesJson\n}"
        }
    }

    /**
     * A client against the conventional origin, optionally carrying a §6.1
     * identity so §21.3 rule 2 applies to every call it makes.
     */
    private fun client(mtlsIdentity: Boolean): AxiamClient {
        val builder = AxiamClient.builder(conventional.url("/").toString(), tenantId)
            .oidcClientId(OidcTestKit.CLIENT_ID)
            .oidcClientSecret(OidcTestKit.CLIENT_SECRET)
        if (mtlsIdentity) {
            val identity = HeldCertificate.Builder().commonName("axiam-alias-client").build()
            builder.clientCertificate(
                identity.certificatePem().toByteArray(),
                identity.privateKeyPkcs8Pem().toByteArray(),
            )
        }
        return builder.build()
    }

    private fun conventionalOrigin() = conventional.url("/").toString().trimEnd('/')
    private fun mtlsOrigin() = mtls.url("/").toString().trimEnd('/')

    // -- The document round-trips the member --------------------------------

    @Test
    fun `discovery exposes the member when the server publishes it`() = runBlocking {
        document = { discovery(allAliases()) }
        client(mtlsIdentity = false).use {
            val configuration = it.oidcDiscover()

            val aliases = configuration.mtls_endpoint_aliases
            assertNotNull(aliases, "the member the server published must survive parsing")
            assertEquals("${mtlsOrigin()}/oauth2/token", aliases!!.token_endpoint)
            // Alongside, never instead of: the conventional entry is untouched.
            assertEquals("${conventionalOrigin()}/oauth2/token", configuration.token_endpoint)
        }
    }

    @Test
    fun `an absent member parses to null rather than failing`() = runBlocking {
        document = { discovery(null) }
        client(mtlsIdentity = true).use {
            val configuration = it.oidcDiscover()
            assertNull(
                configuration.mtls_endpoint_aliases,
                "a document with no aliases is valid, not an error",
            )
        }
    }

    // -- A call over mTLS prefers the alias ---------------------------------

    @Test
    fun `every aliasable endpoint goes to the alias host`() = runBlocking {
        document = { discovery(allAliases()) }
        client(mtlsIdentity = true).use { client ->
            client.loginClientCredentials(LoginClientCredentialsParams(tenantId = tenantId))
            client.introspect(IntrospectParams(token = Sensitive.of("t"), tenantId = tenantId))
            client.revoke(RevokeParams(token = Sensitive.of("t"), tenantId = tenantId))
            client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))
            val configuration = client.oidcDiscover()
            val request = client.oidcBegin(
                OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"),
            )
            client.oidcPar(
                OidcParParams(
                    request = request,
                    redirectUri = "https://app.example.com/cb",
                    tenantId = tenantId,
                ),
            )
        }

        assertEquals(
            listOf(
                "/oauth2/token",
                "/oauth2/introspect",
                "/oauth2/revoke",
                "/oauth2/device_authorization",
                "/oauth2/par",
            ),
            mtlsHits,
        )
        assertTrue(
            conventionalHits.isEmpty(),
            "no aliasable endpoint may reach the conventional host: $conventionalHits",
        )
    }

    // -- Consequence 1: absence means "no separate host" --------------------

    @Test
    fun `an mTLS client with no aliases keeps the top-level endpoints`() = runBlocking {
        document = { discovery(null) }
        // Not an error, and not the alias origin: a deployment running
        // client_auth = optional on one listener serves both populations at the
        // conventional endpoints and correctly publishes nothing.
        client(mtlsIdentity = true).use {
            it.introspect(IntrospectParams(token = Sensitive.of("t"), tenantId = tenantId))
        }

        assertEquals(listOf("/oauth2/introspect"), conventionalHits)
        assertTrue(mtlsHits.isEmpty())
    }

    @Test
    fun `a client not doing mTLS keeps the top-level endpoints`() = runBlocking {
        document = { discovery(allAliases()) }
        client(mtlsIdentity = false).use {
            it.revoke(RevokeParams(token = Sensitive.of("t"), tenantId = tenantId))
        }

        assertEquals(listOf("/oauth2/revoke"), conventionalHits)
        assertTrue(mtlsHits.isEmpty())
    }

    @Test
    fun `a partial alias object falls back per endpoint`() = runBlocking {
        // RFC 8705 §5 does not require an OP to alias all six, and the shape of
        // this member must never be why a client stops working: an object
        // naming only token_endpoint is a valid document, and every endpoint it
        // does not name falls back to the top-level entry.
        document = { discovery("""{"token_endpoint": "${mtlsOrigin()}/oauth2/token"}""") }
        client(mtlsIdentity = true).use { client ->
            client.loginClientCredentials(LoginClientCredentialsParams(tenantId = tenantId))
            client.introspect(IntrospectParams(token = Sensitive.of("t"), tenantId = tenantId))
        }

        assertEquals(listOf("/oauth2/token"), mtlsHits, "the one aliased endpoint uses its alias")
        assertEquals(
            listOf("/oauth2/introspect"),
            conventionalHits,
            "an endpoint the object does not name falls back to the top level",
        )
    }

    @Test
    fun `an unsupported grant is still reported when neither level names it`() = runBlocking {
        val aliasesWithoutDevice = allAliases()
            .replace(""""device_authorization_endpoint": "${mtlsOrigin()}/oauth2/device_authorization",""", "")
        document = {
            discovery(aliasesWithoutDevice).replace(
                """"device_authorization_endpoint": "${conventionalOrigin()}/oauth2/device_authorization",""",
                "",
            )
        }

        // Neither level names the endpoint, so the answer is still "this server
        // does not support the device grant" — never a URL built by concatenation.
        client(mtlsIdentity = true).use { client ->
            assertThrows<AuthError> {
                runBlocking { client.deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId)) }
            }
        }
        Unit
    }

    // -- Consequence 2: no alias is ever synthesised ------------------------

    @Test
    fun `the front-channel and jwks endpoints are never aliased`() = runBlocking {
        document = { discovery(allAliases()) }
        client(mtlsIdentity = true).use { client ->
            val configuration = client.oidcDiscover()

            // A browser sent to an mTLS host raises a native certificate-chooser
            // dialog most users cannot answer, and jwks_uri is public key
            // material that gains nothing from a handshake.
            val request = client.oidcBegin(
                OidcBeginParams(configuration = configuration, redirectUri = "https://app.example.com/cb"),
            )
            assertTrue(
                request.url.startsWith("${conventionalOrigin()}/oauth2/authorize"),
                "authorization_endpoint must stay on the conventional host: ${request.url}",
            )

            val logout = client.logoutUrl(
                LogoutUrlParams(idToken = Sensitive.of("not-a-real-token"), configuration = configuration),
            )
            assertTrue(
                logout.startsWith("${conventionalOrigin()}/oauth2/end_session"),
                "end_session_endpoint must stay on the conventional host: $logout",
            )

            assertEquals("${conventionalOrigin()}/oauth2/jwks", configuration.jwks_uri)
        }
    }

    @Test
    fun `the alias type carries only the six aliasable endpoints`() {
        // Naming them as a closed set is what makes authorization_endpoint,
        // end_session_endpoint and jwks_uri unrepresentable rather than merely
        // unused. A seventh property here would be an alias the SDK could
        // synthesise.
        val properties = MtlsEndpointAliases::class.members
            .filterIsInstance<kotlin.reflect.KProperty1<*, *>>()
            .map { it.name }
            .sorted()
        assertEquals(
            listOf(
                "device_authorization_endpoint",
                "introspection_endpoint",
                "pushed_authorization_request_endpoint",
                "revocation_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
            ),
            properties,
        )
    }

    // -- Consequence 3: issuer is never aliased -----------------------------

    @Test
    fun `the issuer does not move with the endpoints`() = runBlocking {
        document = { discovery(allAliases()) }
        client(mtlsIdentity = true).use {
            val configuration = it.oidcDiscover()

            // §12.4 rule 3 compares `iss` against THIS value by exact string,
            // for every token — including one minted at an alias endpoint. An
            // SDK that derived an expected issuer from the host it called would
            // reject every token it obtains over mTLS.
            assertEquals(conventionalOrigin(), configuration.issuer)
            assertNotEquals(mtlsOrigin(), configuration.issuer)
        }
    }
}
