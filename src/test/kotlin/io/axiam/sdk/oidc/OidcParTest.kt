package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
 *
 * Two assertions carry the section:
 *
 * - `a successful push answers 201` — RFC 9126 §2.2 specifies *Created*. A
 *   success predicate written `== 200` passes every other test in this file and
 *   treats every real push as a failure.
 * - `the redirect url carries exactly two parameters` — the server refuses a
 *   request that mixes a `request_uri` with inline authorization parameters
 *   rather than merging them, and merging is where parameter confusion lives
 *   (§26.2 rule 2).
 */
class OidcParTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private companion object {
        const val TENANT_ID = "22222222-2222-2222-2222-222222222222"
        const val REDIRECT_URI = "https://app.example.com/callback"
        const val REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"
    }

    private fun parResponse() = MockResponse()
        .setResponseCode(201)
        .addHeader("Content-Type", "application/json")
        .setBody("""{"request_uri":"$REQUEST_URI","expires_in":90}""")

    private fun form(body: String): Map<String, String> =
        body.split("&").associate { pair ->
            val eq = pair.indexOf('=')
            URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8) to
                URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)
        }

    /** Discovery, then `oidcBegin`, leaving PAR as the next call. */
    private suspend fun begin(client: AxiamClient): Pair<OidcConfiguration, AuthorizationRequest> {
        server.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.discoveryJson(server.url("/").toString())),
        )
        val config = client.oidcDiscover()
        server.takeRequest()
        return config to client.oidcBegin(OidcBeginParams(config, REDIRECT_URI))
    }

    private fun client(secret: String? = "s3cret") =
        OidcTestKit.clientFor(server, clientId = "app", clientSecret = secret, tenantId = TENANT_ID)

    // -----------------------------------------------------------------------
    // §26.1 — the push
    // -----------------------------------------------------------------------

    @Test
    fun `a successful push answers 201`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            val pushed = client.oidcPar(
                OidcParParams(begun, REDIRECT_URI, config, scope = "openid profile"),
            )

            assertEquals(REQUEST_URI, pushed.requestUri.expose())
            assertEquals(90L, pushed.expiresIn)
        }
    }

    @Test
    fun `the push goes to the discovered endpoint with the tenant query`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config))

            val request = server.takeRequest()
            assertEquals("POST", request.method)
            val url = request.requestUrl!!
            assertEquals("/oauth2/par", url.encodedPath)
            // §12.1 rule 2: the /oauth2 endpoints carry the tenant as a query
            // parameter, and PAR is one of those.
            assertEquals(TENANT_ID, url.queryParameter("tenant_id"))
        }
    }

    @Test
    fun `the push carries everything oidcBegin computed and generates nothing new`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            val pushed = client.oidcPar(
                OidcParParams(begun, REDIRECT_URI, config, scope = "openid profile"),
            )

            val fields = form(server.takeRequest().body.readUtf8())
            // §26.2 rule 1: no second generator. state, nonce and the PKCE pair
            // all come from the AuthorizationRequest that was pushed — two
            // sources for any of them are two things that can disagree.
            assertEquals(begun.state, fields["state"])
            assertEquals(begun.nonce, fields["nonce"])
            assertEquals(begun.state, pushed.state)
            assertEquals(begun.nonce, pushed.nonce)
            assertEquals(begun.codeVerifier.expose(), pushed.codeVerifier.expose())

            assertEquals("app", fields["client_id"])
            assertEquals("code", fields["response_type"])
            assertEquals(REDIRECT_URI, fields["redirect_uri"])
            assertEquals("openid profile", fields["scope"])
            assertEquals("S256", fields["code_challenge_method"])
            assertEquals(
                OidcPkce.computeCodeChallenge(begun.codeVerifier.expose()),
                fields["code_challenge"],
            )
        }
    }

    @Test
    fun `a confidential client authenticates the push`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config))

            assertEquals("s3cret", form(server.takeRequest().body.readUtf8())["client_secret"])
        }
    }

    @Test
    fun `a public client pushes without a secret`() = runBlocking {
        client(secret = null).use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config))

            assertNull(form(server.takeRequest().body.readUtf8())["client_secret"])
        }
    }

    @Test
    fun `openid is added to a scope that omits it`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config, scope = "profile email"))

            val scope = form(server.takeRequest().body.readUtf8())["scope"]!!
            assertTrue(
                scope.split(" ").contains("openid"),
                "an OIDC request without the openid scope is not an OIDC request: $scope",
            )
        }
    }

    @Test
    fun `par discovers when given no configuration`() = runBlocking {
        client().use { client ->
            val (_, begun) = begin(client)
            server.enqueue(parResponse())

            // The document is cached per origin (§12.3 rule 6), so passing null
            // costs no second fetch.
            client.oidcPar(OidcParParams(begun, REDIRECT_URI, configuration = null))

            assertEquals("/oauth2/par", server.takeRequest().requestUrl!!.encodedPath)
            assertEquals(2, server.requestCount)
        }
    }

    @Test
    fun `an explicit tenant overrides the client tenant`() = runBlocking {
        val other = "44444444-4444-4444-4444-444444444444"
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config, tenantId = other))

            assertEquals(other, server.takeRequest().requestUrl!!.queryParameter("tenant_id"))
        }
    }

    // -----------------------------------------------------------------------
    // §26.2 rule 2 — the redirect URL
    // -----------------------------------------------------------------------

    @Test
    fun `the redirect url carries exactly two parameters`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            val pushed = client.oidcPar(OidcParParams(begun, REDIRECT_URI, config, scope = "openid"))

            val url = pushed.url.toHttpUrl()
            assertEquals(
                setOf("client_id", "request_uri"),
                url.queryParameterNames,
                "the server REFUSES a request_uri mixed with inline parameters rather than " +
                    "merging them — re-adding scope/state/redirect_uri here restores the " +
                    "parameter-confusion attack (§26.2 rule 2)",
            )
            assertEquals("app", url.queryParameter("client_id"))
            assertEquals(REQUEST_URI, url.queryParameter("request_uri"))
            assertEquals("/oauth2/authorize", url.encodedPath)
        }
    }

    @Test
    fun `the redirect url drops any query the discovered endpoint carried`() = runBlocking {
        client().use { client ->
            val origin = server.url("/").toString().trimEnd('/')
            // An authorization_endpoint that already carries a query is legal,
            // and its parameters are exactly the ones rule 2 forbids travelling
            // alongside a request_uri.
            val config = OidcConfiguration(
                issuer = origin,
                authorization_endpoint = "$origin/oauth2/authorize?audience=legacy&scope=all",
                token_endpoint = "$origin/oauth2/token",
                userinfo_endpoint = "$origin/oauth2/userinfo",
                jwks_uri = "$origin/oauth2/jwks",
                revocation_endpoint = "$origin/oauth2/revoke",
                introspection_endpoint = "$origin/oauth2/introspect",
                response_types_supported = listOf("code"),
                subject_types_supported = listOf("public"),
                id_token_signing_alg_values_supported = listOf("EdDSA"),
                scopes_supported = listOf("openid"),
                token_endpoint_auth_methods_supported = listOf("client_secret_post"),
                claims_supported = listOf("sub"),
                grant_types_supported = listOf("authorization_code"),
                pushed_authorization_request_endpoint = "$origin/oauth2/par",
            )
            val begun = client.oidcBegin(OidcBeginParams(config, REDIRECT_URI))
            server.enqueue(parResponse())

            val pushed = client.oidcPar(OidcParParams(begun, REDIRECT_URI, config, scope = "openid"))

            assertEquals(setOf("client_id", "request_uri"), pushed.url.toHttpUrl().queryParameterNames)
        }
    }

    // -----------------------------------------------------------------------
    // refusals
    // -----------------------------------------------------------------------

    @Test
    fun `a server without par is refused client-side with no wire call`() = runBlocking {
        client().use { client ->
            server.enqueue(
                MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.discoveryJsonWithoutOptionalEndpoints(server.url("/").toString())),
            )
            val config = client.oidcDiscover()
            server.takeRequest()
            val begun = client.oidcBegin(OidcBeginParams(config, REDIRECT_URI))
            val before = server.requestCount

            val error = assertThrows(AuthError::class.java) {
                runBlocking { client.oidcPar(OidcParParams(begun, REDIRECT_URI, config)) }
            }
            assertTrue(error.message!!.contains("pushed_authorization_request_endpoint"))

            // §12.7.2 rule 1's discipline: no URL is concatenated onto the issuer.
            assertEquals(0, server.requestCount - before)
        }
    }

    @Test
    fun `an oauth error body becomes an OAuthProtocolError`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(
                MockResponse().setResponseCode(400)
                    .addHeader("Content-Type", "application/json")
                    .setBody(
                        """{"error":"invalid_request_uri","error_description":"bad request_uri"}""",
                    ),
            )

            val error = assertThrows(OAuthProtocolError::class.java) {
                runBlocking { client.oidcPar(OidcParParams(begun, REDIRECT_URI, config)) }
            }
            assertEquals("invalid_request_uri", error.error)
        }
    }

    @Test
    fun `a 503 is not retried`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            val before = server.requestCount
            server.enqueue(MockResponse().setResponseCode(503).setBody("{}"))

            assertThrows(NetworkError::class.java) {
                runBlocking { client.oidcPar(OidcParParams(begun, REDIRECT_URI, config)) }
            }

            // §26.2 rule 4: a POST that creates server state falls outside
            // §16.2's read-only eligibility. The safe recovery is a fresh push,
            // which cannot double-consume anything.
            assertEquals(1, server.requestCount - before, "the push must not be retried")
        }
    }

    @Test
    fun `a response with no request_uri is a network error`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(
                MockResponse().setResponseCode(201)
                    .addHeader("Content-Type", "application/json")
                    .setBody("""{"expires_in":90}"""),
            )

            assertThrows(NetworkError::class.java) {
                runBlocking { client.oidcPar(OidcParParams(begun, REDIRECT_URI, config)) }
            }
        }
        Unit
    }

    // -----------------------------------------------------------------------
    // §26.5 / discovery
    // -----------------------------------------------------------------------

    @Test
    fun `the request_uri is sensitive`() = runBlocking {
        client().use { client ->
            val (config, begun) = begin(client)
            server.enqueue(parResponse())

            val pushed = client.oidcPar(OidcParParams(begun, REDIRECT_URI, config))

            // Between the push and the redirect it is a bearer handle to a
            // fully-formed authorization request (§26.5). The URL it goes into
            // is not secret; the bare handle in a log line is.
            assertEquals("[SENSITIVE]", pushed.requestUri.toString())
            // The URL still carries it — percent-encoded, since a urn: is full
            // of characters a query parameter must escape.
            assertEquals(REQUEST_URI, pushed.url.toHttpUrl().queryParameter("request_uri"))
        }
    }

    @Test
    fun `discovery exposes the pushed authorization request endpoint`() = runBlocking {
        client().use { client ->
            server.enqueue(
                MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.discoveryJson(server.url("/").toString())),
            )
            val config = client.oidcDiscover()
            val origin = server.url("/").toString().trimEnd('/')
            assertEquals("$origin/oauth2/par", config.pushed_authorization_request_endpoint)
        }
    }

    @Test
    fun `a discovery document without par parses with a null endpoint`() = runBlocking {
        client().use { client ->
            server.enqueue(
                MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.discoveryJsonWithoutOptionalEndpoints(server.url("/").toString())),
            )
            // Absent, not empty: §26 is optional, and an SDK that synthesized
            // an endpoint here would POST a fully-formed authorization request
            // at a 404.
            assertNull(client.oidcDiscover().pushed_authorization_request_endpoint)
        }
    }
}
