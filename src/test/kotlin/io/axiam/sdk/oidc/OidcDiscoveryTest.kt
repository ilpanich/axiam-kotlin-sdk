package io.axiam.sdk.oidc

import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicInteger
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OidcDiscoveryTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `oidcDiscover fetches and returns the parsed discovery document`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val doc = client.oidcDiscover()
        assertEquals(server.url("/").toString().trimEnd('/'), doc.issuer)
        assertEquals("${doc.issuer}/oauth2/token", doc.token_endpoint)
        assertEquals("${doc.issuer}/oauth2/jwks", doc.jwks_uri)
        assertTrue(doc.grant_types_supported.contains("authorization_code"))
    }

    @Test
    fun `oidcDiscover caches within the TTL and does not refetch`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, discoveryTtlMs = 300_000)
        client.oidcDiscover()
        client.oidcDiscover()
        client.oidcDiscover()
        assertEquals(1, dispatcher.discoveryCallCount)
    }

    @Test
    fun `oidcDiscover cache is per-client instance, never shared across clients`(): Unit = runBlocking {
        // CONTRACT.md §12.3 rule 6: never process-global. Two independently
        // constructed clients against the SAME origin each fetch their own
        // copy — proven by the call count doubling rather than staying at 1.
        val clientA = OidcTestKit.clientFor(server)
        val clientB = OidcTestKit.clientFor(server)
        val docA = clientA.oidcDiscover()
        val docB = clientB.oidcDiscover()
        assertEquals(2, dispatcher.discoveryCallCount)
        assertEquals(docA, docB)
    }

    @Test
    fun `a small configured TTL is floored to the 5-minute minimum`(): Unit = runBlocking {
        // CONTRACT.md §12.3 rule 6: TTL MUST be at least 5 minutes; a smaller
        // configured value is silently raised to the floor. Proven by two
        // rapid-fire calls still hitting the cache instead of refetching.
        val client = OidcTestKit.clientFor(server, discoveryTtlMs = 1)
        client.oidcDiscover()
        client.oidcDiscover()
        assertEquals(1, dispatcher.discoveryCallCount)
    }

    @Test
    fun `oidcDiscover de-duplicates concurrent callers into a single fetch`(): Unit = runBlocking {
        val discoveryCalls = AtomicInteger(0)
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse {
                discoveryCalls.incrementAndGet()
                Thread.sleep(150) // hold the flight open so waiters queue behind the leader
                return MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.discoveryJson(server.url("/").toString()))
            }
        }
        val client = OidcTestKit.clientFor(server)
        val results = (1..8).map { async(Dispatchers.IO) { client.oidcDiscover() } }.awaitAll()
        assertEquals(1, discoveryCalls.get())
        results.forEach { assertEquals(results.first(), it) }
    }

    @Test
    fun `oidcDiscover maps a non-200 response to the taxonomy`(): Unit = runBlocking {
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                MockResponse().setResponseCode(500)
        }
        val client = OidcTestKit.clientFor(server)
        assertThrows(NetworkError::class.java) { runBlocking { client.oidcDiscover() } }
    }

    @Test
    fun `oidcDiscover surfaces a malformed JSON body as NetworkError`(): Unit = runBlocking {
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                MockResponse().setResponseCode(200).setBody("not json")
        }
        val client = OidcTestKit.clientFor(server)
        assertThrows(NetworkError::class.java) { runBlocking { client.oidcDiscover() } }
    }

    @Test
    fun `oidcDiscover requires the required discovery fields`(): Unit = runBlocking {
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json").setBody("{}")
        }
        val client = OidcTestKit.clientFor(server)
        assertThrows(NetworkError::class.java) { runBlocking { client.oidcDiscover() } }
    }

    // -----------------------------------------------------------------------
    // Contract 1.42 — the two new RFC 8414 members (§21.5)
    // -----------------------------------------------------------------------

    @Test
    fun `the two contract-1_42 metadata members are parsed when present`(): Unit = runBlocking {
        server.dispatcher = discoveryDispatcher(
            """
              "code_challenge_methods_supported": ["S256"],
              "token_endpoint_auth_signing_alg_values_supported": ["EdDSA", "ES256"],
            """.trimIndent(),
        )
        val doc = OidcTestKit.clientFor(server).oidcDiscover()
        assertEquals(listOf("S256"), doc.code_challenge_methods_supported)
        assertEquals(listOf("EdDSA", "ES256"), doc.token_endpoint_auth_signing_alg_values_supported)
    }

    @Test
    fun `an absent code_challenge_methods_supported is null, never an assumed S256`(): Unit = runBlocking {
        // CONTRACT.md §21.5: RFC 8414 defines no default for this member, so
        // its absence does not mean S256 — and openapi.json marking it
        // required must not stop this SDK parsing a document from a
        // non-AXIAM OP that omits it. `null` is "the document said nothing";
        // an empty list would be "the document said none".
        val doc = OidcTestKit.clientFor(server).oidcDiscover()
        assertNull(doc.code_challenge_methods_supported)
        assertNull(doc.token_endpoint_auth_signing_alg_values_supported)
    }

    // -----------------------------------------------------------------------
    // Contract 1.42 — the server publishes the tenant inside the endpoints it
    // advertises, so the SDK must REPLACE `tenant_id`, not append it.
    // -----------------------------------------------------------------------

    @Test
    fun `a tenant-scoped discovered endpoint yields exactly one tenant_id on the wire`(): Unit = runBlocking {
        // `tenant_scoped()` appends `?tenant_id=<uuid>` to the token,
        // revocation, introspection, device-authorization, PAR and
        // end-session URLs whenever the discovery request named a tenant or
        // the deployment sets `oauth2_default_tenant_id`. OkHttp's
        // addQueryParameter APPENDS, so the SDK used to produce
        // `?tenant_id=A&tenant_id=B` — two values for the parameter that
        // selects a tenant.
        val published = "99999999-9999-9999-9999-999999999999"
        val resolved = "22222222-2222-2222-2222-222222222222"
        server.dispatcher = tenantScopedIntrospectDispatcher(published)

        val client = OidcTestKit.clientFor(
            server,
            clientSecret = OidcTestKit.CLIENT_SECRET,
            tenantId = resolved,
        )
        client.introspect(IntrospectParams.of("tok"))

        val url = introspectUrl!!
        assertEquals(
            listOf(resolved),
            url.queryParameterValues("tenant_id"),
            "exactly one tenant_id, and the RESOLVED one wins: it is what this caller " +
                "authenticated against (§12.3 rule 4)",
        )
        assertEquals(
            "legacy",
            url.queryParameter("audience"),
            "every OTHER query parameter the endpoint published is preserved — RFC 6749 " +
                "§3.1/§3.2 require a client to retain the endpoint's own query component",
        )
    }

    private var introspectUrl: okhttp3.HttpUrl? = null

    /** A dispatcher whose discovery document splices [extraMembers] in, and whose JWKS is live. */
    private fun discoveryDispatcher(extraMembers: String): OidcTestKit.RoutingDispatcher =
        OidcTestKit.RoutingDispatcher(
            discoveryBody = {
                OidcTestKit.discoveryJson(server.url("/").toString())
                    .replaceFirst("{", "{\n$extraMembers")
            },
            jwksBody = { OidcTestKit.jwksJson(signingKey.toPublicJWK()) },
        )

    /**
     * Discovery whose `introspection_endpoint` already carries the tenant the
     * server published plus an unrelated parameter, and an introspection
     * handler that records the URL the SDK actually dialed.
     */
    private fun tenantScopedIntrospectDispatcher(publishedTenant: String): OidcTestKit.RoutingDispatcher {
        val origin = server.url("/").toString().trimEnd('/')
        val dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = {
                OidcTestKit.discoveryJson(server.url("/").toString()).replace(
                    "\"introspection_endpoint\": \"$origin/oauth2/introspect\"",
                    "\"introspection_endpoint\": " +
                        "\"$origin/oauth2/introspect?audience=legacy&tenant_id=$publishedTenant\"",
                )
            },
            jwksBody = { OidcTestKit.jwksJson(signingKey.toPublicJWK()) },
        )
        dispatcher.on("/oauth2/introspect") { request ->
            introspectUrl = request.requestUrl
            MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody("""{"active": false}""")
        }
        return dispatcher
    }
}
