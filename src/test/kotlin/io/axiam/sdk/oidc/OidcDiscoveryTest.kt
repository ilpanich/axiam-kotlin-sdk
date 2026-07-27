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
}
