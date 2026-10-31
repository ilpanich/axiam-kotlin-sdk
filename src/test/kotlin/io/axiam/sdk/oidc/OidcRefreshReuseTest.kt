package io.axiam.sdk.oidc

import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * CONTRACT.md §9, the contract 1.65 paragraph (a replayed refresh token ends the session) and its
 * confirmation test: against a mocked `400 invalid_grant`, `oidcRefresh` makes exactly ONE wire
 * call for a burst of N >= 5 concurrent callers, every waiter receives that one error, and the
 * spent token is never presented again. This is the §9 rule 2 coalescing test run against a
 * failure; the SDK needed no code change.
 */
class OidcRefreshReuseTest {

    private lateinit var server: MockWebServer
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher
    private val tokenRequests = Collections.synchronizedList(mutableListOf<RecordedRequest>())
    private val tenantId = "22222222-2222-2222-2222-222222222222"
    private val spent = "spent-refresh-token"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey())
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `a 400 invalid_grant on oidcRefresh is one wire call shared by all waiters and the spent token is never presented again`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val onWire = CountDownLatch(1)
        val release = CountDownLatch(1)
        dispatcher.on("/oauth2/token") {
            tokenRequests += it
            onWire.countDown()
            check(release.await(10, TimeUnit.SECONDS)) { "token gate never released" }
            MockResponse().setResponseCode(400).addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.oauth2ErrorJson("invalid_grant", "refresh token reuse"))
        }
        val params = OidcRefreshParams.of(spent, tenantId = tenantId)

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val burst = 8
            val leader = callers.async { runCatching { client.oidcRefresh(params) } }
            check(onWire.await(10, TimeUnit.SECONDS)) { "leader never reached /oauth2/token" }
            val waiters = (1 until burst).map { callers.async { runCatching { client.oidcRefresh(params) } } }
            delay(400) // every waiter is coalesced into the one in-flight call
            assertEquals(1, tokenRequests.size, "the waiters coalesce, they do not start their own wire call (§9 rule 1)")
            release.countDown()

            val outcomes = (listOf(leader) + waiters).awaitAll()
            assertEquals(burst, outcomes.size)
            val errors = outcomes.map { it.exceptionOrNull() }
            assertTrue(errors.all { it is OAuthProtocolError && it.error == "invalid_grant" }, "every caller gets the OAuthProtocolError")
            assertTrue(errors.all { it === errors.first() }, "...and it is the ONE error of the one call (§9 rule 2)")
            assertEquals(1, tokenRequests.size, "exactly one wire call for the whole burst")
            assertEquals(spent, tokenRequests.single().body.readUtf8().split("&").first { it.startsWith("refresh_token=") }.substringAfter('='))
        } finally {
            callers.cancel()
        }

        // The SDK holds no copy of the spent token, so nothing can present it again: after the
        // burst has settled, the one request is still the only one that carried it.
        delay(300)
        assertEquals(1, tokenRequests.size, "the spent token was presented exactly once")
    }
}
