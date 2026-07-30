package io.axiam.sdk.oidc

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * CONTRACT.md §9 rule 6 (contract 1.6) conformance for the §12 `oidcRefresh`
 * coalescer, which runs on its own dedicated guard instance (§9 rule 5) over
 * the OAuth2 `refresh_token` namespace.
 *
 * Every assertion here is on the **wire-call count** as well as the value:
 * `/oauth2/token` is single-use and rotating, so a second wire call in a burst
 * is a hard failure even when the returned value looks right.
 */
class OidcRefreshRule6Test {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    private val tenantId = "22222222-2222-2222-2222-222222222222"

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

    private fun params() = OidcRefreshParams.of("old-refresh", tenantId = tenantId)

    /**
     * Gates `/oauth2/token` so a refresh can be pinned "on the wire". The
     * MockWebServer dispatcher thread blocks in `release.await()`, exactly like
     * the real non-interruptible OkHttp `Call.execute()`: cancelling the
     * calling coroutine cannot abort the request already in flight.
     */
    private class TokenGate(private val calls: AtomicInteger, private val access: String) {
        val onWire = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun install(dispatcher: OidcTestKit.RoutingDispatcher) {
            dispatcher.on("/oauth2/token") {
                calls.incrementAndGet()
                onWire.countDown()
                check(release.await(10, TimeUnit.SECONDS)) { "token gate never released" }
                MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.tokenResponseJson(accessToken = access))
            }
        }
    }

    @Test
    fun `a cancelled oidcRefresh leader must not strand the waiters coalesced into it`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val gate = TokenGate(calls, "shared-access")
        gate.install(dispatcher)

        // Independent jobs: cancelling one caller must not cancel the other.
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { client.oidcRefresh(params()) }
            check(gate.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached /oauth2/token" }

            val waiter = callers.async { client.oidcRefresh(params()) }
            delay(300) // let the waiter coalesce into the leader's in-flight slot
            assertEquals(1, calls.get(), "the waiter must coalesce, not start a second wire call (§9 rule 1)")

            leader.cancel() // the caller that happened to be elected leader goes away
            gate.release.countDown() // the one wire call now completes successfully

            val outcome = runCatching { waiter.await() }

            assertEquals(1, calls.get(), "still exactly one /oauth2/token call (§9 rule 1)")
            assertTrue(outcome.isSuccess) {
                "§9 rule 2: the waiter must receive the single refresh's outcome; the initiating " +
                    "caller's cancellation is not that outcome. Got: ${outcome.exceptionOrNull()}"
            }
            assertEquals("shared-access", outcome.getOrThrow().accessToken.expose())
        } finally {
            callers.cancel()
        }
    }

    @Test
    fun `a cancelled oidcRefresh leader still vacates its slot for the next caller`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val first = TokenGate(calls, "first-access")
        first.install(dispatcher)

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { client.oidcRefresh(params()) }
            check(first.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached /oauth2/token" }
            leader.cancel()
            first.release.countDown()
            runCatching { leader.await() }
            delay(300) // let the cancelled leader finish unwinding

            // §9 rule 6d: a caller arriving after full settlement refreshes afresh.
            val second = TokenGate(calls, "second-access")
            second.install(dispatcher)
            second.release.countDown()
            val fresh = client.oidcRefresh(params())

            assertEquals(2, calls.get(), "§9 rule 6d: the post-settlement caller must refresh afresh")
            assertEquals("second-access", fresh.accessToken.expose(), "§9 rule 6d: not a previous burst's outcome")
        } finally {
            callers.cancel()
        }
    }

    /**
     * §9 rule 6a + 6d, the two windows contract 1.6's test requirement calls
     * out explicitly, in one deterministic sequence:
     *
     *  - a caller landing strictly AFTER the outcome was published but BEFORE
     *    the slot was vacated MUST join that outcome (wire count stays 1) —
     *    finding the slot empty there would let it start a second call against
     *    an already-consumed refresh token;
     *  - a caller landing strictly AFTER the slot was vacated MUST run its own
     *    new attempt and receive THAT call's outcome, never the previous
     *    burst's.
     *
     * The window is pinned open by the visible-for-testing `afterPublish` hook
     * rather than raced for.
     */
    @Test
    fun `the publish-before-vacate window joins, and a post-vacate caller refreshes afresh`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val access = java.util.concurrent.atomic.AtomicReference("burst-1-access")
        dispatcher.on("/oauth2/token") {
            calls.incrementAndGet()
            MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = access.get()))
        }

        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        client.oidcRefreshAfterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val first = callers.async { client.oidcRefresh(params()) }
            check(windowOpen.await(10, TimeUnit.SECONDS)) { "outcome was never published" }
            assertEquals("burst-1-access", first.await().accessToken.expose())

            // --- inside the window: the slot still holds the SETTLED outcome ---
            val late = callers.async { client.oidcRefresh(params()) }
            delay(300)
            assertEquals(1, calls.get(), "§9 rule 6a: a caller inside the window must join, not re-call")
            assertEquals("burst-1-access", late.await().accessToken.expose(), "§9 rule 2: the one outcome")

            // --- after full settlement: a new caller must refresh afresh ---
            client.oidcRefreshAfterPublishHook = null
            access.set("burst-2-access")
            releaseWindow.countDown()
            delay(500) // let the worker finish its (uncancellable, identity-checked) vacate

            val afterVacate = client.oidcRefresh(params())
            assertEquals(2, calls.get(), "§9 rule 6d: a post-settlement caller runs its own attempt")
            assertEquals(
                "burst-2-access",
                afterVacate.accessToken.expose(),
                "§9 rule 6d: it must receive its OWN call's outcome, not the previous burst's",
            )
        } finally {
            client.oidcRefreshAfterPublishHook = null
            releaseWindow.countDown()
            callers.cancel()
        }
    }

    /**
     * §9 rule 6b — occupancy is not liveness. While the settled-but-uncleared
     * slot sits in rule 6a's bookkeeping window, an unrelated §12 operation
     * must run normally: nothing in this SDK may read "the slot is non-null" as
     * "a refresh is on the wire" and refuse or stall on it (the shape of the
     * Java port's bug).
     */
    @Test
    fun `an unrelated operation is unaffected while the settled slot still occupies the window`() = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "a"))
        dispatcher.onJson("/oauth2/introspect", 200, """{"active": true, "sub": "user-1"}""")

        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        client.oidcRefreshAfterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val refresh = callers.async { client.oidcRefresh(params()) }
            check(windowOpen.await(10, TimeUnit.SECONDS)) { "outcome was never published" }
            assertEquals("a", refresh.await().accessToken.expose())

            val result = client.introspect(
                IntrospectParams.of("some-token", tenantId = tenantId),
            )
            assertTrue(result.active, "§9 rule 6b: the bookkeeping window must not read as 'busy'")
            assertEquals("user-1", result.sub)
        } finally {
            client.oidcRefreshAfterPublishHook = null
            releaseWindow.countDown()
            callers.cancel()
        }
    }

    @Test
    fun `a cancelled oidcRefresh waiter neither cancels the leader nor disturbs the slot`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val gate = TokenGate(calls, "shared-access")
        gate.install(dispatcher)

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { client.oidcRefresh(params()) }
            check(gate.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached /oauth2/token" }
            val waiter = callers.async { client.oidcRefresh(params()) }
            delay(300)
            assertEquals(1, calls.get())

            waiter.cancel()
            gate.release.countDown()

            assertEquals("shared-access", leader.await().accessToken.expose(), "the leader must be unaffected")
            assertEquals(1, calls.get(), "exactly one /oauth2/token call (§9 rule 1)")
        } finally {
            callers.cancel()
        }
    }
}
