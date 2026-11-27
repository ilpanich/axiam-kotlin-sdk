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
     * Issue #109 — the single-flight is keyed by the refresh token. A caller
     * holding a DIFFERENT refresh token is not part of another token's burst:
     * even inside the publish-before-vacate window it must get its own wire
     * call and its own token set (never another grant's), while the same token
     * still joins (rule 6a, pinned by the test above).
     */
    @Test
    fun `a different refresh token in the publish window gets its own wire call and token set`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") { req ->
            calls.incrementAndGet()
            val rt = req.body.peek().readUtf8().substringAfter("refresh_token=").substringBefore("&")
            MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "access-for-$rt"))
        }
        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        client.oidcRefreshAfterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            check(windowOpen.await(10, TimeUnit.SECONDS)) { "outcome was never published" }
            assertEquals("access-for-rtA", a.await().accessToken.expose())

            // Different token inside rtA's window: its own call, its own outcome.
            client.oidcRefreshAfterPublishHook = null
            val b = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtB", tenantId = tenantId)) }
            assertEquals("access-for-rtB", b.await().accessToken.expose(), "a different refresh token must not receive another grant's tokens")
            assertEquals(2, calls.get())

            // Same token as the settled slot still joins (rule 6a).
            val a2 = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            delay(300)
            assertEquals("access-for-rtA", a2.await().accessToken.expose())
            assertEquals(2, calls.get(), "same token inside its window must join, not re-call")
        } finally {
            client.oidcRefreshAfterPublishHook = null
            releaseWindow.countDown()
            callers.cancel()
        }
    }

    private val wireTenants = java.util.concurrent.ConcurrentLinkedQueue<String>()

    private fun installEchoToken(calls: AtomicInteger, gate: CountDownLatch? = null) {
        dispatcher.on("/oauth2/token") { req ->
            calls.incrementAndGet()
            wireTenants.add(req.requestUrl?.queryParameter("tenant_id") ?: "")
            gate?.let { check(it.await(10, TimeUnit.SECONDS)) { "gate never released" } }
            val rt = req.body.peek().readUtf8().substringAfter("refresh_token=").substringBefore("&")
            val t = req.requestUrl?.queryParameter("tenant_id")
            MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "access-for-$rt-$t"))
        }
    }

    /** Issue #109, required test 1: a different token during a LIVE flight gets its own call. */
    @Test
    fun `a different refresh token during a live flight gets its own wire call and token set`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val release = CountDownLatch(1)
        installEchoToken(calls, release)
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            val b = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtB", tenantId = tenantId)) }
            delay(500)
            release.countDown()
            assertEquals("access-for-rtA-$tenantId", a.await().accessToken.expose())
            assertEquals("access-for-rtB-$tenantId", b.await().accessToken.expose())
            assertEquals(2, calls.get())
        } finally {
            release.countDown()
            callers.cancel()
        }
    }

    /**
     * Different keys run independently: while A's wire call is HELD on the
     * transport, B's wire call starts (asserted on the server), and no lock is
     * shared with the §1 cookie refresh. Twenty distinct tokens complete
     * concurrently under a timeout.
     */
    @Test
    fun `different keys run concurrently and twenty distinct tokens complete under a timeout`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val release = CountDownLatch(1)
        installEchoToken(calls, release)
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            val others = (1..19).map { i ->
                callers.async { client.oidcRefresh(OidcRefreshParams.of("rt-$i", tenantId = tenantId)) }
            }
            // Every distinct token reaches the transport while A's call is still held.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (calls.get() < 20 && System.nanoTime() < deadline) delay(20)
            assertEquals(20, calls.get(), "a held wire call must not block other keys' wire calls")
            release.countDown()
            kotlinx.coroutines.withTimeout(15_000) {
                assertEquals("access-for-rtA-$tenantId", a.await().accessToken.expose())
                others.forEachIndexed { i, d ->
                    assertEquals("access-for-rt-${i + 1}-$tenantId", d.await().accessToken.expose())
                }
            }
        } finally {
            release.countDown()
            callers.cancel()
        }
    }

    /** Same token, different resolved tenant: separate flights. Scope is not part of the key. */
    @Test
    fun `the same token for a different tenant is a separate flight and scope does not split one`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val release = CountDownLatch(1)
        installEchoToken(calls, release)
        val other = "33333333-3333-3333-3333-333333333333"
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            val a2 = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", scope = "x", tenantId = tenantId)) }
            val t2 = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = other)) }
            delay(500)
            release.countDown()
            assertEquals("access-for-rtA-$tenantId", a.await().accessToken.expose())
            assertEquals("access-for-rtA-$tenantId", a2.await().accessToken.expose(), "scope joins the one flight")
            assertEquals("access-for-rtA-$other", t2.await().accessToken.expose(), "other tenant gets its own result")
            assertEquals(2, calls.get(), "one flight per (tenant, token)")
            assertEquals(setOf(tenantId, other), wireTenants.toSet())
        } finally {
            release.countDown()
            callers.cancel()
        }
    }

    /** The client's default tenant, explicit or omitted, is ONE flight and ONE wire call. */
    @Test
    fun `an explicit tenant equal to the default and an omitted tenant share one flight`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val release = CountDownLatch(1)
        installEchoToken(calls, release)
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = tenantId)) }
            val b = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA")) }
            delay(500)
            release.countDown()
            assertEquals("access-for-rtA-$tenantId", a.await().accessToken.expose())
            assertEquals("access-for-rtA-$tenantId", b.await().accessToken.expose())
            assertEquals(1, calls.get())
        } finally {
            release.countDown()
            callers.cancel()
        }
    }

    /** Upper-case, lower-case and omitted default tenant spell one key: one flight, one wire call. */
    @Test
    fun `tenant case does not split a flight`() = runBlocking {
        val client = OidcTestKit.clientFor(server, tenantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        val release = CountDownLatch(1)
        installEchoToken(calls, release)
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")) }
            val b = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")) }
            val c = callers.async { client.oidcRefresh(OidcRefreshParams.of("rtA")) }
            delay(500)
            release.countDown()
            assertEquals("access-for-rtA-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", a.await().accessToken.expose())
            b.await(); c.await()
            assertEquals(1, calls.get())
            assertEquals(listOf("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), wireTenants.toList(), "canonical tenant on the wire")
        } finally {
            release.countDown()
            callers.cancel()
        }
    }

    /** An invalid tenant fails immediately: no slot, no request. */
    @Test
    fun `an invalid tenant is rejected before the guard with no request`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val calls = AtomicInteger(0)
        installEchoToken(calls)
        try {
            client.oidcRefresh(OidcRefreshParams.of("rtA", tenantId = "not-a-uuid"))
            org.junit.jupiter.api.Assertions.fail<Unit>("expected AuthError")
        } catch (e: io.axiam.sdk.errors.AuthError) {
            // expected
        }
        assertEquals(0, calls.get())
        assertTrue(client.oidcRefreshOccupiedKeys().isEmpty())
    }

    /** No raw token in the registry, and the slot is removed once vacated (no growth). */
    @Test
    fun `the flight registry holds a digest never the raw token and empties after vacate`() = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        installEchoToken(AtomicInteger(0))
        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        client.oidcRefreshAfterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val a = callers.async { client.oidcRefresh(OidcRefreshParams.of("rt-secret-value", tenantId = tenantId)) }
            check(windowOpen.await(10, TimeUnit.SECONDS))
            a.await()
            val keys = client.oidcRefreshOccupiedKeys()
            assertEquals(1, keys.size)
            assertTrue(keys.none { it.toString().contains("rt-secret-value") }, "raw token must never be a key")
            assertTrue(keys.all { Regex("[0-9a-f]{64}").matches(it.toString()) })
            client.oidcRefreshAfterPublishHook = null
            releaseWindow.countDown()
            delay(500)
            assertTrue(client.oidcRefreshOccupiedKeys().isEmpty(), "a vacated key's slot must be removed")
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
