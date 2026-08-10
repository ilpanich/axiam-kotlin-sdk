package io.axiam.sdk

import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.DecisionMemo
import io.axiam.sdk.internal.Retry
import io.axiam.sdk.internal.TelemetryDispatcher
import io.axiam.sdk.telemetry.TelemetryEvent
import java.time.Duration as JavaDuration
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * D5 conformance — CONTRACT.md §16, §17, §18, §19.
 *
 * These assert through the **public `checkAccess` surface**, counting requests
 * that reach the mock server, rather than against the helpers in isolation.
 * That distinction is normative as of contract 1.8.1: the TypeScript SDK
 * shipped a retry helper that was exported, unit-tested and green while no
 * production path called it, so that SDK performed no read-only retries at all
 * and every test passed. Counting on the wire is the only assertion that
 * catches it.
 */
class D5ConformanceTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun client(
        memoTtl: JavaDuration = JavaDuration.ZERO,
        retry: Boolean = true,
        hook: ((TelemetryEvent) -> Unit)? = null,
    ): AxiamClient = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
        .orgId(TestSupport.ORG_ID)
        .apply {
            if (!retry) retryDisabled()
            if (memoTtl > JavaDuration.ZERO) decisionMemoTtl(memoTtl)
            hook?.let { telemetryHook { event -> it(event) } }
            // Pin the jitter to 0 so the tests do not really sleep: a test that
            // waits 200ms is a test nobody runs (§16.7). The delay arithmetic
            // is asserted directly below instead.
            jitterSource { 0.0 }
        }
        .build()

    private fun enqueueAllow(times: Int = 1) = repeat(times) {
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"allowed":true,"reason_code":"allowed"}"""),
        )
    }

    private fun enqueueStatus(status: Int, times: Int = 1) = repeat(times) {
        server.enqueue(MockResponse().setResponseCode(status))
    }

    // -----------------------------------------------------------------------
    // §16 — the policy table
    // -----------------------------------------------------------------------

    @Test
    fun `backoff doubles from the base and stops at the cap`() {
        assertEquals(Retry.BASE_DELAY, Retry.backoffFor(1))
        assertEquals(400.milliseconds, Retry.backoffFor(2))
        assertEquals(Retry.MAX_DELAY, Retry.backoffFor(20))
    }

    @Test
    fun `jitter is full, not partial`() {
        // The range is [0, backoff], not backoff +- something. Pinning the
        // fraction to its endpoints is what distinguishes the two — a random
        // draw would pass under either policy.
        assertEquals(Duration.ZERO, Retry.delayFor(1, Duration.ZERO, 0.0))
        assertEquals(Retry.BASE_DELAY, Retry.delayFor(1, Duration.ZERO, 1.0))
        assertEquals(200.milliseconds, Retry.delayFor(2, Duration.ZERO, 0.5))
    }

    @Test
    fun `Retry-After is a floor, never a ceiling`() {
        // TypeScript's `retryAfterMs ?? backoff(n)` made the hint REPLACE the
        // backoff, so a zero retried immediately and defeated the policy.
        assertEquals(2.seconds, Retry.delayFor(1, 2.seconds, 1.0))
        assertEquals(Retry.BASE_DELAY, Retry.delayFor(1, Duration.ZERO, 1.0))
        assertEquals(50.milliseconds, Retry.delayFor(1, 50.milliseconds, 0.0))
    }

    @Test
    fun `jitter fraction outside the unit interval is clamped`() {
        // A caller-supplied source is not trusted to stay in [0, 1]: above 1
        // would exceed the §16.1 cap, below 0 would produce a negative wait.
        assertEquals(Retry.BASE_DELAY, Retry.delayFor(1, Duration.ZERO, 1.5))
        assertEquals(Duration.ZERO, Retry.delayFor(1, Duration.ZERO, -0.5))
    }

    @Test
    fun `a persistent 503 makes exactly three attempts`() = runBlocking {
        enqueueStatus(503, times = 3)
        client().use {
            assertThrows(NetworkError::class.java) {
                runBlocking { it.checkAccess("read", "r-1") }
            }
        }
        assertEquals(Retry.MAX_ATTEMPTS, server.requestCount)
    }

    @Test
    fun `a transient failure is retried and the success returned`() = runBlocking {
        enqueueStatus(503)
        enqueueAllow()
        client().use {
            assertTrue(it.checkAccess("read", "r-1").allowed)
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a decisive 403 is not retried`() {
        // A 403 is an answer, not a transport failure.
        enqueueStatus(403)
        client().use {
            assertThrows(AuthzError::class.java) {
                runBlocking { it.checkAccess("read", "r-1") }
            }
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `retryDisabled makes exactly one attempt`() {
        enqueueStatus(503)
        client(retry = false).use {
            assertThrows(NetworkError::class.java) {
                runBlocking { it.checkAccess("read", "r-1") }
            }
        }
        assertEquals(1, server.requestCount)
    }

    // -----------------------------------------------------------------------
    // §17 — decision memo
    // -----------------------------------------------------------------------

    @Test
    fun `the memo is off by default`() = runBlocking {
        // The most important assertion here. §11.2 rule 6's ban on decision
        // caching is still the default; a build that quietly enabled this would
        // change authorization staleness for every existing caller without them
        // asking for it.
        enqueueAllow(times = 2)
        client().use {
            it.checkAccess("read", "r-1")
            it.checkAccess("read", "r-1")
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a repeat inside the TTL is served without a second call`() = runBlocking {
        enqueueAllow()
        client(memoTtl = JavaDuration.ofSeconds(5)).use {
            val first = it.checkAccess("read", "r-1")
            val second = it.checkAccess("read", "r-1")
            assertEquals(1, server.requestCount)
            // §17.1 rule 5: the reason code survives the memo.
            assertEquals(first.reasonCode, second.reasonCode)
            assertNotNull(second.reasonCode)
        }
    }

    @Test
    fun `denies are memoized exactly like allows`() = runBlocking {
        // §17.1 rule 4 — asymmetric caching leaks the outcome through latency.
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"allowed":false,"reason_code":"denied_by_rule"}"""),
        )
        client(memoTtl = JavaDuration.ofSeconds(5)).use {
            it.checkAccess("read", "r-1")
            val second = it.checkAccess("read", "r-1")
            assertEquals(1, server.requestCount)
            assertFalse(second.allowed)
            assertEquals("denied_by_rule", second.reasonCode)
        }
    }

    @Test
    fun `a failure is never memoized`() {
        // §17.1 rule 7 — caching a transport error as a deny turns a blip into
        // a TTL-long outage.
        enqueueStatus(503, times = 2)
        client(memoTtl = JavaDuration.ofSeconds(5), retry = false).use { c ->
            repeat(2) {
                assertThrows(NetworkError::class.java) {
                    runBlocking { c.checkAccess("read", "r-1") }
                }
            }
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `every key component is distinguished`() {
        val keys = setOf(
            DecisionMemo.key(null, "r1", "read", null),
            DecisionMemo.key(null, "r1", "write", null),
            DecisionMemo.key(null, "r2", "read", null),
            DecisionMemo.key(null, "r1", "read", "col-a"),
            DecisionMemo.key("u1", "r1", "read", null),
        )
        assertEquals(5, keys.size)
        // An absent scope must never collide with a present empty one.
        assertFalse(
            DecisionMemo.key(null, "r1", "read", null) ==
                DecisionMemo.key(null, "r1", "read", ""),
        )
    }

    @Test
    fun `a TTL above the ceiling is clamped rather than rejected`() {
        assertEquals(DecisionMemo.MAX_TTL, DecisionMemo(1.seconds * 3600).effectiveTtl)
        assertEquals(2.seconds, DecisionMemo(2.seconds).effectiveTtl)
        assertFalse(DecisionMemo(Duration.ZERO).enabled)
        assertFalse(DecisionMemo((-1).seconds).enabled, "a negative TTL disables rather than wrapping")
    }

    @Test
    fun `an entry expires at exactly the TTL`() {
        var now = 1_000_000_000L
        val memo = DecisionMemo(5.seconds) { now }
        memo.put("k", AccessResult(allowed = true, reason = null, reasonCode = "allowed"))

        now += 4_999_000_000L
        assertNotNull(memo.get("k"))
        now += 1_000_000L
        assertNull(memo.get("k"))
    }

    @Test
    fun `the memo evicts rather than growing without bound`() {
        // §17.1 rule 8 — an unbounded per-client cache keyed by (subject,
        // resource, action, scope) is a memory leak in any service that checks
        // many resources.
        val memo = DecisionMemo(5.seconds)
        val decision = AccessResult(allowed = true, reason = null, reasonCode = "allowed")
        repeat(DecisionMemo.MAX_ENTRIES + 100) { i ->
            memo.put(DecisionMemo.key(null, "r$i", "read", null), decision)
        }
        assertEquals(DecisionMemo.MAX_ENTRIES, memo.size)
    }

    // -----------------------------------------------------------------------
    // §18 — deterministic shutdown
    // -----------------------------------------------------------------------

    @Test
    fun `close is idempotent`() {
        val c = client()
        c.close()
        c.close()
    }

    @Test
    fun `close issues no network request`() {
        // §18.1 rule 5. The server-side session deliberately outlives the
        // client object — that is what lets a process restart and resume — so a
        // close() that logged out would silently end every user's session on
        // each deploy. Asserted against the wire, because a logout wired into
        // close() succeeds silently.
        client().close()
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `use after close throws rather than reconnecting`() = runBlocking {
        enqueueAllow()
        val c = client()
        c.checkAccess("read", "r-1")
        val before = server.requestCount

        c.close()

        assertThrows(NetworkError::class.java) {
            runBlocking { c.checkAccess("read", "r-1") }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { c.login("u@example.com", "pw") }
        }
        assertThrows(NetworkError::class.java) { runBlocking { c.logout() } }
        assertEquals(before, server.requestCount, "no request may reach the server after close()")
    }

    // -----------------------------------------------------------------------
    // §19 — telemetry
    // -----------------------------------------------------------------------

    @Test
    fun `one request pair per attempt, with a retry between`() = runBlocking {
        enqueueStatus(503)
        enqueueAllow()
        val events = mutableListOf<TelemetryEvent>()
        client(hook = { events += it }).use {
            it.checkAccess("read", "r-1")
        }

        val kinds = events.map {
            when (it) {
                is TelemetryEvent.RequestStart -> "start"
                is TelemetryEvent.RequestEnd -> "end"
                is TelemetryEvent.Retry -> "retry"
                is TelemetryEvent.Refresh -> "refresh"
                is TelemetryEvent.ConfigClamped -> "clamped"
            }
        }
        assertEquals(listOf("start", "end", "retry", "start", "end"), kinds)

        val starts = events.filterIsInstance<TelemetryEvent.RequestStart>()
        // Emitting both pairs as attempt 1 would make a retried call
        // indistinguishable from a single slow one.
        assertEquals(listOf(1, 2), starts.map { it.attempt })
        // The path TEMPLATE, never a substituted URL — a metric label carrying
        // a UUID is a cardinality bomb.
        assertEquals("/api/v1/authz/check", starts.first().pathTemplate)
    }

    @Test
    fun `a throwing hook cannot fail the operation`() = runBlocking {
        // §19.2 rule 2 — telemetry is not permitted to fail an authz check.
        enqueueAllow()
        client(hook = { error("hook exploded") }).use {
            assertTrue(it.checkAccess("read", "r-1").allowed)
        }
    }

    @Test
    fun `no event payload carries a token`() {
        // §19.2 rule 3 — this surface exists to be shipped to a metrics
        // backend, which is the last place a bearer token should land.
        enqueueStatus(503, times = 3)
        val events = mutableListOf<TelemetryEvent>()
        client(hook = { events += it }).use { c ->
            assertThrows(NetworkError::class.java) {
                runBlocking { c.checkAccess("read", "r-1") }
            }
        }
        val rendered = events.toString().lowercase()
        assertFalse(rendered.contains("eyj"), "no JWT-shaped string in telemetry")
        assertFalse(rendered.contains("authorization"), "no auth header content in telemetry")
    }

    @Test
    fun `a clamped setting is reported, not swallowed`() {
        // §19.2 rule 6 — an operator who set a 60-second memo TTL believes
        // their staleness bound is 60 seconds. It is five. Clamping is right;
        // doing it silently leaves their revocation reasoning wrong by a factor
        // of twelve with nothing anywhere to say so.
        val events = mutableListOf<TelemetryEvent>()
        client(memoTtl = JavaDuration.ofMinutes(1), hook = { events += it }).use { }

        val clamps = events.filterIsInstance<TelemetryEvent.ConfigClamped>()
        assertEquals(1, clamps.size)
        assertEquals("decisionMemoTtl", clamps.first().setting)
        assertEquals(1.minutes.toString(), clamps.first().requested)
        assertEquals(DecisionMemo.MAX_TTL.toString(), clamps.first().effective)
        assertEquals("§17.1 rule 2", clamps.first().contractReference)
    }

    @Test
    fun `a value already inside its limit reports nothing`() {
        // An event that fires when nothing happened trains its reader to ignore
        // it, which costs exactly the case above.
        val inRange = mutableListOf<TelemetryEvent>()
        client(memoTtl = JavaDuration.ofSeconds(2), hook = { inRange += it }).use { }
        assertTrue(
            inRange.filterIsInstance<TelemetryEvent.ConfigClamped>().isEmpty(),
            "2s is inside the 5s ceiling",
        )

        val boundary = mutableListOf<TelemetryEvent>()
        client(memoTtl = JavaDuration.ofSeconds(5), hook = { boundary += it }).use { }
        assertTrue(
            boundary.filterIsInstance<TelemetryEvent.ConfigClamped>().isEmpty(),
            "the ceiling exactly is not a clamp",
        )
    }

    @Test
    fun `the disabled default reports no clamp`() {
        // Never configuring the memo is not a setting that got overridden.
        val events = mutableListOf<TelemetryEvent>()
        client(hook = { events += it }).use { }
        assertTrue(events.filterIsInstance<TelemetryEvent.ConfigClamped>().isEmpty())

        // A negative TTL disables the memo; it is not clamped up to the ceiling.
        val negative = mutableListOf<TelemetryEvent>()
        val c = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .decisionMemoTtl(JavaDuration.ofSeconds(-5))
            .telemetryHook { event -> negative += event }
            .build()
        c.use { }
        assertTrue(negative.filterIsInstance<TelemetryEvent.ConfigClamped>().isEmpty())
    }

    @Test
    fun `an uninstalled dispatcher is inert`() {
        val dispatcher = TelemetryDispatcher()
        assertFalse(dispatcher.installed)
        dispatcher.emit(
            TelemetryEvent.Refresh(TelemetryEvent.RefreshRole.LEADER, 1.milliseconds),
        )
        dispatcher.startRequest("op", "POST", "/api/v1/authz/check", 1)
            .end(200, TelemetryEvent.Outcome.SUCCESS)
    }
}
