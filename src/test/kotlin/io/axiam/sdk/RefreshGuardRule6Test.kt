package io.axiam.sdk

import io.axiam.sdk.internal.RefreshGuard
import io.axiam.sdk.internal.TokenPair
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * CONTRACT.md §9 rule 6 (contract 1.6) conformance for the §1 cookie-session
 * [RefreshGuard]: publish-before-vacate (6a), occupancy-is-not-liveness (6b),
 * only-the-owner-clears (6c), and a post-settlement arrival gets its own fresh
 * attempt (6d) — with the wire-call COUNT asserted, not just the value.
 *
 * The scenarios here are the cancellation ones, which is where a coroutine
 * coalescer differs from a thread-based one: a `Deferred` shared between
 * callers must not couple any waiter's fate to the *initiating* caller's
 * [kotlinx.coroutines.Job].
 */
class RefreshGuardRule6Test {

    private fun pair(access: String) =
        TokenPair(access, "$access-refresh", System.currentTimeMillis() + 60_000)

    /**
     * A refresh whose wire call is NOT interruptible — the shape
     * `SessionState.doHttpRefresh` really has (a blocking OkHttp
     * `Call.execute()` inside `withContext(Dispatchers.IO)`). Cancelling the
     * calling coroutine cannot abort the request; it only makes `withContext`
     * discard the already-obtained result on the way out.
     */
    private class Wire(private val calls: AtomicInteger, private val access: String = "new-access") {
        val onWire = CountDownLatch(1)
        val release = CountDownLatch(1)

        val doRefresh: suspend () -> TokenPair = {
            withContext(Dispatchers.IO) {
                calls.incrementAndGet()
                onWire.countDown()
                check(release.await(10, TimeUnit.SECONDS)) { "wire gate never released" }
                TokenPair(access, "$access-refresh", System.currentTimeMillis() + 60_000)
            }
        }
    }

    @Test
    fun `a cancelled leader must not strand the waiters coalesced into its refresh`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val wire = Wire(calls)
        // Independent jobs: cancelling one caller must not cancel the other.
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { guard.refreshIfNeeded("stale-access", wire.doRefresh) }
            check(wire.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached the wire" }

            val waiter = callers.async { guard.refreshIfNeeded("stale-access", wire.doRefresh) }
            delay(300) // let the waiter coalesce into the leader's in-flight slot
            assertEquals(1, calls.get(), "the waiter must coalesce, not start a second wire call (§9 rule 1)")

            // The caller that happened to be elected leader goes away.
            leader.cancel()
            wire.release.countDown() // the one wire call now completes successfully

            val outcome = runCatching { waiter.await() }

            assertEquals(1, calls.get(), "still exactly one wire call (§9 rule 1)")
            assertTrue(outcome.isSuccess) {
                "§9 rule 2: the waiter must receive the single refresh's outcome; the initiating " +
                    "caller's cancellation is not that outcome. Got: ${outcome.exceptionOrNull()}"
            }
            assertEquals("new-access", outcome.getOrThrow().access)
        } finally {
            callers.cancel()
        }
    }

    @Test
    fun `a cancelled leader still vacates its slot so the next caller refreshes afresh`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val first = Wire(calls, access = "first-access")
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { guard.refreshIfNeeded("stale-access", first.doRefresh) }
            check(first.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached the wire" }
            leader.cancel()
            first.release.countDown()
            runCatching { leader.await() }
            delay(300) // let the cancelled leader finish unwinding

            // §9 rule 6d: a caller arriving after full settlement performs its OWN attempt.
            val second = Wire(calls, access = "second-access")
            second.release.countDown()
            val fresh = guard.refreshIfNeeded("first-access", second.doRefresh)

            assertEquals(2, calls.get(), "§9 rule 6d: the post-settlement caller must refresh afresh")
            assertEquals("second-access", fresh.access, "§9 rule 6d: not a previous burst's outcome")
        } finally {
            callers.cancel()
        }
    }

    /**
     * §9 rule 6a + 6d for the §1 guard, with the window pinned open by the
     * visible-for-testing `afterPublish` hook rather than raced for.
     *
     * Note the extra §1-specific guarantee proven here: [RefreshGuard] caches
     * the fresh pair BEFORE the outcome reaches waiters, so a caller arriving
     * anywhere in the sequence either joins the one attempt or finds the fresh
     * token already cached — never "slot empty and nothing cached", the only
     * state that would let it issue a redundant second refresh.
     */
    @Test
    fun `the publish-before-vacate window joins, and a post-vacate caller refreshes afresh`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val doRefresh: suspend () -> TokenPair = {
            pair("access-${calls.incrementAndGet()}")
        }

        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        guard.afterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val first = callers.async { guard.refreshIfNeeded("stale-access", doRefresh) }
            check(windowOpen.await(10, TimeUnit.SECONDS)) { "outcome was never published" }
            assertEquals("access-1", first.await().access)

            // --- inside the window: the slot still holds the SETTLED outcome ---
            // "stale-access" keeps the observed-token double-check from
            // short-circuiting, so this caller genuinely reaches the slot.
            val late = callers.async { guard.refreshIfNeeded("stale-access", doRefresh) }
            delay(300)
            assertEquals(1, calls.get(), "§9 rule 6a: a caller inside the window must join, not re-call")
            assertEquals("access-1", late.await().access, "§9 rule 2: the one outcome")

            // --- after full settlement: a new caller must refresh afresh ---
            guard.afterPublishHook = null
            releaseWindow.countDown()
            delay(500) // let the worker finish its (uncancellable, identity-checked) vacate

            val afterVacate = guard.refreshIfNeeded("access-1", doRefresh)
            assertEquals(2, calls.get(), "§9 rule 6d: a post-settlement caller runs its own attempt")
            assertEquals("access-2", afterVacate.access, "§9 rule 6d: its OWN outcome, not the prior burst's")
        } finally {
            guard.afterPublishHook = null
            releaseWindow.countDown()
            callers.cancel()
        }
    }

    /**
     * §9 rule 6b — occupancy is not liveness. [RefreshGuard.cachedAccessToken]
     * is the only other reader anywhere near the guard, and it reads the cached
     * PAIR, never the in-flight slot; while the settled-but-uncleared slot sits
     * in rule 6a's window it already reports the FRESH token, so no caller can
     * mistake the window for "a refresh is still on the wire".
     */
    @Test
    fun `the settled-but-uncleared window already reports the fresh token`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val doRefresh: suspend () -> TokenPair = { pair("access-${calls.incrementAndGet()}") }

        val windowOpen = CountDownLatch(1)
        val releaseWindow = CountDownLatch(1)
        guard.afterPublishHook = {
            windowOpen.countDown()
            check(releaseWindow.await(10, TimeUnit.SECONDS)) { "window never released" }
        }

        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val first = callers.async { guard.refreshIfNeeded("stale-access", doRefresh) }
            check(windowOpen.await(10, TimeUnit.SECONDS)) { "outcome was never published" }
            assertEquals("access-1", guard.cachedAccessToken())
            assertEquals("access-1", first.await().access)
            assertEquals(1, calls.get())
        } finally {
            guard.afterPublishHook = null
            releaseWindow.countDown()
            callers.cancel()
        }
    }

    @Test
    fun `a cancelled waiter neither cancels the leader nor disturbs the slot`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val wire = Wire(calls)
        val callers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val leader = callers.async { guard.refreshIfNeeded("stale-access", wire.doRefresh) }
            check(wire.onWire.await(10, TimeUnit.SECONDS)) { "leader never reached the wire" }
            val waiter = callers.async { guard.refreshIfNeeded("stale-access", wire.doRefresh) }
            delay(300)
            assertEquals(1, calls.get())

            waiter.cancel() // this waiter's caller goes away
            wire.release.countDown()

            assertEquals("new-access", leader.await().access, "the leader must be unaffected")
            assertEquals(1, calls.get(), "exactly one wire call (§9 rule 1)")
        } finally {
            callers.cancel()
        }
    }
}
