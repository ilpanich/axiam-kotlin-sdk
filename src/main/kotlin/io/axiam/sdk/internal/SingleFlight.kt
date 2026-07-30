package io.axiam.sdk.internal

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * The one implementation of CONTRACT.md §9's single-flight coalescer for this
 * SDK: a kotlinx.coroutines [Mutex] guarding a shared [CompletableDeferred]
 * (the mechanism §9's per-language table prescribes for Kotlin). Every
 * coalesced operation in the SDK — the §1 cookie-session refresh
 * ([RefreshGuard]), the §12 `oidcRefresh`, and the §12.1 discovery fetch —
 * uses its own INSTANCE of this class (§9 rule 5 explicitly permits a
 * dedicated instance per token namespace), so the invariants below are
 * implemented and tested exactly once.
 *
 * A burst of N concurrent callers produces exactly ONE invocation of the work
 * block, and all N receive that invocation's outcome — success or failure, the
 * original throwable instance, no wrapper and no retry (§9 rules 1–3). The
 * work block runs OUTSIDE [mutex]: the lock is only ever held for the short
 * start/join decision and for the equally short vacate, never across the
 * network call.
 *
 * ## §9 rule 6 (contract 1.6) — the four invariants, and how each is met here
 *
 * **(a) Publish-before-vacate.** [inFlight] is a result-sharing channel, not a
 * busy flag. The outcome is handed to [CompletableDeferred.complete] *before*
 * the slot is cleared, so a caller arriving at any instant either finds the
 * slot occupied and joins the one outcome, or finds it empty — never "empty
 * while a just-settled outcome has not reached its waiters", the state that is
 * indistinguishable from "nothing has run yet" and would let a caller start a
 * SECOND wire call against an already-consumed, single-use refresh token. The
 * price is a short window in which the slot references an already-settled
 * `Deferred`; that window is intended, and joining it is correct.
 *
 * **(b) Occupancy is not liveness.** Nothing in this SDK asks "is a refresh on
 * the wire?" — there is no operation that must be mutually exclusive with a
 * live refresh (`oidcRefresh` runs on its own instance rather than composing
 * with [RefreshGuard], so the Java port's `runExclusive` has no counterpart
 * here). [inFlight] is therefore read at exactly ONE place, [run]'s start/join
 * decision, where "non-null" correctly means "join", never "busy". Any future
 * caller that genuinely needs liveness MUST test
 * `deferred.isActive`/`isCompleted`, not nullness.
 *
 * **(c) Only the current owner clears its own slot.** The vacate is
 * identity-checked (`inFlight === slot`) so a lagging attempt can never clear
 * a newer attempt's entry, and it runs inside [NonCancellable]: acquiring
 * [mutex] is a cancellable suspension point, so without that a worker unwound
 * by cancellation could throw *before* clearing and leave a settled outcome
 * parked in the slot forever, which every later caller would then be handed
 * (a rule 6d violation) with no wire call ever happening again.
 *
 * **(d) A caller arriving after full settlement gets a fresh attempt.** Once
 * the slot is vacated it is `null`, so the next caller becomes a new leader and
 * runs its own work block. Nothing caches the settled `Deferred` — [fastPath]
 * caches *values* (a token pair, a discovery document), never the in-flight
 * slot.
 *
 * ## Cancellation and structured concurrency
 *
 * The work block does NOT run in the coroutine of whichever caller happened to
 * be elected leader. It runs in [scope], this instance's own
 * [SupervisorJob]-rooted scope, and every caller — leader included — simply
 * awaits the shared slot. That is what makes rule 2 hold under cancellation:
 *
 *  - Cancelling ANY caller cancels only its own [CompletableDeferred.await];
 *    the single in-flight attempt, the slot, and every other caller are
 *    untouched. Callers are peers, so no caller's [kotlinx.coroutines.Job] can
 *    take the shared attempt down with it — the classic coroutine coalescer
 *    hazard, and doubly wrong for a refresh whose wire call is a *blocking*,
 *    non-interruptible OkHttp `Call.execute()`: cancelling the caller does not
 *    abort the request, it only discards a result the server has already
 *    rotated the refresh token for.
 *  - No caller ever observes a foreign [kotlinx.coroutines.CancellationException]
 *    as "the refresh's outcome": the outcome is modelled as a [Result] carried
 *    by a `Deferred` that is only ever completed *successfully*, so
 *    [CompletableDeferred.await] never resumes with another coroutine's
 *    cancellation. Waiters see either the value or the original throwable.
 *  - [scope] is never cancelled (this SDK exposes no client-close API), so the
 *    worker always runs to its vacate.
 */
internal class SingleFlight<T : Any> private constructor(private val scope: CoroutineScope) {

    /**
     * @param context dispatcher/context for the work block. Defaults to
     *   [Dispatchers.IO] because every current work block ends in a blocking
     *   OkHttp call; tests may substitute their own.
     */
    constructor(context: CoroutineContext = Dispatchers.IO) :
        this(CoroutineScope(SupervisorJob() + context + CoroutineName("axiam-single-flight")))

    private val mutex = Mutex()

    /**
     * The shared outcome of the attempt currently being coalesced, or `null`.
     * Read and written ONLY under [mutex], and only by [run]/[start] — see
     * rule (b) above on why nothing else may consult it.
     */
    private var inFlight: CompletableDeferred<Result<T>>? = null

    /**
     * Visible-for-testing seam: invoked on the worker immediately after the
     * outcome has been published to waiters and while the worker holds no lock
     * — i.e. exactly inside rule (a)'s "settled slot still occupied" window.
     * Lets a test pin that window open deterministically instead of racing for
     * it. **Never set in production** (always `null`).
     */
    @Volatile
    internal var afterPublishHook: (() -> Unit)? = null

    /**
     * Coalesces [block] (§9 rules 1–3).
     *
     * @param fastPath consulted under [mutex] before the start/join decision;
     *   a non-null return short-circuits with no attempt at all (the §1
     *   observed-token double-check, the §12.1 discovery TTL cache).
     * @param beforePublish applied to a SUCCESSFUL outcome on the worker,
     *   before the outcome reaches any waiter and therefore before the slot is
     *   vacated — so a caller that finds the slot already empty is guaranteed
     *   to see the value this stored (rule (a) for cache-backed callers).
     * @param block the actual work; invoked at most once per coalesced burst,
     *   never under [mutex].
     * @return [block]'s value, shared by every caller in the burst.
     * @throws Throwable whatever [block] threw — the original instance, handed
     *   to every caller in the burst, never retried (§9.3).
     */
    suspend fun run(
        fastPath: () -> T? = { null },
        beforePublish: (T) -> Unit = {},
        block: suspend () -> T,
    ): T {
        val shared = mutex.withLock {
            fastPath()?.let { return it }
            inFlight ?: start(beforePublish, block)
        }
        // Awaited OUTSIDE the mutex: a waiter never holds the lock it (or the
        // worker's vacate) would otherwise need. `getOrThrow` rethrows the
        // original throwable as-is (§9.3).
        return shared.await().getOrThrow()
    }

    /** Elects this caller's attempt as leader and starts it. Caller MUST hold [mutex]. */
    private fun start(beforePublish: (T) -> Unit, block: suspend () -> T): CompletableDeferred<Result<T>> {
        val slot = CompletableDeferred<Result<T>>()
        inFlight = slot
        scope.launch {
            val outcome = runCatching { block() }
            outcome.getOrNull()?.let(beforePublish)
            // (a) publish FIRST — waiters can now be served ...
            slot.complete(outcome)
            afterPublishHook?.invoke()
            // ... (c) and only THEN vacate: uncancellably, and only our own entry.
            withContext(NonCancellable) {
                mutex.withLock { if (inFlight === slot) inFlight = null }
            }
        }
        return slot
    }
}
