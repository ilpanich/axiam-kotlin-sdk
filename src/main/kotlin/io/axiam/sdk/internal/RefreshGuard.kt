package io.axiam.sdk.internal

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The §9 single-flight refresh guard (CONTRACT.md §9): at most ONE in-flight
 * `POST /api/v1/auth/refresh` across any number of concurrent coroutines that
 * observed the same stale/expired access token.
 *
 * One instance per [io.axiam.sdk.AxiamClient], shared by every request path.
 *
 * Implementation: a kotlinx.coroutines [Mutex] guards the decision of whether
 * to *start* a refresh or *join* one already in flight; the shared in-flight
 * result is a [CompletableDeferred] that all waiters `await()`. The actual
 * network refresh runs OUTSIDE the mutex (the mutex is only held for the short
 * start/join decision), so the refresh never serializes unrelated work behind
 * the lock and waiters never hold the mutex while blocked.
 *
 * **No retry loop (§9.3):** a failing refresh completes the shared deferred
 * exceptionally; every waiter receives that same failure, and the guard does
 * not re-attempt. The caller must re-authenticate.
 */
class RefreshGuard {

    private val mutex = Mutex()

    // The last successfully refreshed pair; a plain reference read under/without
    // the mutex for the double-check. @Volatile so a hot-path reader sees writes.
    @Volatile
    private var current: TokenPair? = null

    // Non-null only while a refresh is actually in flight.
    private var inFlight: CompletableDeferred<TokenPair>? = null

    /** Non-blocking read of the last cached access token, or `null`. */
    fun cachedAccessToken(): String? = current?.access

    /**
     * Ensures exactly one call to [doRefresh] is in flight at a time.
     *
     * Double-check: if another coroutine already refreshed while this one waited
     * for the mutex (the cached token no longer equals what this caller observed
     * as stale), the cached pair is returned without a new refresh.
     *
     * @param observedAccessToken the token this caller observed as stale/rejected
     * @param doRefresh           performs the real refresh POST; invoked at most
     *                            once per single-flight round, outside the mutex
     * @return the resolved (freshly refreshed or already-current) token pair
     * @throws AxiamException whatever [doRefresh] throws, delivered to every waiter (§9.3)
     */
    suspend fun refreshIfNeeded(
        observedAccessToken: String,
        doRefresh: suspend () -> TokenPair,
    ): TokenPair {
        val leaderDeferred: CompletableDeferred<TokenPair>?
        val joinTarget: CompletableDeferred<TokenPair>

        mutex.withLock {
            val snapshot = current
            if (snapshot != null && snapshot.access != observedAccessToken) {
                // Someone already refreshed while we waited for the lock.
                return snapshot
            }
            val existing = inFlight
            if (existing != null) {
                leaderDeferred = null
                joinTarget = existing
            } else {
                val fresh = CompletableDeferred<TokenPair>()
                inFlight = fresh
                leaderDeferred = fresh
                joinTarget = fresh
            }
        }

        if (leaderDeferred == null) {
            // Waiter: share the single in-flight result (success or failure).
            return joinTarget.await()
        }

        // Leader: run the actual refresh OUTSIDE the mutex.
        return try {
            val result = doRefresh()
            current = result
            leaderDeferred.complete(result)
            result
        } catch (t: Throwable) {
            leaderDeferred.completeExceptionally(t)
            throw t
        } finally {
            mutex.withLock { inFlight = null }
        }
    }
}
