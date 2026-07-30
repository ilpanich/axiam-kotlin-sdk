package io.axiam.sdk.internal

/**
 * The §9 single-flight refresh guard (CONTRACT.md §9): at most ONE in-flight
 * `POST /api/v1/auth/refresh` across any number of concurrent coroutines that
 * observed the same stale/expired access token.
 *
 * One instance per [io.axiam.sdk.AxiamClient], shared by every request path.
 *
 * Implementation: a dedicated [SingleFlight] instance — the
 * `Mutex`-guarding-a-shared-`Deferred` mechanism §9's per-language table
 * prescribes for Kotlin. Read [SingleFlight]'s documentation for how §9 rule 6
 * (contract 1.6) is satisfied: publish-before-vacate (6a), occupancy is not
 * liveness (6b), identity-checked uncancellable vacate (6c), and a fresh
 * attempt for callers arriving after full settlement (6d). The actual network
 * refresh runs OUTSIDE the mutex, and in the guard's own scope rather than in
 * whichever caller happened to be elected leader — so cancelling one caller
 * can never strand the others.
 *
 * **No retry loop (§9.3):** a failing refresh hands every waiter that same
 * failure, as the original throwable instance, and the guard does not
 * re-attempt. The caller must re-authenticate.
 */
class RefreshGuard {

    private val flight = SingleFlight<TokenPair>()

    // The last successfully refreshed pair. @Volatile so a hot-path reader
    // (cachedAccessToken) sees the refreshing coroutine's write.
    @Volatile
    private var current: TokenPair? = null

    /** Non-blocking read of the last cached access token, or `null`. */
    fun cachedAccessToken(): String? = current?.access

    /**
     * Visible-for-testing seam; see [SingleFlight.afterPublishHook]. Never set
     * in production.
     */
    internal var afterPublishHook: (() -> Unit)?
        get() = flight.afterPublishHook
        set(value) {
            flight.afterPublishHook = value
        }

    /**
     * Ensures exactly one call to [doRefresh] is in flight at a time.
     *
     * Double-check: if another coroutine already refreshed while this one waited
     * for the mutex (the cached token no longer equals what this caller observed
     * as stale), the cached pair is returned without a new refresh.
     *
     * [current] is published BEFORE the shared outcome reaches any waiter and
     * therefore before the in-flight slot is vacated, so a caller arriving at
     * any instant either joins the one attempt or finds the fresh pair already
     * cached — never "slot empty and nothing cached", the only state that would
     * let it issue a redundant second refresh (§9 rule 6a).
     *
     * @param observedAccessToken the token this caller observed as stale/rejected
     * @param doRefresh           performs the real refresh POST; invoked at most
     *                            once per single-flight round, outside the mutex
     * @return the resolved (freshly refreshed or already-current) token pair
     * @throws io.axiam.sdk.errors.AxiamException whatever [doRefresh] throws,
     *   delivered to every waiter as-is (§9.3)
     */
    suspend fun refreshIfNeeded(
        observedAccessToken: String,
        doRefresh: suspend () -> TokenPair,
    ): TokenPair = flight.run(
        // Someone already refreshed while we waited for the lock.
        fastPath = { current?.takeIf { it.access != observedAccessToken } },
        beforePublish = { current = it },
        block = doRefresh,
    )
}
