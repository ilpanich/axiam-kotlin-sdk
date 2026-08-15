package io.axiam.sdk.reactor

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration

/**
 * Bounded, thread-safe, in-memory nonce-replay tracker (CONTRACT.md §8 v2, as
 * §22.2 restates it for events).
 *
 * One instance is shared across every delivery a [ReactorServer] handles — it is
 * NOT recreated per delivery — so a nonce observed on one delivery is rejected
 * as a replay on any subsequent delivery inside its TTL window.
 *
 * Entries expire [ttl] after they are first observed (the runtime supplies
 * `2 × freshnessSkew`, so a nonce cannot be replayed for as long as its
 * `issued_at` could plausibly still pass the freshness check). Pruning is
 * opportunistic — amortized across calls, not a background thread — and the map
 * is bounded by [maxTrackedNonces] to cap worst-case memory use under a flood of
 * distinct nonces.
 *
 * @param ttl how long a nonce stays replay-rejecting; must be positive.
 * @param maxTrackedNonces cap on concurrently-tracked nonces; must be positive.
 */
public class ReactorNonceStore(
    private val ttl: Duration,
    private val maxTrackedNonces: Int = DEFAULT_MAX_TRACKED_NONCES,
) {

    init {
        require(ttl.isPositive()) { "ttl must be positive" }
        require(maxTrackedNonces > 0) { "maxTrackedNonces must be positive" }
    }

    private val seenUntil = ConcurrentHashMap<String, Instant>()
    private val callCount = AtomicLong()

    /**
     * Records [nonce] as seen at [now].
     *
     * Atomic per key via [ConcurrentHashMap.compute]: concurrent deliveries
     * carrying the same nonce cannot both be reported fresh.
     *
     * @return `true` when the nonce had not been seen inside its window, `false`
     *   when it is a replay
     */
    public fun observe(nonce: String, now: Instant): Boolean {
        pruneIfDue(now)
        val expiry = now.plusMillis(ttl.inWholeMilliseconds)
        var replay = false
        seenUntil.compute(nonce) { _, existing ->
            if (existing != null && existing.isAfter(now)) {
                replay = true
                existing
            } else {
                expiry
            }
        }
        return !replay
    }

    /**
     * @return the number of nonces currently held, expired-but-unpruned included
     */
    public fun size(): Int = seenUntil.size

    private fun pruneIfDue(now: Instant) {
        val overCapacity = seenUntil.size >= maxTrackedNonces
        val periodicDue = callCount.incrementAndGet() % PRUNE_EVERY_N_CALLS == 0L
        if (overCapacity || periodicDue) {
            seenUntil.entries.removeIf { !it.value.isAfter(now) }
        }
    }

    public companion object {
        /** Default cap on distinct in-flight nonces tracked at once. */
        public const val DEFAULT_MAX_TRACKED_NONCES: Int = 100_000

        private const val PRUNE_EVERY_N_CALLS = 256L
    }
}
