package io.axiam.sdk.internal

import io.axiam.sdk.AccessResult
import io.axiam.sdk.telemetry.TelemetryEvent
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Client-side decision memo — CONTRACT.md §17.
 *
 * **Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions
 * is still the default behaviour; this is the single opt-in exception that
 * section carves out, and a caller has to switch it on having read the cost.
 *
 * ## What it costs
 *
 * The staleness bound is the TTL, **in both directions**. A grant revoked on
 * the server can still read as allowed for up to the TTL, and a grant just
 * added can still read as denied for up to the TTL. That second direction is
 * the one that surprises people: **reads-your-own-writes is not guaranteed.**
 * An admin UI that grants a role and immediately re-checks is the case that
 * breaks, and it breaks silently.
 *
 * This mirrors the server's own bound rather than inventing a second staleness
 * story — `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5s) makes the same
 * trade server-side. One deliberate difference: the server's setting is an
 * unclamped integer, so an operator can configure a multi-hour staleness
 * window. [MAX_TTL] clamps this one at 5s, because the client has no reason to
 * repeat that.
 *
 * Safe for concurrent use: a Kotlin client is routinely shared across
 * coroutines on different threads, and a cache that corrupted under concurrency
 * would be a worse bug than the one it is optimising away.
 */
internal class DecisionMemo(
    ttl: Duration,
    private val now: () -> Long = { System.nanoTime() },
) {

    /** The clamped TTL in nanoseconds; zero means disabled. */
    private val ttlNanos: Long = when {
        ttl <= Duration.ZERO -> 0L
        ttl > MAX_TTL -> MAX_TTL.inWholeNanoseconds
        else -> ttl.inWholeNanoseconds
    }

    private val lock = Any()
    private val entries = LinkedHashMap<String, Entry>()

    /** Whether this memo does anything. `false` for the default configuration. */
    val enabled: Boolean get() = ttlNanos > 0

    /** The effective TTL after clamping. */
    val effectiveTtl: Duration get() = ttlNanos.nanoseconds

    /** A live decision for [key], if one is memoized and unexpired. */
    fun get(key: String): AccessResult? {
        if (!enabled) return null
        synchronized(lock) {
            val entry = entries[key] ?: return null
            if (now() - entry.storedAt >= ttlNanos) {
                entries.remove(key)
                return null
            }
            // Returned whole, including reasonCode: §17.1 rule 5 forbids
            // returning `allowed` while dropping the code, which would make the
            // field intermittently absent — worse than never having had it.
            return entry.result
        }
    }

    /**
     * Memoizes a decision the server actually returned.
     *
     * Callers must only reach here on success. §17.1 rule 7 forbids
     * negative-caching a failure: memoizing a transport error as a deny would
     * turn a blip into a TTL-long outage, and memoizing it as an allow is
     * unthinkable.
     */
    fun put(key: String, result: AccessResult) {
        if (!enabled) return
        synchronized(lock) {
            // Re-inserting moves the key to the end of LinkedHashMap iteration
            // order, which is what makes the eviction below FIFO by insertion.
            entries.remove(key)
            entries[key] = Entry(result, now())
            while (entries.size > MAX_ENTRIES) {
                val oldest = entries.keys.firstOrNull() ?: break
                entries.remove(oldest)
            }
        }
    }

    /**
     * Drops every entry (§17.1 rule 9).
     *
     * Called on login, verifyMfa, refresh and logout. Entries are keyed by
     * subject, not by session, so a re-authentication as a *different*
     * principal would otherwise read the previous principal's decisions.
     */
    fun clear() {
        synchronized(lock) { entries.clear() }
    }

    /**
     * Emits a [TelemetryEvent.ConfigClamped] if [requested] was clamped
     * (CONTRACT.md §19.2 rule 6).
     *
     * This is the clamp that matters most to get right: an operator who set a
     * 60-second TTL believes their staleness bound is 60 seconds. It is five,
     * and without this event nothing anywhere says so.
     *
     * Nothing is emitted when the requested value was already inside the limit,
     * or when the memo is disabled — an event that fires when nothing happened
     * trains its reader to ignore it.
     */
    fun reportClamp(requested: Duration, telemetry: TelemetryDispatcher) {
        if (requested <= Duration.ZERO || requested == effectiveTtl) return
        telemetry.emit(
            TelemetryEvent.ConfigClamped(
                setting = "decisionMemoTtl",
                requested = requested.toString(),
                effective = effectiveTtl.toString(),
                contractReference = "§17.1 rule 2",
            ),
        )
    }

    /** Entry count, for tests. */
    val size: Int get() = synchronized(lock) { entries.size }

    private data class Entry(val result: AccessResult, val storedAt: Long)

    internal companion object {
        /**
         * The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not
         * rejected: a caller who asked for a minute wants caching, and silently
         * giving them the maximum safe value beats failing construction.
         */
        val MAX_TTL: Duration = 5.seconds

        /**
         * Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
         * optimisation, so dropping an entry is always correct — but it must
         * drop rather than grow without bound.
         */
        const val MAX_ENTRIES: Int = 1024

        /**
         * Joins the key components. U+001F (unit separator) cannot appear in
         * an action, a UUID or a scope, so no combination of caller-supplied
         * values can forge a collision.
         */
        private const val SEP = "\u001F"

        /**
         * Marks an *absent* optional, which is why an absent scope can never
         * collide with a present one — a memo that let them collide would
         * answer a narrower question with a broader answer.
         */
        private const val ABSENT = "\u0000"

        /**
         * Builds the §17.1 rule 3 key: all four components, with absent
         * distinguished from present.
         */
        fun key(
            subjectId: String?,
            resourceId: String,
            action: String,
            scope: String?,
        ): String = buildString {
            append(subjectId ?: ABSENT).append(SEP)
            append(resourceId).append(SEP)
            append(action).append(SEP)
            append(scope ?: ABSENT)
        }
    }
}
