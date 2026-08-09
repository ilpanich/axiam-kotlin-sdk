package io.axiam.sdk.internal

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.telemetry.TelemetryEvent
import kotlin.coroutines.cancellation.CancellationException
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay

/**
 * Bounded read-only retry policy — CONTRACT.md §16.
 *
 * This SDK had **no** §16 policy before D5 — only §9.3's
 * refresh-then-retry-once, which is a different mechanism (it reacts to a 401
 * by refreshing, and deliberately does not loop). §11.2 rule 5 and §14.2 rule 6
 * had both been requiring "the SDK's existing bounded read-only retry policy"
 * against a policy that did not exist here.
 */
internal object Retry {

    /** Attempt cap: 1 initial + 2 retries (§16.1). */
    const val MAX_ATTEMPTS: Int = 3

    /** First backoff step (§16.1). */
    val BASE_DELAY: Duration = 200.milliseconds

    /** Ceiling on any single computed backoff (§16.1). */
    val MAX_DELAY: Duration = 5.seconds

    /**
     * The un-jittered backoff for a 1-based [attempt]:
     * `min(MAX_DELAY, BASE_DELAY * 2^(n-1))`. Attempt 1 → 200ms, attempt 2 → 400ms.
     */
    fun backoffFor(attempt: Int): Duration {
        // Shift on the millisecond count rather than multiplying the Duration,
        // so a large attempt cannot overflow into a negative wait.
        val shifted = BASE_DELAY.inWholeMilliseconds shl (attempt - 1).coerceAtMost(32)
        return if (shifted <= 0 || shifted > MAX_DELAY.inWholeMilliseconds) MAX_DELAY
        else shifted.milliseconds
    }

    /**
     * The actual wait: **full jitter** over `[0, backoff]`, raised to any
     * server-supplied `Retry-After` (§16.1).
     *
     * Full jitter, not `backoff ± 10%`. Partial jitter keeps every client's
     * retries clustered around the same instant, which is the thundering herd
     * retries are supposed to prevent rather than cause.
     *
     * `Retry-After` is a **floor, never a ceiling**: the server is stating when
     * it will be ready, so retrying sooner is not permitted — and a
     * `Retry-After: 0` cannot shorten the wait below what jitter chose.
     *
     * @param fraction the jitter draw in `[0, 1]`, injected so tests can pin it.
     */
    fun delayFor(attempt: Int, retryAfter: Duration, fraction: Double): Duration {
        val clamped = min(max(fraction, 0.0), 1.0)
        val jittered = (backoffFor(attempt).inWholeMilliseconds * clamped).toLong().milliseconds
        return if (retryAfter > jittered) retryAfter else jittered
    }

    /**
     * Runs [op] under the §16 policy.
     *
     * [op] receives the 1-based attempt number so it can label its §19 request
     * pair — §19.2 rule 5 requires one pair per attempt so a caller can count
     * real wire calls, and passing 1 every time would make a retried call
     * indistinguishable from a single slow one.
     *
     * [op] MUST be side-effect-free. This helper — like every retry helper —
     * cannot tell the difference, so routing a mutation through it would
     * silently duplicate a side effect, or replay a single-use credential (an
     * authorization code, a device code at redemption, a rotating refresh
     * token) into a hard `invalid_grant`.
     *
     * Only [NetworkError] is retried. The §2 taxonomy folds
     * `408`/`429`/`5xx`/transport into that one type, so this implements the
     * whole §16.3 table: auth and authz failures are decisive answers from the
     * server, not transport failures.
     */
    suspend fun <T> withRetry(
        operation: String,
        enabled: Boolean,
        telemetry: TelemetryDispatcher,
        random: () -> Double = { Random.Default.nextDouble() },
        op: suspend (attempt: Int) -> T,
    ): T {
        val attempts = if (enabled) MAX_ATTEMPTS else 1
        var last: NetworkError? = null

        for (attempt in 1..attempts) {
            try {
                return op(attempt)
            } catch (e: CancellationException) {
                // Cooperative cancellation is the caller's decision, not the
                // server's failure: never retried, never swallowed.
                throw e
            } catch (e: NetworkError) {
                last = e
                if (attempt == attempts) throw e
                val wait = delayFor(attempt, e.retryAfter ?: Duration.ZERO, random())
                // §16.5 — without this a retried-then-succeeded call is
                // invisible: a slow success with no signal the server is failing.
                telemetry.emit(
                    TelemetryEvent.Retry(
                        operation = operation,
                        attempt = attempt,
                        delay = wait,
                        reason = e.message ?: e::class.simpleName.orEmpty(),
                    ),
                )
                delay(wait)
            }
        }
        throw last ?: NetworkError("retry loop exhausted without a result")
    }
}
