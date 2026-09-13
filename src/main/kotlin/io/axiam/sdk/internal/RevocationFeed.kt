package io.axiam.sdk.internal

import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * A poller for one deployment's session-revocation feed (CONTRACT.md §10.4,
 * contract 1.44 — AXIAM threats T-39 and T-143).
 *
 * ## What this narrows, and what it is not
 *
 * An AXIAM access token is self-contained and valid for up to fifteen minutes,
 * and [io.axiam.sdk.AxiamClient.verifySession] verifies it locally. A logout, a
 * role removal or an account disable therefore does not reach a token already in
 * a caller's hands until it expires — §10.2 records that, and the documented
 * answer has been "route the decision through gRPC introspection instead", which
 * is correct and costs a round trip **per request**.
 *
 * A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded
 * SHA-256 of every session id revoked within the last access-token lifetime. A
 * guard that polls it rejects a revoked session within **one poll interval**
 * instead of one token lifetime, for one cacheable fetch per interval.
 *
 * It is **not a control**, and every rule below follows from that:
 *
 *  * **Default off.** Nothing polls unless a caller attaches one with
 *    [io.axiam.sdk.AxiamClient.Builder.revocationFeed].
 *  * **Never on the request path.** [isRevoked] answers from the cached set.
 *  * **Never fail closed.** An unreachable feed, a non-200, a body that does not
 *    parse, an `alg` this build does not know — every one of them behaves
 *    exactly as no feed at all. Not as an empty list: an empty list asserts that
 *    nothing has been revoked, which is a guard that silently honours no
 *    revocations while appearing to honour them.
 *  * **It only ever rejects.** Every §10.1 rule runs first and still decides.
 *  * **A token with no `sid` is never matched.** There is no session behind a
 *    client-credentials token, an RPT or a token exchange, and hashing `jti`
 *    instead would match nothing while looking like it worked.
 *
 * Thread-safe, and meant to be shared: several guards built from one feed poll
 * once between them rather than once each.
 *
 * @param httpClient the client to fetch through, so a caller that pins a proxy,
 *        a timeout or a CA bundle keeps them here too.
 * @param baseUrl the AXIAM server base URL (trailing slash tolerated).
 * @param pollIntervalSeconds how often a check after this long refetches;
 *        anything below [MIN_POLL_INTERVAL_SECONDS] is raised to it rather than
 *        refused.
 */
class RevocationFeed(
    private val httpClient: OkHttpClient,
    baseUrl: String,
    pollIntervalSeconds: Long = DEFAULT_POLL_INTERVAL_SECONDS,
) {

    /** The feed document's URL, for diagnostics. */
    val feedUrl: String = baseUrl.trimEnd('/') + FEED_PATH

    /** The poll interval actually in force, after the floor is applied. */
    val pollIntervalSeconds: Long = maxOf(pollIntervalSeconds, MIN_POLL_INTERVAL_SECONDS)

    /**
     * The monotonic clock the staleness check reads, in nanoseconds. A testing
     * seam only — internal so it can never be reached from configuration —
     * exposed so a test can age the cache without sleeping fifteen seconds,
     * which is a test nobody runs.
     */
    internal var nanoTime: () -> Long = System::nanoTime

    /**
     * `null` means "never successfully fetched", which is NOT the same as a
     * fetched-but-empty document, and is why this is nullable rather than an
     * always-present set.
     */
    @Volatile private var entries: Set<String>? = null

    @Volatile private var lastAttemptNanos: Long? = null

    /**
     * Serializes refreshers, so a burst of guards that all notice the cache is
     * stale produces one fetch rather than one each — the same shape as
     * [JwksVerifier]'s refresh lock, and for the same reason.
     */
    private val fetchLock = ReentrantLock()

    /**
     * Has this session been revoked, as far as this poller knows?
     *
     * `false` whenever the answer is not a confident yes — a feed never fetched,
     * unreachable, malformed, or simply not listing this session. The caller
     * admits the request in all of those cases, which is §10.4 rule 3 and is the
     * whole reason the feature is safe to turn on.
     *
     * A blank `sid` is never matched: there is no session behind one.
     */
    fun isRevoked(sid: String?): Boolean {
        if (sid.isNullOrEmpty()) return false
        refreshIfStale()
        return entries?.contains(entryFor(sid)) == true
    }

    /**
     * Fetch now, whatever the interval says. For tests, and for a caller that
     * wants the first poll to have happened before it starts serving.
     */
    fun refresh() {
        fetchLock.withLock {
            val fetched = fetchOnce()
            lastAttemptNanos = nanoTime()
            // On failure the previous set is deliberately left in place: a blip
            // must not un-revoke a session the guard already knows about.
            if (fetched != null) entries = fetched
        }
    }

    /**
     * Refetches if the poll interval has elapsed since the last *attempt*.
     *
     * Attempt, not success: a feed that is down must not be retried on every
     * request, which would put the request path back on the network — the cost
     * §10.4 exists to avoid.
     */
    private fun refreshIfStale() {
        val last = lastAttemptNanos
        if (last != null && nanoTime() - last < pollIntervalSeconds * NANOS_PER_SECOND) return
        refresh()
    }

    /**
     * One fetch. `null` for every kind of failure, which the caller treats
     * identically — see the class documentation on why "unusable" must not
     * collapse into "empty".
     */
    private fun fetchOnce(): Set<String>? {
        val body = try {
            httpClient.newCall(Request.Builder().url(feedUrl).get().build()).execute().use { response ->
                if (!response.isSuccessful) return null
                response.body?.string() ?: return null
            }
        } catch (_: Exception) {
            // Every failure mode is the same answer, deliberately: an
            // unreachable host, a timeout, a truncated body. Reporting them
            // apart would invite a caller to treat one of them as a denial.
            return null
        }

        val document = try {
            LENIENT_JSON.parseToJsonElement(body).jsonObject
        } catch (_: Exception) {
            return null
        }
        if (document["alg"]?.jsonPrimitive?.contentOrNull != SUPPORTED_ALG) return null
        val revoked = try {
            document["revoked"]?.jsonArray ?: return null
        } catch (_: Exception) {
            return null
        }
        // Overflow drops the WHOLE set rather than truncating it: a truncated
        // set is a guard that admits some revoked sessions and reports none,
        // which is worse than one that admits all of them and says the feed is
        // unusable.
        if (revoked.size > MAX_ENTRIES) return null
        return revoked.mapNotNull { it.jsonPrimitive.contentOrNull }.toSet()
    }

    companion object {
        /** The published feed's path, appended to a deployment's base URL. */
        const val FEED_PATH: String = "/oauth2/revocations"

        /**
         * The shortest interval a caller may configure (§10.4 rule 2).
         *
         * Bounded because the feed is one deployment-wide document and a fleet
         * of guards polling it at a hundred milliseconds is a load source rather
         * than a security improvement. The floor is applied by clamping, not by
         * refusing: a caller who asked for something faster gets the fastest
         * thing on offer.
         */
        const val MIN_POLL_INTERVAL_SECONDS: Long = 15

        /** The default interval, and the one §10.4 recommends. */
        const val DEFAULT_POLL_INTERVAL_SECONDS: Long = 30

        /**
         * The largest number of entries kept in the cache (§10.4 rule 2).
         *
         * The server bounds the document by its own revocation rate over one
         * token lifetime, so this is defence against a server that stops doing
         * so — a cache with no ceiling is an allocation an unauthenticated
         * endpoint controls.
         */
        const val MAX_ENTRIES: Int = 100_000

        /**
         * The only digest the feed publishes, and the only one this poller
         * accepts.
         *
         * A document naming anything else is treated as unusable — exactly as an
         * unreachable feed is — rather than as a list of entries that happen not
         * to match. Silently matching nothing is how a guard ends up reporting
         * that it honours revocations while honouring none.
         */
        private const val SUPPORTED_ALG: String = "SHA-256"

        private const val NANOS_PER_SECOND: Long = 1_000_000_000

        private val LENIENT_JSON = Json { ignoreUnknownKeys = true }

        /**
         * The feed entry for a [sid], as the server computes it.
         *
         * Base64url without padding over the claim's **exact string** — never a
         * parsed-and-re-rendered UUID, or the answer would depend on this SDK's
         * UUID handling rather than on the feed.
         */
        @JvmStatic
        fun entryFor(sid: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(sid.toByteArray(Charsets.UTF_8))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }
    }
}
