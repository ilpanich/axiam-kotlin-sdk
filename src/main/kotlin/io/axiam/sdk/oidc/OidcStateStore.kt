package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * `OidcStateStore` + `MemoryOidcStateStore` (CONTRACT.md §12.3 rule 1).
 *
 * STRICTLY OPTIONAL. The nine §12 operations never touch a store: `oidcBegin`
 * and `oidcExchange` are stateless by contract, and the caller normally keeps
 * `state`/`nonce`/`codeVerifier` in its own HTTP session. This store exists
 * for the framework glue ([io.axiam.sdk.ktor.axiamOidcLogin]), where a login
 * and its callback are two separate HTTP requests with nothing but a `state`
 * value linking them.
 *
 * Semantics mirror the server's `federation_login_state` table exactly:
 * 10-minute TTL, single-use consume.
 */

/**
 * The tuple an [OidcStateStore] holds for one in-flight login.
 *
 * [codeVerifier] stays [Sensitive] while stored (§12.5: the verifier is
 * secret for its whole lifetime, "including … in any `OidcStateStore` entry"),
 * so serializing an entry — e.g. into a Redis-backed store — never emits the
 * verifier by accident; a store implementation that needs to persist the
 * value must call [Sensitive.expose] explicitly and is then responsible for
 * protecting it at rest.
 *
 * @property state the `state` value this entry is keyed by. Not a secret (§12.3 rule 2)
 * @property nonce the `nonce` to check the ID token's `nonce` claim against. Not a secret (§12.3 rule 2)
 * @property codeVerifier the PKCE verifier for the matching authorization request (§12.5 secret)
 * @property redirectUri the `redirect_uri` that was sent on the authorization request and must be replayed on exchange
 * @property returnTo optional application-owned data, e.g. the page the user was heading to before login
 * @property bindingDigest optional (contract 1.68, §12.8 rule 1; C7): lower-case hex SHA-256 of the
 *   browser-binding cookie value the login glue set for the browser that began this login. The
 *   callback compares it, in constant time, with the cookie the callback request presents, and
 *   refuses an entry that has none. It is not secret but is never logged. **A caller-supplied store
 *   MUST persist and return it unchanged**: one that rebuilds entries from a fixed column list and
 *   drops it refuses every sign-in — loudly, which is the safe failure. It is optional so that a
 *   store written for 1.3.x still compiles and an entry without it can still be read.
 */
data class OidcStateEntry(
    val state: String,
    val nonce: String,
    val codeVerifier: Sensitive<String>,
    val redirectUri: String,
    val returnTo: String? = null,
    val bindingDigest: String? = null,
) {
    /**
     * The 1.3.1 five-argument constructor, kept so a store compiled against 1.3.x
     * (it rebuilds entries with this arity) still links; the entry then has no
     * [bindingDigest] and the login glue refuses it, loudly (§12.8 rule 1). Hidden
     * from source (the primary constructor serves it); it also keeps the 1.3.1
     * default-argument bridge (`…, int, DefaultConstructorMarker`) that a caller
     * compiled against 1.3.x with `returnTo` omitted uses.
     */
    @Deprecated("Binary compatibility with 1.3.1 only.", level = DeprecationLevel.HIDDEN)
    constructor(
        state: String,
        nonce: String,
        codeVerifier: Sensitive<String>,
        redirectUri: String,
        returnTo: String? = null,
    ) : this(state, nonce, codeVerifier, redirectUri, returnTo, null)
}

/**
 * Optional server-side store for in-flight `oidcBegin` state (CONTRACT.md
 * §12.3 rule 1).
 *
 * Implement this to back the login/callback handlers with your own storage
 * (Redis, a database, an encrypted cookie). Two invariants are normative:
 *
 * 1. **Single-use.** [consume] MUST return the entry AND delete it atomically,
 *    so a replayed callback cannot reuse a `state`.
 * 2. **Expiry.** An entry older than 10 minutes MUST NOT be returned.
 */
interface OidcStateStore {
    /** Persists [entry], keyed by its `state`, starting its TTL now. */
    suspend fun save(entry: OidcStateEntry)

    /**
     * Atomically fetches AND REMOVES the entry for [state]. Returns `null`
     * when the state is unknown, already consumed, or expired — three cases a
     * caller MUST treat identically (as a failed login), because
     * distinguishing them leaks whether a `state` ever existed.
     */
    suspend fun consume(state: String): OidcStateEntry?
}

/**
 * The contract-mandated MAXIMUM TTL for stored login state: 10 minutes,
 * matching the server's `federation_login_state` row lifetime (§12.3 rule 1).
 */
const val OIDC_STATE_TTL_MS: Long = 600_000L

/**
 * In-memory reference implementation of [OidcStateStore] (CONTRACT.md §12.3
 * rule 1).
 *
 * Per-instance (never process-global), single-use, TTL-bounded. Expired
 * entries are dropped lazily on [save]/[consume] — there is NO background
 * timer/thread, since a library must not keep the host process alive on its
 * own.
 *
 * Suitable for a single-process app and for tests. A multi-instance
 * deployment needs a shared store (Redis, a database) — implement
 * [OidcStateStore] yourself for that; nothing in the SDK assumes this class.
 *
 * @param ttlMs entry lifetime in milliseconds. Defaults to [OIDC_STATE_TTL_MS]
 *   (10 minutes) and is CLAMPED to it: a shorter TTL is honoured (useful in
 *   tests), a longer one is reduced, because §12.3 rule 1 fixes 10 minutes as
 *   the maximum.
 * @param maxEntries the most entries held at once (default
 *   [DEFAULT_MAX_ENTRIES]); when full, [save] evicts the oldest entry. The login route is unauthenticated and every call saves one entry,
 *   so an unbounded map is a memory-exhaustion lever.
 */
class MemoryOidcStateStore(
    ttlMs: Long = OIDC_STATE_TTL_MS,
    maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : OidcStateStore {

    /** The 1.3.1 one-argument constructor `MemoryOidcStateStore(long)`, kept for binary compatibility. */
    constructor(ttlMs: Long) : this(ttlMs, DEFAULT_MAX_ENTRIES)

    private val maxEntries: Int = maxEntries.coerceAtLeast(1)

    private val ttlMs: Long = ttlMs.coerceAtMost(OIDC_STATE_TTL_MS)

    // Insertion-ordered, and every entry lives for the same TTL, so the head is
    // always the oldest AND the first to expire: eviction and the expiry sweep
    // are O(1) per removed entry instead of a scan. Every access holds [lock], so
    // the bound is checked and enforced in one critical section.
    private val entries = LinkedHashMap<String, Held>()
    private val lock = ReentrantLock()

    private class Held(val entry: OidcStateEntry, val expiresAtEpochMs: Long)

    /** Number of unexpired entries currently held. Intended for tests and metrics. */
    val size: Int
        get() = lock.withLock {
            sweepLocked()
            entries.size
        }

    override suspend fun save(entry: OidcStateEntry) {
        lock.withLock {
            sweepLocked()
            // A re-save of a live state replaces it (and counts as the newest).
            entries.remove(entry.state)
            while (entries.size >= maxEntries) {
                val eldest = entries.entries.iterator()
                eldest.next()
                eldest.remove()
            }
            entries[entry.state] = Held(entry, System.currentTimeMillis() + ttlMs)
        }
    }

    /**
     * Atomically returns and deletes the entry for [state]. Deletion happens
     * BEFORE the expiry check, so even an expired hit is removed rather than
     * left to accumulate, and a second call can never return the same entry
     * twice regardless of timing.
     */
    override suspend fun consume(state: String): OidcStateEntry? {
        val held = lock.withLock { entries.remove(state) } ?: return null
        if (held.expiresAtEpochMs <= System.currentTimeMillis()) return null
        return held.entry
    }

    /** Drops every expired entry from the head. Lazy housekeeping only — no background timer. Caller holds [lock]. */
    private fun sweepLocked() {
        val now = System.currentTimeMillis()
        val iterator = entries.entries.iterator()
        while (iterator.hasNext() && iterator.next().value.expiresAtEpochMs <= now) {
            iterator.remove()
        }
    }

    companion object {
        /** The default bound on live entries. */
        const val DEFAULT_MAX_ENTRIES: Int = 10_000
    }
}
