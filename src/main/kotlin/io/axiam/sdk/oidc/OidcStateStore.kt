package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import java.util.concurrent.ConcurrentHashMap
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
 */
data class OidcStateEntry(
    val state: String,
    val nonce: String,
    val codeVerifier: Sensitive<String>,
    val redirectUri: String,
    val returnTo: String? = null,
)

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
 */
class MemoryOidcStateStore(ttlMs: Long = OIDC_STATE_TTL_MS) : OidcStateStore {

    private val ttlMs: Long = ttlMs.coerceAtMost(OIDC_STATE_TTL_MS)
    private val entries = ConcurrentHashMap<String, Held>()
    private val sweepLock = ReentrantLock()

    private class Held(val entry: OidcStateEntry, val expiresAtEpochMs: Long)

    /** Number of unexpired entries currently held. Intended for tests and metrics. */
    val size: Int
        get() {
            sweep()
            return entries.size
        }

    override suspend fun save(entry: OidcStateEntry) {
        sweep()
        entries[entry.state] = Held(entry, System.currentTimeMillis() + ttlMs)
    }

    /**
     * Atomically returns and deletes the entry for [state]. Deletion happens
     * BEFORE the expiry check, so even an expired hit is removed rather than
     * left to accumulate, and a second call can never return the same entry
     * twice regardless of timing — [ConcurrentHashMap.remove] is itself
     * atomic, so no external lock is needed for this operation.
     */
    override suspend fun consume(state: String): OidcStateEntry? {
        val held = entries.remove(state) ?: return null
        if (held.expiresAtEpochMs <= System.currentTimeMillis()) return null
        return held.entry
    }

    /** Drops every expired entry. Lazy housekeeping only — no background timer. */
    private fun sweep() {
        sweepLock.withLock {
            val now = System.currentTimeMillis()
            val iterator = entries.entries.iterator()
            while (iterator.hasNext()) {
                if (iterator.next().value.expiresAtEpochMs <= now) {
                    iterator.remove()
                }
            }
        }
    }
}
