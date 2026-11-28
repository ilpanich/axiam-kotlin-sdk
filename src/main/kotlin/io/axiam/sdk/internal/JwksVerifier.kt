package io.axiam.sdk.internal

import com.nimbusds.jose.Header
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.withLock

/**
 * The TLS a JWKS fetch may use (CONTRACT.md §6): both factories verify the certificate chain and the host name
 * strictly. [withIdentity] also carries the §6.1 client identity; [trustOnly] never does. Internal on purpose:
 * no public input can hand the SDK a TLS configuration, only `customCa` and the client identity.
 */
internal class JwksTls(val withIdentity: SSLSocketFactory?, val trustOnly: SSLSocketFactory?)

/**
 * Local JWT verification against an EdDSA JWKS document, the §10 middleware's
 * verification primitive — extended (never forked) by [verifyForIdToken] for
 * the CONTRACT.md §12.4 ID-token validation checklist.
 *
 * Keys are fetched over `HttpURLConnection` (so the `ETag` and `Cache-Control`
 * headers are readable) and cached here: TTL 300 s by default and at most 300 s
 * (a smaller advertised `max-age` is honoured), at most ONE fetch per 60 s
 * window whatever the cause, and — CONTRACT.md §12.4 rule 2, stale-if-error —
 * a failed refresh keeps the held keys for TTL + 300 s after the last
 * SUCCESSFUL fetch and no longer. See [selectKeyOrNull].
 *
 * **Algorithm pinning:** the header `alg` is checked against an EdDSA allowlist
 * BEFORE any key lookup, so the token's own `alg` never selects the
 * verification algorithm (algorithm-confusion defense).
 *
 * **EdDSA/OKP note:** nimbus's `JWSVerificationKeySelector` cannot drive
 * Ed25519 verification (its `KeyConverter` cannot export an [OctetKeyPair] to a
 * `java.security.Key`), so — as the Java sibling SDK does — this verifier
 * matches the [OctetKeyPair] against the cached JWKS directly and constructs an
 * [Ed25519Verifier] from it.
 *
 * [verifySignatureOnlyUnchecked] verifies **signature only** — no `exp`, no
 * `nbf`, no tenant/issuer/audience binding. It is deliberately NOT the guard
 * entry point (CONTRACT.md §10.1): its name carries the omission to the call
 * site, and it exists only for integrators implementing their own policy. The
 * SDK's own §10 guard — [io.axiam.sdk.AxiamClient.verifySession] — routes
 * signature verification through it and then applies [assertLocalClaims],
 * which is the full §10.1 minimum local-verification set.
 */
class JwksVerifier private constructor(
    private val jwksUrl: URL,
    /**
     * The client's strict TLS stack (CONTRACT.md §6: the system trust store plus `customCa`, and the §6.1 identity
     * when configured), applied to an `https` fetch. `null` keeps the JVM defaults.
     */
    private val tlsSocketFactory: SSLSocketFactory?,
) {

    private val connectTimeoutMs = RemoteJWKSet.resolveDefaultHTTPConnectTimeout()
    private val readTimeoutMs = RemoteJWKSet.resolveDefaultHTTPReadTimeout()
    private val sizeLimitBytes = RemoteJWKSet.resolveDefaultHTTPSizeLimit()
    private val refreshLock = ReentrantLock()

    /** The ONE fetch in flight, if any (single-flight); guarded by [refreshLock]. */
    private var inFlight: CompletableFuture<Unit>? = null

    /**
     * One fetched key set: [atNanos] is the anchor (the last SUCCESSFUL fetch, a
     * `200` with at least one key or a `304`), [ttlNanos] the lifetime the
     * response gave it (clamped to [MAX_TTL_NANOS]), [etag] the validator sent
     * back as `If-None-Match`.
     */
    private class Cached(val keys: JWKSet, val atNanos: Long, val ttlNanos: Long, val etag: String?)

    /** The outcome of one refresh attempt; everything but [Fetched] and [NotModified] is a failed refresh. */
    private sealed interface Refresh {
        class Fetched(val keys: JWKSet, val etag: String?, val ttlNanos: Long) : Refresh
        class NotModified(val ttlNanos: Long?) : Refresh
        object Failed : Refresh
    }

    /** The last key set fetched; written only under [refreshLock], read lock-free. */
    @Volatile
    private var cached: Cached? = null

    /**
     * When the last JWKS fetch was ATTEMPTED, success or failure (the cooldown
     * window's origin); `0` until the first one. Guarded by [refreshLock].
     */
    @Volatile
    private var lastFetchNanos: Long = 0L

    /** Monotonic clock (nanoseconds) behind the cooldown and the cache ages; replaceable by tests. */
    @Volatile
    private var clockNanos: () -> Long = System::nanoTime

    /** Test seam: replaces the monotonic clock behind the unknown-`kid` cooldown. Not part of the public API. */
    internal fun setClockForTesting(clock: () -> Long) {
        clockNanos = clock
    }

    /**
     * The §10 middleware's public entry point: a verifier bound to
     * `{baseUrl}/oauth2/jwks`.
     */
    constructor(baseUrl: String) : this(deriveJwksUrl(baseUrl), null)

    /** As [JwksVerifier], fetching over [sslSocketFactory] so `customCa` (§6) reaches the key fetch. */
    internal constructor(baseUrl: String, sslSocketFactory: SSLSocketFactory?) :
        this(deriveJwksUrl(baseUrl), sslSocketFactory)

    /**
     * **Signature-only primitive — NOT a guard** (CONTRACT.md §10.1).
     *
     * Verifies [token]'s signature (alg pinned to EdDSA *before* key lookup,
     * key taken from the cached/rotated JWKS) and returns its claims WITHOUT
     * checking a single claim: not `exp`, not `nbf`, not `tenant_id`, not
     * `iss`, not `aud`. A caller that stops here has not authenticated
     * anything — the org-wide JWKS makes a valid signature compatible with a
     * permanent, cross-tenant, foreign-audience token.
     *
     * Use [io.axiam.sdk.AxiamClient.verifySession] instead. This entry point
     * exists only for integrators deliberately implementing their own policy,
     * who MUST then apply [assertLocalClaims] (or an equivalent) themselves.
     *
     * @throws AuthError if the token is malformed, the alg is not EdDSA, no
     *   matching key is found, or the signature is invalid.
     */
    fun verifySignatureOnlyUnchecked(token: String): JWTClaimsSet = verifiedJwt(token).claims()

    /**
     * The §10 guard's token primitive — **internal to the SDK, not a public entry
     * point** (it checks rules 1 and 10-12 only: no `exp`, `nbf`, `tenant_id`,
     * `iss`, `aud` or `cnf`, so it is not a guard on its own; the guard is
     * [io.axiam.sdk.AxiamClient.verifySession]): [verifySignatureOnlyUnchecked] plus the
     * CONTRACT.md §10.1 rules 10-12 that say the token is an ACCESS token
     * (contract 1.68; N14, N10, D-7).
     *
     * AXIAM signs more than access tokens with the access-token key — the MFA
     * challenge and setup tokens and the WebAuthn ceremony state, which an
     * anonymous caller can obtain with the nil UUID as `sub`. They carry `sub`,
     * `tenant_id`, `iss` and `exp` and no `aud`, so without these rules a guard
     * with no expected audience would admit them as the user they name.
     *
     * - rule 10 `typ`: when the header carries one it MUST be `at+jwt`
     *   (RFC 9068 §2.1), compared ASCII case-insensitively and with or without
     *   the `application/` prefix (RFC 7515 §4.1.9). A header with no `typ` is
     *   not refused by this rule.
     * - rule 11 `purpose`: a payload with a `purpose` member is refused,
     *   whatever its value (`null` included) and whatever `typ` says. It is
     *   read from the verified payload itself, not from a claims model that
     *   would drop an unknown or null member.
     * - rule 12 `kid`: REQUIRED — enforced by key selection, which has no
     *   "the only key in the set" fallback.
     *
     * These apply on the access-token path only: the ID token
     * ([verifyForIdToken], `typ` `JWT`), the back-channel logout token and the
     * SSF event token take other paths and are not affected.
     *
     * @throws AuthError if [token] fails signature verification or rules 10-12.
     */
    internal fun verifyAccessTokenSignature(token: String): JWTClaimsSet {
        val jwt = verifiedJwt(token)
        assertAccessTokenShape(jwt)
        return jwt.claims()
    }

    private fun SignedJWT.claims(): JWTClaimsSet =
        try {
            jwtClaimsSet
        } catch (e: Exception) {
            throw AuthError("malformed claims: ${e.message}")
        }

    private fun assertAccessTokenShape(jwt: SignedJWT) {
        // Rule 10.
        val typ = jwt.header.type?.type
        if (typ != null) {
            val normalized = typ.lowercase(Locale.ROOT).removePrefix("application/")
            if (normalized != ACCESS_TOKEN_TYP) {
                throw AuthError("token typ is not at+jwt: only an access token is accepted here (CONTRACT.md §10.1 rule 10)")
            }
        }
        // Rule 11.
        val payload = try {
            jwt.payload.toJSONObject()
        } catch (e: Exception) {
            throw AuthError("malformed claims: ${e.message}")
        }
        if (payload != null && payload.containsKey("purpose")) {
            throw AuthError("token carries a purpose claim: only an access token is accepted here (CONTRACT.md §10.1 rule 11)")
        }
    }

    private fun verifiedJwt(token: String): SignedJWT {
        val parts = token.split(".")
        if (parts.size != 3) {
            throw AuthError("malformed token: expected a 3-part compact JWS")
        }

        // §10.1 rule 1: the `alg` is read from the RAW header and pinned to
        // EdDSA before any key lookup, so neither `alg: none` (which nimbus's
        // `SignedJWT.parse` would otherwise surface as a generic parse error)
        // nor an HS-family token bearing an EdDSA `kid` ever reaches the JWKS.
        val rawHeader = try {
            Header.parse(Base64URL.from(parts[0]))
        } catch (e: Exception) {
            throw AuthError("malformed token header: ${e.message}")
        }
        if (JWSAlgorithm.EdDSA != rawHeader.algorithm) {
            throw AuthError("unexpected JWS algorithm ${rawHeader.algorithm}: only EdDSA is accepted")
        }

        val jwt = try {
            SignedJWT.parse(token)
        } catch (e: Exception) {
            throw AuthError("malformed token: ${e.message}")
        }

        val header = jwt.header
        val key = selectKeyOrNull(header)
            ?: throw AuthError("no matching EdDSA key found in JWKS (kid=${header.keyID})")
        val verifier = try {
            Ed25519Verifier(key)
        } catch (e: Exception) {
            throw AuthError("failed to construct EdDSA verifier: ${e.message}")
        }

        val valid = try {
            jwt.verify(verifier)
        } catch (e: Exception) {
            throw AuthError("signature verification failed: ${e.message}")
        }
        if (!valid) {
            throw AuthError("invalid token signature")
        }
        return jwt
    }

    /**
     * CONTRACT.md §12.4 rules 1-2 for an OIDC `id_token`: the SAME
     * alg-allowlist + kid-lookup + one-shot unknown-kid-refetch machinery as
     * [verifySignatureOnlyUnchecked] (same cache, same [refreshLock] —
     * never a forked fetch path), but the thrown [AuthError] carries one of
     * the §12.3 rule 3 reason codes (`invalid_alg`, `unknown_kid`,
     * `invalid_signature`) instead of that method's plain messages, so the
     * §12.4 orchestration in `io.axiam.sdk.oidc` can classify the failure per
     * the contract.
     *
     * A missing `kid` header is treated identically to an unknown `kid`
     * (CONTRACT.md §12 port addendum item 12), and a JWKS re-fetch failure
     * during key lookup is likewise folded into `unknown_kid` rather than a
     * separate network-error path — mirroring the Go reference port.
     *
     * @throws AuthError with [AuthError.reason] set to `invalid_alg`,
     *   `unknown_kid`, or `invalid_signature`.
     */
    fun verifyForIdToken(token: String): JWTClaimsSet {
        val parts = token.split(".")
        if (parts.size != 3) {
            throw idTokenError("invalid_signature", "malformed id_token: expected a 3-part compact JWS")
        }

        // Rule 1 MUST be read from the header and checked BEFORE any
        // signature work, so a token can never select its own verification
        // algorithm. Parsed via the generic nimbus `Header` (which also
        // accepts a `PlainHeader`-shaped `alg: none`) rather than
        // `SignedJWT.parse`, because nimbus's `SignedJWT.parse` itself
        // REJECTS an `alg: none` header outright (it is not a JWS algorithm)
        // — which would otherwise surface as a generic parse failure instead
        // of the contract-mandated `invalid_alg` classification.
        val header = try {
            Header.parse(Base64URL.from(parts[0]))
        } catch (e: Exception) {
            throw idTokenError("invalid_alg", "id_token header could not be parsed: ${e.message}")
        }
        if (JWSAlgorithm.EdDSA != header.algorithm) {
            throw idTokenError(
                "invalid_alg",
                "expected alg \"EdDSA\", got ${header.algorithm?.let { "\"$it\"" } ?: "no alg header"}",
            )
        }

        val jwt = try {
            SignedJWT.parse(token)
        } catch (e: Exception) {
            throw idTokenError("invalid_signature", "malformed id_token: ${e.message}")
        }

        val key = selectKeyOrNull(jwt.header)
            ?: throw idTokenError("unknown_kid", "no matching EdDSA key found in JWKS (kid=${jwt.header.keyID})")

        val verifier = try {
            Ed25519Verifier(key)
        } catch (e: Exception) {
            throw idTokenError("invalid_signature", "failed to construct EdDSA verifier: ${e.message}")
        }
        val valid = try {
            jwt.verify(verifier)
        } catch (e: Exception) {
            throw idTokenError("invalid_signature", "signature verification failed: ${e.message}")
        }
        if (!valid) {
            throw idTokenError("invalid_signature", "invalid token signature")
        }
        return try {
            jwt.jwtClaimsSet
        } catch (e: Exception) {
            throw idTokenError("invalid_signature", "malformed claims: ${e.message}")
        }
    }

    private fun idTokenError(reason: String, detail: String): AuthError =
        AuthError("id_token validation failed ($reason): $detail", reason)

    /**
     * Resolves the EdDSA key matching [header]'s `kid`. Returns `null` — never
     * throws — on ANY failure to produce a match: no `kid` header, a `kid`
     * absent from the key set, or the fetch itself failing (a 5xx, a timeout).
     * Both [verifySignatureOnlyUnchecked] and [verifyForIdToken] treat a `null`
     * result as their own "no matching key" failure — this is the ONE shared
     * fetch/cache code path (CONTRACT.md §12 forbids forking the JWKS mechanism).
     *
     * CONTRACT.md §12.4 rule 2: a set within its TTL (300 s, or a smaller `max-age`) answers a
     * known `kid` with no fetch. Past the TTL, or for an unknown `kid`, a refresh is due, and at
     * most ONE JWKS fetch is made per 60 s cooldown window (C5), however many tokens ask — a
     * failed attempt, a cold cache included, counts toward the window. The fetch is single-flight
     * and runs detached, on an SDK-owned thread with its own total deadline: no lock is held
     * across the network, a usable held key is answered at once without waiting for it, and a
     * caller that is interrupted records nothing. A failed refresh keeps the held keys, which
     * verify until exactly TTL + 300 s after the last SUCCESSFUL fetch (the anchor) and not after.
     */
    private fun selectKeyOrNull(header: JWSHeader): OctetKeyPair? {
        if (header.keyID.isNullOrEmpty()) return null

        val matcher = JWKMatcher.Builder()
            .keyType(KeyType.OKP)
            .keyID(header.keyID)
            .keyUses(KeyUse.SIGNATURE, null)
            .algorithms(JWSAlgorithm.EdDSA, null)
            .curves(Curve.Ed25519, Curve.Ed448)
            .build()
        val selector = JWKSelector(matcher)

        val clock = clockNanos
        // Lock-free fast path: a set within its TTL answers a KNOWN kid with no fetch
        // and no lock; an unknown kid inside the open cooldown window is refused with
        // no fetch either.
        cached?.let { snapshot ->
            val t = clock()
            if (t - snapshot.atNanos in 0 until snapshot.ttlNanos) {
                firstOctetKeyPair(selector.select(snapshot.keys))?.let { return it }
                val last = lastFetchNanos
                if (last != 0L && t - last in 0 until UNKNOWN_KID_COOLDOWN_NANOS) return null
            }
        }

        // Decide under the lock (a short snapshot, never across I/O); the fetch itself runs detached.
        val toAwait: CompletableFuture<Unit> = refreshLock.withLock {
            val now = clock()
            val current = cached
            // Held keys verify until TTL + 300 s after the anchor (the last successful
            // fetch), strictly, and not after — whatever the cause of the failures.
            val usable = current?.takeIf { now - it.atNanos in 0 until it.ttlNanos + MAX_STALE_NANOS }
            val held = usable?.let { firstOctetKeyPair(selector.select(it.keys)) }
            val fresh = current != null && now - current.atNanos in 0 until current.ttlNanos
            if (fresh && held != null) return held
            var flight = inFlight
            if (flight == null) {
                // Inside the window: no fetch (a failed attempt counts toward it).
                if (lastFetchNanos != 0L && now - lastFetchNanos in 0 until UNKNOWN_KID_COOLDOWN_NANOS) return held
                flight = startFetch(now, current?.etag)
            }
            // A usable held key never waits for a fetch: it is answered now, the refresh runs behind it.
            if (held != null) return held
            flight
        }

        // No usable key for this kid: wait, bounded, for the one shared fetch. A caller that is
        // interrupted or gives up records nothing — only the fetch's own outcome does.
        try {
            toAwait.get(fetchTotalTimeoutMs + 1_000, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        } catch (_: Exception) {
            // timeout or failure: whatever the fetch published (if anything) is read below
        }
        return refreshLock.withLock {
            val now = clock()
            cached?.takeIf { now - it.atNanos in 0 until it.ttlNanos + MAX_STALE_NANOS }
                ?.let { firstOctetKeyPair(selector.select(it.keys)) }
        }
    }

    /**
     * Starts THE fetch (caller holds [refreshLock], [inFlight] is null) on the SDK-owned executor.
     *
     * The total deadline is enforced from OUTSIDE the blocking call: a watchdog fires at the deadline,
     * closes the connection (which unblocks a read stuck in the status line, the headers or the body) and
     * settles the flight as failed itself. The flight settles exactly once — whichever of the fetch task
     * and the watchdog gets there first — so a result arriving late is ignored, and the fetch's `finally`
     * always clears [inFlight] and completes the flight.
     */
    private fun startFetch(startNanos: Long, etag: String?): CompletableFuture<Unit> {
        val flight = CompletableFuture<Unit>()
        inFlight = flight
        val clock = clockNanos
        val settled = AtomicBoolean(false)
        val connRef = AtomicReference<HttpURLConnection?>(null)

        fun settle(r: Refresh) {
            if (!settled.compareAndSet(false, true)) return // a late result is ignored
            try {
                refreshLock.withLock {
                    when (r) {
                        is Refresh.Fetched -> cached = Cached(r.keys, startNanos, r.ttlNanos, r.etag)
                        is Refresh.NotModified -> cached?.let { held ->
                            // 304 to a conditional request re-confirms the held set and moves the anchor.
                            cached = Cached(held.keys, startNanos, r.ttlNanos ?: held.ttlNanos, held.etag)
                        }
                        // A failed refresh never replaces the held keys and never moves the anchor.
                        Refresh.Failed -> Unit
                    }
                    // The cooldown is stamped from the fetch's own outcome, success or failure.
                    val t = clock()
                    lastFetchNanos = if (t == 0L) 1L else t
                }
            } finally {
                refreshLock.withLock { if (inFlight === flight) inFlight = null }
                flight.complete(Unit)
            }
        }

        val timeoutMs = fetchTotalTimeoutMs
        val watchdog = try {
            FETCH_WATCHDOG.schedule({
                try {
                    connRef.get()?.disconnect()
                } catch (_: Throwable) {
                    // best effort
                }
                settle(Refresh.Failed)
            }, timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            null
        }
        try {
            FETCH_EXECUTOR.execute {
                var r: Refresh = Refresh.Failed
                try {
                    r = refresh(etag, System.nanoTime() + timeoutMs * 1_000_000L, connRef)
                } catch (_: Throwable) {
                    r = Refresh.Failed
                } finally {
                    watchdog?.cancel(false)
                    settle(r)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            watchdog?.cancel(false)
            settle(Refresh.Failed)
        }
        return flight
    }

    /** Test seam: waits for the in-flight fetch, if any, to publish its outcome. */
    internal fun awaitIdleForTesting() {
        val f = refreshLock.withLock { inFlight }
        f?.get(30, TimeUnit.SECONDS)
    }

    /** Test seam: the total deadline of one fetch, in milliseconds. */
    @Volatile
    internal var fetchTotalTimeoutMs: Long = FETCH_TOTAL_TIMEOUT_MS

    /**
     * One JWKS fetch. Success is a `200` whose body is a JWKS document with at
     * least one key, or a `304` to a conditional request ([etag] held). Anything
     * else — transport error, timeout, another status (a redirect included), a
     * body that is not a JWKS document, an over-size body, an EMPTY key set — is
     * [Refresh.Failed]. Nothing about the response is logged.
     */
    private fun refresh(etag: String?, deadlineNanos: Long, connRef: AtomicReference<HttpURLConnection?>): Refresh {
        var conn: HttpURLConnection? = null
        return try {
            conn = (jwksUrl.openConnection() as HttpURLConnection).apply {
                connectTimeout = connectTimeoutMs
                readTimeout = readTimeoutMs
                instanceFollowRedirects = false
                requestMethod = "GET"
                setRequestProperty("Accept", "application/json")
                if (etag != null) setRequestProperty("If-None-Match", etag)
                // Only the socket factory is replaced: verification stays strict and the
                // default hostname check of HttpsURLConnection is untouched.
                if (this is HttpsURLConnection && tlsSocketFactory != null) {
                    this.sslSocketFactory = tlsSocketFactory
                }
            }
            connRef.set(conn)
            when (conn.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> if (etag != null) {
                        Refresh.NotModified(conn.getHeaderField("Cache-Control")?.let { ttlFrom(it) })
                    } else {
                        Refresh.Failed
                    }
                HttpURLConnection.HTTP_OK -> {
                    val body = conn.inputStream.use { input ->
                        val out = ByteArrayOutputStream()
                        val buf = ByteArray(8192)
                        while (true) {
                            if (System.nanoTime() - deadlineNanos > 0) return Refresh.Failed // total deadline
                            val n = input.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                            if (sizeLimitBytes > 0 && out.size() > sizeLimitBytes) return Refresh.Failed
                        }
                        out.toString(Charsets.UTF_8)
                    }
                    val keys = parseEntries(body)
                    if (keys == null) {
                        Refresh.Failed
                    } else {
                        Refresh.Fetched(keys, sanitizeEtag(conn.getHeaderField("ETag")), ttlFrom(conn.getHeaderField("Cache-Control")))
                    }
                }
                else -> Refresh.Failed
            }
        } catch (_: Exception) {
            Refresh.Failed
        } finally {
            conn?.disconnect()
        }
    }

    /**
     * Parses a JWKS body entry by entry. An entry that is a JSON object with a string `kty` counts toward
     * "holding at least one key" even if this library cannot build a usable JWK from it (it is skipped);
     * `null` when the body is not a JWKS document or no entry is such an object.
     */
    private fun parseEntries(body: String): JWKSet? {
        val json = com.nimbusds.jose.util.JSONObjectUtils.parse(body)
        val entries = json["keys"] as? List<*> ?: return null
        var wellFormed = 0
        val usable = ArrayList<JWK>()
        for (e in entries) {
            val m = e as? Map<*, *> ?: continue
            if (m["kty"] !is String) continue
            wellFormed++
            try {
                @Suppress("UNCHECKED_CAST")
                usable.add(JWK.parse(m as Map<String, Any>))
            } catch (_: Exception) {
                // unusable here, skipped
            }
        }
        return if (wellFormed == 0) null else JWKSet(usable)
    }

    /** An `ETag` worth storing and echoing: printable ASCII only, at most 256 bytes; otherwise none. */
    private fun sanitizeEtag(v: String?): String? =
        v?.takeIf { it.length <= 256 && it.all { c -> c.code in 0x20..0x7e } }

    /** `max-age` of a `Cache-Control` value, clamped to [MAX_TTL_NANOS]; [MAX_TTL_NANOS] when absent or unparseable. */
    private fun ttlFrom(cacheControl: String?): Long {
        val seconds = cacheControl?.split(',')
            ?.map { it.trim().lowercase(Locale.ROOT) }
            ?.firstOrNull { it.startsWith("max-age=") }
            ?.substringAfter('=')?.trim('"')?.toLongOrNull()
            ?: return MAX_TTL_NANOS
        if (seconds < 0) return MAX_TTL_NANOS
        return minOf(seconds, MAX_TTL_NANOS / 1_000_000_000L) * 1_000_000_000L
    }

    private fun firstOctetKeyPair(jwks: List<JWK>): OctetKeyPair? =
        jwks.filterIsInstance<OctetKeyPair>().firstOrNull()

    companion object {
        /**
         * Builds a verifier bound to the EXACT [jwksUri] given — no
         * `/oauth2/jwks` path is concatenated.
         *
         * Exists for the OIDC relying-party helpers (CONTRACT.md §12.3
         * rule 6), which MUST read `jwks_uri` from the discovery document
         * rather than assume the fixed AXIAM resource-server path — the two
         * may legitimately differ behind a proxy.
         */
        fun forJwksUri(jwksUri: String): JwksVerifier = forJwksUri(jwksUri, jwksUri, JwksTls(null, null))

        /**
         * As [forJwksUri], fetching over the client's TLS stack so `customCa` (§6) reaches the key fetch. The §6.1
         * client identity is presented only when [jwksUri] has the same origin (scheme, host, port) as [baseUrl];
         * any other origin (§12.3 rule 6 allows one) gets the trust configuration alone.
         */
        internal fun forJwksUri(jwksUri: String, baseUrl: String, tls: JwksTls): JwksVerifier {
            val url = try {
                URI.create(jwksUri).toURL()
            } catch (e: Exception) {
                throw IllegalArgumentException("invalid jwks_uri: $jwksUri", e)
            }
            val sameOrigin = try {
                origin(url) == origin(URI.create(baseUrl).toURL())
            } catch (_: Exception) {
                false
            }
            return JwksVerifier(url, if (sameOrigin) tls.withIdentity else tls.trustOnly)
        }

        private fun origin(u: URL): Triple<String, String, Int> =
            Triple(u.protocol.lowercase(Locale.ROOT), u.host.lowercase(Locale.ROOT), if (u.port == -1) u.defaultPort else u.port)

        /** Derives `{baseUrl}/oauth2/jwks` as a [URL], failing clearly on a malformed [baseUrl]. */
        private fun deriveJwksUrl(baseUrl: String): URL {
            val trimmed = baseUrl.trimEnd('/')
            return try {
                URI.create("$trimmed/oauth2/jwks").toURL()
            } catch (e: Exception) {
                throw IllegalArgumentException("invalid AXIAM base URL: $baseUrl", e)
            }
        }

        /**
         * CONTRACT.md §10.1 rule 7 — the ONE named, bounded leeway applied to
         * the `exp` and `nbf` comparisons. It is a constant, not an inline
         * literal, and there is deliberately no setter: the contract forbids
         * an operator raising it to an unbounded value.
         */
        const val CLOCK_SKEW_SECONDS: Long = 60

        /**
         * CONTRACT.md §12.4 rule 2 (C5) — the unknown-`kid` re-fetch window: at
         * most ONE JWKS fetch per window, however many tokens present a `kid`
         * the cache does not hold. 60 s, in nanoseconds.
         */
        const val UNKNOWN_KID_COOLDOWN_NANOS: Long = 60_000_000_000L

        /**
         * CONTRACT.md §12.4 rule 2 (contract 1.69; D-10): the default and the MAXIMUM TTL of a
         * fetched set, 300 s in nanoseconds. A larger advertised `max-age` is clamped to it.
         */
        private const val MAX_TTL_NANOS: Long = 300_000_000_000L

        /**
         * The total deadline of one JWKS fetch, in milliseconds, enforced from outside the blocking call by
         * a watchdog (it closes the connection and settles the fetch as failed), so a server that drips the
         * status line, the headers or the body cannot hold the single in-flight fetch past it. DNS
         * resolution, which Java cannot interrupt, is the one step the watchdog abandons rather than aborts.
         */
        private const val FETCH_TOTAL_TIMEOUT_MS: Long = 5_000L

        /** SDK-owned daemon threads for the detached fetches: no caller's thread or cancellation scope runs one. */
        private val FETCH_EXECUTOR = Executors.newCachedThreadPool { r ->
            Thread(r, "axiam-jwks-fetch").apply { isDaemon = true }
        }

        private val FETCH_WATCHDOG = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "axiam-jwks-watchdog").apply { isDaemon = true }
        }

        /** The stale-if-error bound beyond the TTL: held keys verify until TTL + 300 s after the last successful fetch. */
        private const val MAX_STALE_NANOS: Long = 300_000_000_000L

        /** CONTRACT.md §10.1 rule 10 — the `typ` an access token carries (RFC 9068 §2.1), lower-cased. */
        private const val ACCESS_TOKEN_TYP = "at+jwt"

        /**
         * CONTRACT.md §10.1 rules 2-7 — the **minimum local-verification set**,
         * applied to an already-signature-verified [claims] set (rule 1 lives
         * in [verifySignatureOnlyUnchecked]). Together those two calls are the
         * whole guard; neither is sufficient alone.
         *
         * Every rule fails CLOSED: a required claim that is absent, of the
         * wrong JSON type, or unparseable rejects the token. "The claim was
         * missing so there was nothing to check" is the SEC-080 defect and is
         * never a success path here.
         *
         * - rule 2 `exp` — REQUIRED. Absent ⇒ reject (a token with no expiry
         *   is a permanent credential). A non-numeric `exp` never reaches
         *   this method: nimbus fails the claim-set parse in
         *   [verifySignatureOnlyUnchecked], which surfaces as `malformed claims`.
         * - rule 3 `nbf` — honoured when present; a future `nbf` rejects.
         *   Absent `nbf` is valid.
         * - rule 4 `tenant_id` — REQUIRED and asserted (see [assertTenant]).
         * - rule 5 `iss` — checked only when [expectedIssuer] is configured.
         * - rule 6 `aud` — checked only when [expectedAudience] is configured.
         * - rule 7 — both time comparisons allow [CLOCK_SKEW_SECONDS].
         *
         * @param nowEpochSec current time in epoch seconds — injectable so a
         *   test can pin it.
         */
        fun assertLocalClaims(
            claims: JWTClaimsSet,
            configuredTenantId: String,
            expectedIssuer: String? = null,
            expectedAudience: String? = null,
            nowEpochSec: Long = System.currentTimeMillis() / 1000,
        ) {
            // Rule 2 — `exp` is REQUIRED, not "checked if present".
            val exp = claims.expirationTime
                ?: throw AuthError("token has no exp claim; refusing to accept an unbounded session")
            if (exp.time / 1000 + CLOCK_SKEW_SECONDS <= nowEpochSec) {
                throw AuthError("token is expired")
            }

            // Rule 3 — `nbf` is optional, but binding when present.
            val nbf = claims.notBeforeTime
            if (nbf != null && nbf.time / 1000 - CLOCK_SKEW_SECONDS > nowEpochSec) {
                throw AuthError("token is not yet valid (nbf is in the future)")
            }

            // Rule 4 — tenant binding.
            assertTenant(claims, configuredTenantId)

            // Rule 5 — issuer, only when the SDK was configured with one.
            if (expectedIssuer != null) {
                val iss = claims.issuer
                    ?: throw AuthError("token has no iss claim but an expected issuer is configured")
                if (iss != expectedIssuer) {
                    throw AuthError("token iss does not match the configured expected issuer")
                }
            }

            // Rule 6 — audience, only when the SDK was configured with one.
            if (expectedAudience != null) {
                val audiences = claims.audience ?: emptyList()
                if (!audiences.contains(expectedAudience)) {
                    throw AuthError("token aud does not contain the configured expected audience")
                }
            }
        }

        /**
         * CONTRACT.md §10.1 **rule 9** — enforce a token's sender constraint
         * against the certificate the caller presented on **this** connection
         * (RFC 8705 §3 / RFC 7800, contract 1.15).
         *
         * A token carrying `cnf` is **not** a bearer token. Accepting one
         * without proving the caller holds the named key converts it straight
         * back into one, discarding the whole protection the operator turned
         * on — which is why this is a rule and not a recommendation.
         *
         * The four cases:
         *
         * | token's `cnf`          | [presentedThumbprint] | result  |
         * |------------------------|-----------------------|---------|
         * | absent                 | anything              | returns |
         * | `x5t#S256`             | equal                 | returns |
         * | `x5t#S256`             | different, or null    | throws  |
         * | present, no `x5t#S256` | anything              | throws  |
         *
         * The first row is why adopting this rule breaks nothing: an
         * **unbound** token is still accepted whether or not a certificate is
         * present. Rule 9 constrains tokens that claim a constraint; it does
         * not make certificates mandatory.
         *
         * The last row is the one that is easy to get wrong. A `cnf` naming a
         * confirmation method this SDK cannot check — a DPoP `jkt`, say — is
         * an *unverifiable constraint*, never *no constraint*. Read the other
         * way, a sender-constrained token silently degrades to a bearer token
         * the day a newer AXIAM issues a confirmation this SDK predates.
         *
         * **The thumbprint must come from the transport** — the TLS peer
         * certificate, or a value a *trusted* terminating proxy forwarded over
         * a channel your application controls. Never from a caller-settable
         * request header: a forgeable input makes the whole mechanism
         * decorative. [certificateThumbprintS256] computes it from DER bytes.
         *
         * Deliberately NOT folded into [assertLocalClaims]: that function has
         * no transport to ask, and threading a nullable thumbprint through it
         * would have every existing caller pass `null` — which reads as "no
         * certificate" and rejects every bound token.
         *
         * @throws AuthError on any of the three rejecting rows.
         */
        fun verifyCertificateBinding(claims: JWTClaimsSet, presentedThumbprint: String?) {
            val cnf = claims.getClaim("cnf") ?: return
            val cnfMap = cnf as? Map<*, *>
                ?: throw AuthError("token cnf claim is malformed")

            val expected = cnfMap["x5t#S256"] as? String
            if (expected.isNullOrEmpty()) {
                // Includes the DPoP case: this entry point has no proof to
                // check, so a jkt-bound token is refused rather than silently
                // downgraded.
                throw AuthError(
                    "token carries a cnf confirmation naming a method this entry point cannot " +
                        "verify (CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an " +
                        "absent one; use verifyTokenBinding for DPoP)",
                )
            }
            // A token naming BOTH methods is a conjunction (contract 1.16):
            // this function can establish one half and must not answer for the
            // whole. Refusing here is what stops "check whichever we can".
            val jkt = cnfMap["jkt"] as? String
            if (!jkt.isNullOrEmpty()) {
                throw AuthError(
                    "token names both a certificate and a DPoP key; both must hold " +
                        "(CONTRACT.md §10.1 rule 9) — use verifyTokenBinding",
                )
            }
            if (presentedThumbprint.isNullOrEmpty()) {
                throw AuthError("token is certificate-bound but no client certificate was presented")
            }
            // Constant-time. The thumbprint is usually public — it derives
            // from a certificate sent in the clear during the handshake — so
            // this is defence in depth. It matters most for a self-signed
            // client, where the registered thumbprint is the whole credential.
            if (!MessageDigest.isEqual(
                    expected.toByteArray(Charsets.UTF_8),
                    presentedThumbprint.toByteArray(Charsets.UTF_8),
                )
            ) {
                throw AuthError("token is bound to a different client certificate than the one presented")
            }
        }

        /**
         * CONTRACT.md §10.1 **rule 9** in full — enforce a token's sender
         * constraint against **every** proof the caller presented (contract
         * 1.16).
         *
         * This is the complete rule, and the one to use unless your transport
         * genuinely cannot produce a DPoP thumbprint.
         *
         * The ten cases:
         *
         * ```
         * token's cnf             certificate     DPoP        result
         * absent                  anything        anything    returns
         * x5t#S256                equal           ignored     returns
         * x5t#S256                different       ignored     throws
         * x5t#S256                null            ignored     throws
         * jkt                     ignored         equal       returns
         * jkt                     ignored         different   throws
         * jkt                     ignored         null        throws
         * both                    equal           equal       returns
         * both                    wrong/missing   —           throws
         * present, names neither  anything        anything    throws
         * ```
         *
         * Two rows carry the weight. **Both named is a conjunction**: an
         * operator who turned on two constraints asked for two, and satisfying
         * the more convenient one is not compliance. **Names neither is a
         * refusal**: a confirmation this SDK cannot interpret is an
         * unverifiable constraint, and reading it as "unconstrained" is the
         * exact downgrade rule 9 exists to prevent. That includes an *empty*
         * `cnf`, which is also how proto3 delivers an empty `CnfClaim` over
         * gRPC (§10.3 rule 3).
         *
         * @param claims the verified claims of the token being guarded
         * @param proofs what the caller proved on this connection and request
         * @throws AuthError on any rejecting row
         */
        fun verifyTokenBinding(claims: JWTClaimsSet, proofs: PresentedProofs) {
            // The fast path, and the common one. First on purpose: an unbound
            // token is accepted with no proofs at all, which is what keeps
            // existing deployments working when a guard adopts this rule.
            val cnf = claims.getClaim("cnf") ?: return
            val cnfMap = cnf as? Map<*, *>
                ?: throw AuthError("token cnf claim is malformed")

            val expectedCert = (cnfMap["x5t#S256"] as? String)?.takeIf { it.isNotEmpty() }
            val expectedJkt = (cnfMap["jkt"] as? String)?.takeIf { it.isNotEmpty() }

            if (expectedCert == null && expectedJkt == null) {
                throw AuthError(
                    "token carries a cnf confirmation naming no method this SDK can verify " +
                        "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one)",
                )
            }

            // Each arm that applies must pass. Two independent checks rather
            // than a `when` on the pair, precisely so "both named" needs no
            // branch of its own — it is simply where both run.
            if (expectedCert != null) {
                if (proofs.certificateThumbprint.isNullOrEmpty()) {
                    throw AuthError("token is certificate-bound but no client certificate was presented")
                }
                if (!MessageDigest.isEqual(
                        expectedCert.toByteArray(Charsets.UTF_8),
                        proofs.certificateThumbprint.toByteArray(Charsets.UTF_8),
                    )
                ) {
                    throw AuthError("token is bound to a different client certificate than the one presented")
                }
            }

            if (expectedJkt != null) {
                if (proofs.dpopThumbprint.isNullOrEmpty()) {
                    throw AuthError("token is DPoP-bound but no verified DPoP proof was presented")
                }
                if (!MessageDigest.isEqual(
                        expectedJkt.toByteArray(Charsets.UTF_8),
                        proofs.dpopThumbprint.toByteArray(Charsets.UTF_8),
                    )
                ) {
                    throw AuthError("token is bound to a different DPoP key than the one presented")
                }
            }
        }

        /**
         * Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of a DER client
         * certificate: base64url-encoded SHA-256, **without** padding.
         *
         * Unpadded is not a style choice — RFC 7515 §2 defines base64url in
         * JOSE as omitting `=`, and a padded value will not compare equal to
         * what AXIAM put in the token.
         *
         * @param der the DER encoding of the peer's leaf certificate
         *   (`X509Certificate.encoded`).
         */
        fun certificateThumbprintS256(der: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(der))

        /**
         * Cross-tenant carry-forward control (CONTRACT.md §10.1 rule 4): the
         * JWKS endpoint is org-wide, so a valid signature alone does not imply
         * the token belongs to [configuredTenantId]. Throws if the `tenant_id`
         * claim is absent, of the wrong JSON type, or mismatched — and also
         * when there is no configured tenant to compare against, since a
         * blank expectation would otherwise silently match nothing (or, with
         * a blank claim, everything).
         */
        fun assertTenant(claims: JWTClaimsSet, configuredTenantId: String) {
            if (configuredTenantId.isBlank()) {
                throw AuthError("no configured tenant to bind the session to")
            }
            val tenantId = try {
                claims.getStringClaim("tenant_id")
            } catch (e: Exception) {
                throw AuthError("token tenant_id claim is malformed")
            }
            if (tenantId == null || tenantId != configuredTenantId) {
                throw AuthError("token tenant_id does not match the configured tenant")
            }
        }
    }
}
