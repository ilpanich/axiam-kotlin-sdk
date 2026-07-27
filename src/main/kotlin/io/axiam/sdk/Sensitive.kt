package io.axiam.sdk

/**
 * Hardened wrapper for secret material — access tokens, refresh tokens, the MFA
 * challenge token, and the mTLS private key (CONTRACT.md §7).
 *
 * The wrapped value can never leak via [toString] (always `"[SENSITIVE]"`),
 * and it is reachable only through the single explicit [expose] accessor
 * (CONTRACT.md §7 rule 3) — there is no other public getter, no implicit
 * conversion, and no public field.
 *
 * This is a plain `class`, NOT a `data class`: a `data class` would synthesize a
 * `toString()`/`component1()`/`copy()` that print or hand out the raw value,
 * defeating the redaction. Equality is intentionally not overridden either, to
 * avoid a timing side channel on the secret.
 *
 * @param T the wrapped value type (e.g. `String` for a token, `ByteArray` for a
 *          PEM private key).
 */
class Sensitive<T> private constructor(private val value: T) {

    /** Always `"[SENSITIVE]"` — never the wrapped value. */
    override fun toString(): String = REDACTED

    /**
     * Returns the wrapped raw value — the SDK's single explicit accessor for
     * a [Sensitive] (CONTRACT.md §7 rule 3).
     *
     * Public because CONTRACT.md §12 hands `accessToken`/`refreshToken`/
     * `idToken` to the **calling application** inside the `/oauth2/token`
     * response body, not via a `Set-Cookie` the SDK captures on the caller's
     * behalf — there is no cookie jar to read them back out of. Without a
     * public accessor a §12 caller could hold an `OidcTokenSet` and never be
     * able to persist, forward, or later revoke the tokens it contains, which
     * would make §12 unusable. Widening this accessor from `internal` is
     * additive and breaks no existing caller.
     *
     * Call this only at the point of actually using the value (attaching it
     * to an `Authorization` header, writing it to your own encrypted session
     * store, handing it to a revoke call) and never pass the result to a
     * log/trace/serialization sink — [toString] on [Sensitive] itself still
     * always redacts, but that protection does not follow the raw value once
     * this function returns it.
     */
    fun expose(): T = value

    companion object {
        private const val REDACTED = "[SENSITIVE]"

        /** Wraps [value] so it can never accidentally leak via [toString]. */
        fun <T> of(value: T): Sensitive<T> = Sensitive(value)
    }
}
