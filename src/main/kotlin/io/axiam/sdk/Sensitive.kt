package io.axiam.sdk

/**
 * Hardened wrapper for secret material — access tokens, refresh tokens, the MFA
 * challenge token, and the mTLS private key (CONTRACT.md §7).
 *
 * The wrapped value can never leak via [toString] (always `"[SENSITIVE]"`),
 * and it is reachable only through the module-internal [expose] accessor —
 * there is deliberately **no public getter**.
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
     * Module-internal accessor for SDK code that legitimately needs the raw
     * value (e.g. to attach a bearer header or load a key store). Never public.
     */
    internal fun expose(): T = value

    companion object {
        private const val REDACTED = "[SENSITIVE]"

        /** Wraps [value] so it can never accidentally leak via [toString]. */
        fun <T> of(value: T): Sensitive<T> = Sensitive(value)
    }
}
