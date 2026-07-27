package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md §12.1
 * "oidc_begin inputs and construction", RFC 7636).
 *
 * `java.security.SecureRandom` and `java.security.MessageDigest` cover
 * everything needed — CSPRNG, SHA-256, and `Base64.getUrlEncoder()` covers
 * base64url — so §12 adds NO new runtime dependency. This object is
 * deliberately tiny, pure, and synchronous: `oidcBegin` performs no network
 * I/O, and every value here is derived locally.
 *
 * S256 ONLY. `plain` is not implemented, not reachable, and not configurable:
 * there is no code path in this SDK that can emit
 * `code_challenge_method=plain`.
 */
internal object OidcPkce {

    /** The only PKCE code-challenge method this SDK emits (RFC 7636 §4.2). `plain` is intentionally absent. */
    const val CODE_CHALLENGE_METHOD_S256: String = "S256"

    /**
     * Entropy, in bytes, of a generated `state` / `nonce` / `code_verifier`.
     *
     * §12.1 rule 1 requires at least 16 bytes (128 bits) and RECOMMENDS 32;
     * rule 2 RECOMMENDS 32 bytes for the verifier, which base64url-encodes to
     * exactly 43 characters — the minimum RFC 7636 §4.1 length, drawn only
     * from the unreserved set `[A-Za-z0-9-._~]`.
     */
    const val CSPRNG_BYTES: Int = 32

    private val secureRandom = SecureRandom()
    private val urlEncoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    /**
     * Generates a URL-safe random token: [bytes] CSPRNG bytes, base64url
     * encoded WITHOUT padding (RFC 4648 §5).
     *
     * Used for both `state` and `nonce`, which CONTRACT.md §12.3 rule 2
     * classes as **non-secret**: they are returned as plain strings, are
     * echoed through the browser's address bar by construction, and are safe
     * to log.
     */
    fun randomUrlSafeToken(bytes: Int = CSPRNG_BYTES): String {
        val raw = ByteArray(bytes)
        secureRandom.nextBytes(raw)
        return urlEncoder.encodeToString(raw)
    }

    /**
     * Generates a fresh PKCE `code_verifier` (RFC 7636 §4.1): 32 CSPRNG bytes
     * base64url-encoded without padding, i.e. 43 characters from the
     * unreserved set.
     *
     * Returned already wrapped in [Sensitive] — CONTRACT.md §12.5 makes the
     * verifier secret for its WHOLE lifetime, including while it sits in the
     * `AuthorizationRequest` handed back to the caller and in any
     * [OidcStateStore] entry.
     */
    fun generateCodeVerifier(): Sensitive<String> = Sensitive.of(randomUrlSafeToken(CSPRNG_BYTES))

    /**
     * Derives the PKCE `code_challenge` from a verifier:
     * `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, unpadded (RFC 7636
     * §4.2, CONTRACT.md §12.1 rule 3).
     *
     * The verifier is hashed as ASCII exactly as the RFC specifies. Verified
     * against the RFC 7636 Appendix B test vector, which every SDK must carry
     * (§12.1 rule 3).
     *
     * The challenge is a one-way digest and is NOT secret — it travels in the
     * authorization URL — so it is returned as a plain string.
     */
    fun computeCodeChallenge(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        return urlEncoder.encodeToString(digest)
    }
}
