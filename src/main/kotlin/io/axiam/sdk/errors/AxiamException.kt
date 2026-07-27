package io.axiam.sdk.errors

/**
 * Root of the AXIAM SDK error taxonomy (CONTRACT.md §2).
 *
 * Three concrete TOP-LEVEL error types exist, exposed as a sealed hierarchy so
 * a `when` over an [AxiamException] is exhaustive:
 *
 *  - [AuthError]    — authentication failure (wrong credentials, expired
 *    session, MFA failure, 401 on refresh).
 *  - [AuthzError]   — authorization failure (authenticated but not permitted).
 *  - [NetworkError] — transport-level failure (connection refused, timeout,
 *    TLS error, DNS failure, 5xx).
 *
 * CONTRACT.md §2 additionally permits language-idiomatic SUB-TYPES of those
 * three (they never replace them): [io.axiam.sdk.errors.OAuthProtocolError]
 * is one, a subclass of [AuthError] added for CONTRACT.md §12. `is AuthError`
 * therefore still matches every authentication failure, including OAuth2
 * protocol errors and §12.4 ID-token validation failures — that backward
 * compatibility is what makes contract 1.4 additive rather than breaking.
 *
 * All are unchecked ([RuntimeException]) so they compose with coroutines and
 * lambdas without a forced `throws`. Messages are English-only (no i18n);
 * classification is by type, not by localized text. No error message, context
 * field, or cause chain ever contains a raw token string (CONTRACT.md §2/§7).
 */
sealed class AxiamException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * Authentication failure: wrong credentials, expired session, MFA failure, a
 * 401 on refresh, or a §12.4 ID-token validation failure (CONTRACT.md §2).
 * Carries a human-readable [message].
 *
 * `open` (not `sealed`'s usual final leaf) so
 * [io.axiam.sdk.errors.OAuthProtocolError] can subclass it (CONTRACT.md §12
 * port addendum item 17) without becoming a fourth peer error type. Because
 * [OAuthProtocolError][io.axiam.sdk.errors.OAuthProtocolError] extends
 * `AuthError` rather than the sealed [AxiamException] directly, it is an
 * INDIRECT subclass and may live outside this file/package (Kotlin's sealed-
 * class same-package restriction applies only to direct subclasses).
 *
 * @property reason an OPTIONAL stable, machine-readable failure code. Populated
 *   by the CONTRACT.md §12.4 ID-token validation checklist with one of the
 *   seven reason codes §12.3 rule 3 enumerates (`invalid_alg`, `unknown_kid`,
 *   `invalid_signature`, `invalid_issuer`, `invalid_audience`,
 *   `token_expired`, `nonce_mismatch`); `null` for every other [AuthError]
 *   construction site, which is fully backward compatible (CONTRACT.md §12
 *   port addendum item 17 — the reason code rides on this EXISTING type via
 *   an additive field, rather than a second error class).
 */
open class AuthError(message: String, val reason: String? = null) : AxiamException(message)

/**
 * Authorization failure: the caller is authenticated but lacks permission for
 * the requested operation (CONTRACT.md §2).
 *
 * [action] and [resourceId] are populated when the server's 403/409 body
 * reports them ("Error Construction Rules"); both may be `null` otherwise.
 *
 * @property action     the denied action, or `null` if the server did not report it
 * @property resourceId the denied resource id, or `null` if the server did not report it
 */
class AuthzError(
    message: String,
    val action: String? = null,
    val resourceId: String? = null,
) : AxiamException(message)

/**
 * Transport-level failure: connection refused, timeout, TLS error, DNS failure,
 * or a server-side 5xx (CONTRACT.md §2).
 *
 * Carries the underlying transport error as [cause] (CONTRACT.md §2 MUST).
 * Callers building a [NetworkError] from an HTTP response MUST pass an
 * already-redacted [summary] string — never a raw response — so no
 * `Set-Cookie`/`Authorization` header or token value can reach the exception
 * chain.
 *
 * @property summary an already-redacted transport-error summary, or `null`
 */
class NetworkError private constructor(
    message: String,
    val summary: String?,
    cause: Throwable?,
) : AxiamException(message, cause) {

    /** A [NetworkError] with no attached summary or cause. */
    constructor(message: String) : this(message, null, null)

    /**
     * A [NetworkError] chaining an underlying transport failure as its cause.
     * The cause is retained for diagnostics; the SDK never places raw token
     * material in a cause it constructs.
     */
    constructor(message: String, cause: Throwable) : this(message, null, cause)

    companion object {
        /**
         * Builds a [NetworkError] carrying an already-redacted transport
         * [summary] (e.g. `"http status 500, headers: ..."` with sensitive
         * headers stripped). The single path from an HTTP response into a
         * [NetworkError] (via [ErrorMapper]).
         */
        fun withSummary(message: String, summary: String?): NetworkError =
            NetworkError(message, summary, null)
    }
}
