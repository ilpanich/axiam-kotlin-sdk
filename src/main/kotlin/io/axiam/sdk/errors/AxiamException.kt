package io.axiam.sdk.errors

/**
 * Root of the AXIAM SDK error taxonomy (CONTRACT.md §2).
 *
 * Exactly three concrete error types exist, exposed as a sealed hierarchy so a
 * `when` over an [AxiamException] is exhaustive:
 *
 *  - [AuthError]    — authentication failure (wrong credentials, expired
 *    session, MFA failure, 401 on refresh).
 *  - [AuthzError]   — authorization failure (authenticated but not permitted).
 *  - [NetworkError] — transport-level failure (connection refused, timeout,
 *    TLS error, DNS failure, 5xx).
 *
 * All are unchecked ([RuntimeException]) so they compose with coroutines and
 * lambdas without a forced `throws`. Messages are English-only (no i18n);
 * classification is by type, not by localized text. No error message, context
 * field, or cause chain ever contains a raw token string (CONTRACT.md §2/§7).
 */
sealed class AxiamException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * Authentication failure: wrong credentials, expired session, MFA failure, or a
 * 401 on refresh (CONTRACT.md §2). Carries a human-readable [message].
 */
class AuthError(message: String) : AxiamException(message)

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
