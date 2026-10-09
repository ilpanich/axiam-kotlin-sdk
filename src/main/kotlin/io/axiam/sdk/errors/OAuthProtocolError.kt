package io.axiam.sdk.errors

/**
 * An RFC 6749 protocol error returned by an `/oauth2/...` endpoint as an
 * `OAuth2ErrorResponse` body (CONTRACT.md §2 sub-type table,
 * CONTRACT.md §12.3 rule 3).
 *
 * A **subclass of [AuthError]**, not a replacement for it: existing
 * `catch (e: AuthError) { ... }` code, and any `is AuthError` check, keeps
 * matching this type unchanged (CONTRACT.md §12 port addendum item 17).
 * Raised for a `400` from `POST /oauth2/token` (e.g. `invalid_grant`) and for
 * a `401` from `POST /oauth2/introspect` / `POST /oauth2/revoke` (client
 * authentication failed) — neither of which may collapse into the generic §2
 * `400`/`401` rows.
 *
 * [message] is exactly `"<error>: <error_description>"`, built from the two
 * wire fields, which are also exposed individually as [error] and
 * [errorDescription] (CONTRACT.md §2 Error Construction Rules). RFC 6749 §5.2
 * makes `error_description` OPTIONAL, and the RFC 7592 (§28.12) and CIBA
 * (§33) endpoints may omit it: a body without one is still this error, with an
 * empty [errorDescription] and a [message] of just `"<error>"`.
 *
 * Two outcomes a polling grant (§14 device flow, §33 CIBA) must tell apart have
 * their own checks — [isAccessDenied] (a human refused) and [isExpiredToken]
 * (nobody decided in time) — so a caller branches on a typed answer rather than
 * a string comparison it can misspell.
 *
 * @property error the RFC 6749 `error` code (e.g. `"invalid_grant"`,
 *   `"invalid_client"`, `"unsupported_grant_type"`)
 * @property errorDescription the server's human-readable `error_description`,
 *   or `""` when the server sent none; never contains token material
 */
class OAuthProtocolError(
    val error: String,
    val errorDescription: String = "",
) : AuthError(message = if (errorDescription.isEmpty()) error else "$error: $errorDescription") {

    /**
     * Whether this is the `access_denied` answer — at a CIBA or device poll,
     * the user refused (CONTRACT.md §33.4, §14.2 rule 3).
     */
    val isAccessDenied: Boolean get() = error == "access_denied"

    /**
     * Whether this is the `expired_token` answer — at a CIBA or device poll,
     * nobody decided in time. Raised locally too when `cibaAwait` or
     * `deviceLogin` reaches its client-side deadline (§33.7 rule 4).
     */
    val isExpiredToken: Boolean get() = error == "expired_token"
}
