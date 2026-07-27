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
 * [message] is always exactly `"<error>: <error_description>"`, built from the
 * two wire fields, which are also exposed individually as [error] and
 * [errorDescription] (CONTRACT.md §2 Error Construction Rules).
 *
 * @property error the RFC 6749 `error` code (e.g. `"invalid_grant"`,
 *   `"invalid_client"`, `"unsupported_grant_type"`)
 * @property errorDescription the server's human-readable `error_description`;
 *   never contains token material
 */
class OAuthProtocolError(
    val error: String,
    val errorDescription: String,
) : AuthError(message = "$error: $errorDescription")
