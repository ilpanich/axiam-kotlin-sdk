package io.axiam.sdk.internal

/**
 * The result of a successful login/refresh: an access token, a (rotating,
 * single-use) refresh token, and the access token's expiry.
 *
 * A plain `class` with a redacted [toString] — a `data class` would synthesize
 * a `toString()` that prints both bearer tokens verbatim into logs and stack
 * traces (CONTRACT.md §7). The field accessors stay usable by in-SDK callers;
 * only the string form is redacted. The non-secret [expiresAtEpochMs] is kept
 * for diagnostics.
 *
 * @property access           the current access token
 * @property refresh          the current refresh token
 * @property expiresAtEpochMs the access token's expiry, in epoch milliseconds
 */
class TokenPair(
    val access: String,
    val refresh: String,
    val expiresAtEpochMs: Long,
) {
    override fun toString(): String =
        "TokenPair(access=***, refresh=***, expiresAtEpochMs=$expiresAtEpochMs)"
}
