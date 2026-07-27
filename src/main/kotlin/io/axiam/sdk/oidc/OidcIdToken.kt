package io.axiam.sdk.oidc

import com.nimbusds.jwt.JWTClaimsSet
import io.axiam.sdk.errors.AuthError
import java.security.MessageDigest
import java.util.Date

/**
 * ID-token claim validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.
 *
 * PURE logic only: no network, no JWKS. The signature half of §12.4
 * (rules 1-2: `alg` allowlist, `kid` lookup, Ed25519 verification, single
 * JWKS re-fetch) lives in [io.axiam.sdk.internal.JwksVerifier.verifyForIdToken] —
 * the SAME verifier the §10 middleware uses, extended (never forked) with an
 * id-token-shaped entry point. This file holds rules 3-6 (issuer, audience,
 * time, nonce) plus the reason-code vocabulary, so both halves are
 * independently testable.
 *
 * Every failure raises [AuthError] carrying one of the seven stable reason
 * codes from CONTRACT.md §12.3 rule 3. Rule 7 (all-or-nothing discard) is
 * enforced by the caller ([OidcSupport]) — it never returns a token set whose
 * ID token failed here, so `access_token`/`refresh_token` from the same
 * response are dropped with it.
 */
internal object OidcIdToken {

    /** The seven CONTRACT.md §12.3/§12.4 stable, machine-readable ID-token validation failure codes. */
    const val REASON_INVALID_ALG: String = "invalid_alg"
    const val REASON_UNKNOWN_KID: String = "unknown_kid"
    const val REASON_INVALID_SIGNATURE: String = "invalid_signature"
    const val REASON_INVALID_ISSUER: String = "invalid_issuer"
    const val REASON_INVALID_AUDIENCE: String = "invalid_audience"
    const val REASON_TOKEN_EXPIRED: String = "token_expired"
    const val REASON_NONCE_MISMATCH: String = "nonce_mismatch"

    /**
     * Maximum (and default) permitted clock skew in seconds for ID-token time
     * claims. CONTRACT.md §12.4 rule 5 caps this at 60s and forbids any
     * configuration above the bound.
     */
    const val MAX_CLOCK_SKEW_SEC: Int = 60

    /**
     * Clamps [clockSkewSec] into `[0, MAX_CLOCK_SKEW_SEC]`; `null` (unset)
     * defaults to the maximum. An explicit `0` is honored as "no tolerance"
     * rather than treated as unset — only the ABSENCE of a value defaults,
     * matching the TypeScript reference's `undefined`-only default rule.
     */
    fun resolveClockSkewSec(clockSkewSec: Int?): Int {
        if (clockSkewSec == null) return MAX_CLOCK_SKEW_SEC
        return clockSkewSec.coerceIn(0, MAX_CLOCK_SKEW_SEC)
    }

    /**
     * Constant-time string equality, used for the `nonce` comparison §12.4
     * rule 6 requires. A length mismatch short-circuits to `false`.
     */
    fun constantTimeEquals(a: String, b: String): Boolean {
        val left = a.toByteArray(Charsets.UTF_8)
        val right = b.toByteArray(Charsets.UTF_8)
        if (left.size != right.size) return false
        return MessageDigest.isEqual(left, right)
    }

    private fun idTokenAuthError(reason: String, message: String): AuthError =
        AuthError("id_token validation failed ($reason): $message", reason)

    /**
     * What an ID token is checked against by [checkClaims] (CONTRACT.md §12.4
     * rules 3-6).
     *
     * @property issuer the authoritative issuer — always the discovery
     *   document's `issuer`, never the client's own base URL (§12.3 rule 6)
     * @property clientId the relying party's own `client_id`, matched against
     *   `aud`/`azp` (rule 4)
     * @property nonce the `nonce` returned by `oidcBegin` and passed back into
     *   `oidcExchange`; `null` for `oidcRefresh`/`loginClientCredentials`,
     *   which skip rule 6 entirely (OIDC Core §12.2 does not require a nonce
     *   in a refresh-issued ID token) — this is deliberately DIFFERENT from
     *   an empty string, which would still enforce the rule
     * @property clockSkewSec permitted clock skew in seconds for
     *   `exp`/`iat`/`nbf` (rule 5); resolved via [resolveClockSkewSec] before use
     */
    data class Expectations(
        val issuer: String,
        val clientId: String,
        val nonce: String?,
        val hasNonce: Boolean,
        val clockSkewSec: Int? = null,
    )

    /**
     * CONTRACT.md §12.4 rules 3-6 — issuer, audience, time, and nonce checks
     * over an already-signature-verified claim set. Returns the decoded
     * [IdTokenClaims] on success; throws the matching [AuthError] reason code
     * on the FIRST failure.
     *
     * @param claims the JWS-verified JWT claims (rules 1-2 already passed)
     * @param expectations issuer/client_id/nonce/skew to check against
     * @param nowEpochSec current time in epoch seconds — injectable so tests can pin it
     */
    fun checkClaims(
        claims: JWTClaimsSet,
        expectations: Expectations,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): IdTokenClaims {
        val skew = resolveClockSkewSec(expectations.clockSkewSec).toLong()

        val iss = claims.issuer
            ?: throw idTokenAuthError(REASON_INVALID_ISSUER, "iss claim is missing")
        // Rule 3 — exact string comparison. No normalization, no
        // trailing-slash tolerance, no prefix matching.
        if (iss != expectations.issuer) {
            throw idTokenAuthError(REASON_INVALID_ISSUER, "iss does not equal the discovery document issuer")
        }

        // Rule 4 — aud must contain our client_id; with multiple audiences an
        // azp claim must be present and equal to it.
        val audiences: List<String> = claims.audience ?: emptyList()
        if (!audiences.contains(expectations.clientId)) {
            throw idTokenAuthError(REASON_INVALID_AUDIENCE, "aud does not contain this client_id")
        }
        val azp = claims.getStringClaim("azp")
        if (audiences.size > 1 && azp != expectations.clientId) {
            throw idTokenAuthError(
                REASON_INVALID_AUDIENCE,
                "aud holds multiple audiences and azp is absent or does not equal this client_id",
            )
        }

        // Rule 5 — exp must be in the future, iat must not be in the future,
        // nbf is honored when present; all within skew seconds. exp/iat are
        // treated as REQUIRED: a token with no expiry could never satisfy
        // "exp must be in the future", so absence is an expiry failure, not a
        // free pass (§12 port addendum item 11).
        val exp = claims.expirationTime
            ?: throw idTokenAuthError(REASON_TOKEN_EXPIRED, "exp claim is missing or not a number")
        if (exp.time / 1000 + skew <= nowEpochSec) {
            throw idTokenAuthError(REASON_TOKEN_EXPIRED, "exp is in the past")
        }
        val iat = claims.issueTime
            ?: throw idTokenAuthError(REASON_TOKEN_EXPIRED, "iat claim is missing or not a number")
        if (iat.time / 1000 - skew > nowEpochSec) {
            throw idTokenAuthError(REASON_TOKEN_EXPIRED, "iat is in the future")
        }
        val nbf = claims.notBeforeTime
        if (nbf != null && nbf.time / 1000 - skew > nowEpochSec) {
            throw idTokenAuthError(REASON_TOKEN_EXPIRED, "nbf is in the future")
        }

        // Rule 6 — mandatory for oidcExchange (hasNonce=true), skipped for
        // oidcRefresh/loginClientCredentials.
        val nonceClaim = claims.getStringClaim("nonce")
        if (expectations.hasNonce) {
            val expectedNonce = expectations.nonce
            if (expectedNonce == null || nonceClaim == null || !constantTimeEquals(nonceClaim, expectedNonce)) {
                throw idTokenAuthError(REASON_NONCE_MISMATCH, "nonce claim is absent or does not match the request nonce")
            }
        }

        return IdTokenClaims(
            iss = iss,
            sub = claims.subject ?: "",
            aud = audiences,
            exp = exp.time / 1000,
            iat = iat.time / 1000,
            nbf = nbf?.let { it.time / 1000 },
            nonce = nonceClaim,
            azp = azp,
            extra = extraClaims(claims),
        )
    }

    private val KNOWN_CLAIMS = setOf("iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "azp")

    /** Every claim NOT already modeled on [IdTokenClaims], preserved verbatim (CONTRACT.md §12.1 open-map requirement). */
    private fun extraClaims(claims: JWTClaimsSet): Map<String, Any?> {
        val all = claims.claims
        val extra = LinkedHashMap<String, Any?>()
        for ((key, value) in all) {
            if (key !in KNOWN_CLAIMS) extra[key] = value
        }
        return extra
    }
}

/**
 * The decoded, ALREADY-VALIDATED ID-token claim set carried by
 * [OidcTokenSet.idClaims] (CONTRACT.md §12.1).
 *
 * Claim names are kept verbatim in their JWT/OIDC spelling (`iss`, `sub`,
 * `aud`, …) rather than Kotlin's usual camelCase field-naming, and [extra]
 * preserves any further claim the server sends (e.g. `email`,
 * `preferred_username`) — the ID token's full claim set is not enumerated by
 * `openapi.json`, so unknown claims MUST be preserved and MUST NOT be
 * rejected (§12.1).
 *
 * @property iss issuer — matched for exact string equality against the discovery document's `issuer` (rule 3)
 * @property sub the authenticated end user's stable identifier at AXIAM
 * @property aud audience — contains the relying party's `client_id` (rule 4); always normalized to a list
 * @property exp expiry time (epoch seconds)
 * @property iat issued-at time (epoch seconds)
 * @property nbf not-before time (epoch seconds), when the server sends one
 * @property nonce the `nonce` echoed back from the authorization request (rule 6), when present
 * @property azp authorized party — required to equal `client_id` when [aud] holds multiple audiences (rule 4)
 * @property extra any further claim the server sends, preserved verbatim and never rejected
 */
data class IdTokenClaims(
    val iss: String,
    val sub: String,
    val aud: List<String>,
    val exp: Long,
    val iat: Long,
    val nbf: Long? = null,
    val nonce: String? = null,
    val azp: String? = null,
    val extra: Map<String, Any?> = emptyMap(),
)
