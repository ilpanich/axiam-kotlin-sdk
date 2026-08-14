package io.axiam.sdk.internal

import com.nimbusds.jose.Header
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Local JWT verification against an EdDSA JWKS document, the §10 middleware's
 * verification primitive — extended (never forked) by [verifyForIdToken] for
 * the CONTRACT.md §12.4 ID-token validation checklist.
 *
 * Keys are fetched/cached/rotated by nimbus's [RemoteJWKSet] +
 * [DefaultJWKSetCache] (TTL 300s, forced-refetch cooldown 60s — matching the
 * sibling SDKs' defaults).
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
class JwksVerifier private constructor(jwksUrl: URL) {

    private val jwkSource: RemoteJWKSet<SecurityContext> =
        RemoteJWKSet(jwksUrl, null, DefaultJWKSetCache(300, 60, TimeUnit.SECONDS))
    private val refreshLock = ReentrantLock()

    /**
     * The §10 middleware's public entry point: a verifier bound to
     * `{baseUrl}/oauth2/jwks`.
     */
    constructor(baseUrl: String) : this(deriveJwksUrl(baseUrl))

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
    fun verifySignatureOnlyUnchecked(token: String): JWTClaimsSet {
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
        return try {
            jwt.jwtClaimsSet
        } catch (e: Exception) {
            throw AuthError("malformed claims: ${e.message}")
        }
    }

    /**
     * CONTRACT.md §12.4 rules 1-2 for an OIDC `id_token`: the SAME
     * alg-allowlist + kid-lookup + one-shot unknown-kid-refetch machinery as
     * [verifySignatureOnlyUnchecked] (same [jwkSource], same [refreshLock] —
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
     * Resolves the EdDSA key matching [header]'s `kid` from the cached JWKS,
     * forcing exactly one re-fetch on a cache miss before giving up. Returns
     * `null` — never throws — on ANY failure to produce a match: no `kid`
     * header, a `kid` absent from the JWKS even after the re-fetch, or the
     * re-fetch itself failing (e.g. the JWKS endpoint returning a 5xx). Both
     * [verifySignatureOnlyUnchecked] and [verifyForIdToken] treat a `null`
     * result as their own
     * "no matching key" failure — this is the ONE shared fetch/cache/refetch
     * code path (CONTRACT.md §12 forbids forking the JWKS mechanism).
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

        selectFromCache(selector)?.let { return it }

        return refreshLock.withLock {
            selectFromCache(selector)?.let { return@withLock it }
            val matches = try {
                jwkSource.get(selector, null)
            } catch (_: Exception) {
                emptyList()
            }
            firstOctetKeyPair(matches)
        }
    }

    private fun selectFromCache(selector: JWKSelector): OctetKeyPair? {
        val cached = jwkSource.cachedJWKSet ?: return null
        return firstOctetKeyPair(selector.select(cached))
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
        fun forJwksUri(jwksUri: String): JwksVerifier {
            val url = try {
                URI.create(jwksUri).toURL()
            } catch (e: Exception) {
                throw IllegalArgumentException("invalid jwks_uri: $jwksUri", e)
            }
            return JwksVerifier(url)
        }

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
                throw AuthError(
                    "token carries a cnf confirmation naming a method this SDK cannot verify " +
                        "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one)",
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
