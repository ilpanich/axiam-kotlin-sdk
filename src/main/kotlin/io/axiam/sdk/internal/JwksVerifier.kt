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
 * [verify] verifies **signature only** — never `exp` (no expiry check here, by
 * design) and never tenant scoping. Callers MUST separately check `exp` and
 * call [assertTenant] (the JWKS endpoint is org-wide, so a valid signature does
 * not by itself imply the caller's tenant).
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
     * Verifies [token]'s signature (alg pinned to EdDSA, key from the
     * cached/rotated JWKS) and returns its claims.
     *
     * @throws AuthError if the token is malformed, the alg is not EdDSA, no
     *   matching key is found, or the signature is invalid.
     */
    fun verify(token: String): JWTClaimsSet {
        val jwt = try {
            SignedJWT.parse(token)
        } catch (e: Exception) {
            throw AuthError("malformed token: ${e.message}")
        }

        val header = jwt.header
        if (JWSAlgorithm.EdDSA != header.algorithm) {
            throw AuthError("unexpected JWS algorithm ${header.algorithm}: only EdDSA is accepted")
        }

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
     * [verify] (same [jwkSource], same [refreshLock] — never a forked fetch
     * path), but the thrown [AuthError] carries one of the §12.3 rule 3
     * reason codes (`invalid_alg`, `unknown_kid`, `invalid_signature`)
     * instead of [verify]'s plain messages, so the §12.4 orchestration in
     * `io.axiam.sdk.oidc` can classify the failure per the contract.
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
     * [verify] and [verifyForIdToken] treat a `null` result as their own
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
         * Cross-tenant carry-forward control: the JWKS endpoint is org-wide, so
         * a valid signature alone does not imply the token belongs to
         * [configuredTenantId]. Throws if the `tenant_id` claim is absent or
         * mismatched.
         */
        fun assertTenant(claims: JWTClaimsSet, configuredTenantId: String) {
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
