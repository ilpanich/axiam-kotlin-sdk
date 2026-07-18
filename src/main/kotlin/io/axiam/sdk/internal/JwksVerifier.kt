package io.axiam.sdk.internal

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
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import java.net.URI
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Local JWT verification against the organization-wide EdDSA JWKS
 * (`{baseUrl}/oauth2/jwks`), the §10 middleware's verification primitive.
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
 * This verifies **signature only** — never `exp` (no expiry check here, by
 * design) and never tenant scoping. Callers MUST separately check `exp` and
 * call [assertTenant] (the JWKS endpoint is org-wide, so a valid signature does
 * not by itself imply the caller's tenant).
 */
class JwksVerifier(baseUrl: String) {

    private val jwkSource: RemoteJWKSet<SecurityContext>
    private val refreshLock = ReentrantLock()

    init {
        val trimmed = baseUrl.trimEnd('/')
        val jwksUrl = try {
            URI.create("$trimmed/oauth2/jwks").toURL()
        } catch (e: Exception) {
            throw IllegalArgumentException("invalid AXIAM base URL: $baseUrl", e)
        }
        val cache = DefaultJWKSetCache(300, 60, TimeUnit.SECONDS)
        jwkSource = RemoteJWKSet(jwksUrl, null, cache)
    }

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

        val key = selectKey(header)
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

    private fun selectKey(header: JWSHeader): OctetKeyPair {
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
            selectFromCache(selector)?.let { return it }
            val matches = try {
                jwkSource.get(selector, null)
            } catch (e: Exception) {
                throw AuthError("JWKS fetch failed: ${e.message}")
            }
            firstOctetKeyPair(matches)
                ?: throw AuthError("no matching EdDSA key found in JWKS (kid=${header.keyID})")
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
