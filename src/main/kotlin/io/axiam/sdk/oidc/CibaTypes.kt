package io.axiam.sdk.oidc

import com.google.crypto.tink.subtle.Ed25519Sign
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.ValidationError
import kotlinx.coroutines.delay
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date

/**
 * Whom a CIBA request authenticates: **exactly one** hint (CONTRACT.md §33.2).
 *
 * A sealed type, so sending both hints, or neither, cannot be written.
 * `login_hint_token` is not offered: AXIAM refuses it (§33.3 rule 3).
 */
sealed interface CibaUserHint {
    /**
     * A username, then an e-mail address, within the tenant. Can be personal
     * data: the SDK never logs it.
     *
     * @property value the hint
     */
    data class LoginHint(val value: String) : CibaUserHint

    /**
     * An ID token this deployment issued to this client; it names the user
     * only (its expiry is not checked).
     *
     * @property value the compact ID token
     */
    data class IdTokenHint(val value: String) : CibaUserHint {
        /** Redacted: an ID token is a credential-shaped value. */
        override fun toString(): String = "IdTokenHint(value=[SENSITIVE])"
    }
}

/** How the client receives a CIBA outcome, as it registered (§33.3 rule 1). */
sealed interface CibaDelivery {
    /** The client polls the token endpoint ([io.axiam.sdk.AxiamClient.cibaAwait]). */
    data object Poll : CibaDelivery

    /**
     * AXIAM pings the client's registered notification endpoint, presenting
     * [clientNotificationToken] as a bearer; the client then polls once.
     *
     * @property clientNotificationToken the bearer AXIAM presents at the ping —
     *   keep it to check the ping with [io.axiam.sdk.AxiamClient.cibaHandlePing].
     *   AXIAM never returns it. Must not be empty.
     */
    data class Ping(val clientNotificationToken: Sensitive<String>) : CibaDelivery
}

/**
 * The algorithms a signed CIBA request may use (§33.2) — the client's
 * registered `backchannel_authentication_request_signing_alg`.
 *
 * @property jose the JOSE `alg` header value
 */
enum class CibaSigningAlg(val jose: JWSAlgorithm) {
    /** RSASSA-PSS with SHA-256. */
    PS256(JWSAlgorithm.PS256),

    /** ECDSA on P-256 with SHA-256. */
    ES256(JWSAlgorithm.ES256),

    /** Ed25519. */
    EDDSA(JWSAlgorithm.EdDSA),
}

/**
 * The key and algorithm for the signed request form (CONTRACT.md §33.2, CIBA
 * Core §7.1.1).
 *
 * Both are the caller's: there is no default for either, and the SDK signs
 * under exactly the algorithm given. A key that cannot sign under it is
 * refused at construction — the key is probe-signed — so a mismatch never
 * reaches the wire. The key is held only inside a JOSE signer; [toString]
 * shows the algorithm and `kid`, never the key.
 */
class CibaRequestSigner private constructor(
    /** The algorithm this signer signs under. */
    val alg: CibaSigningAlg,
    private val signer: JWSSigner,
    /** The `kid` header the signed request carries, if any. */
    val kid: String?,
) {

    /**
     * Signs [members] into the §33.2 request object: every member inside the
     * JWT, plus `iss` = [clientId], `aud` = [audience], `iat` = `nbf` = now,
     * `exp` = now + [SIGNED_REQUEST_LIFETIME], and a fresh 256-bit `jti`.
     */
    internal fun sign(clientId: String, audience: String, members: Map<String, Any>): Sensitive<String> {
        val now = Instant.now()
        val jti = ByteArray(32).also { RANDOM.nextBytes(it) }
        val claims = JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(audience)
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now))
            .expirationTime(Date.from(now.plus(SIGNED_REQUEST_LIFETIME)))
            .jwtID(Base64.getUrlEncoder().withoutPadding().encodeToString(jti))
        for ((name, value) in members) claims.claim(name, value)
        val header = JWSHeader.Builder(alg.jose).apply { kid?.let { keyID(it) } }.build()
        val jwt = SignedJWT(header, claims.build())
        try {
            jwt.sign(signer)
        } catch (_: Exception) {
            throw ValidationError(
                "cibaInitiate: the signed request could not be signed with the given key (CONTRACT.md §33.2)",
            )
        }
        return Sensitive.of(jwt.serialize())
    }

    /** The algorithm and `kid`; never the key. */
    override fun toString(): String = "CibaRequestSigner(alg=$alg, kid=$kid, key=[SENSITIVE])"

    companion object {
        /**
         * The lifetime of a signed request this SDK mints: five minutes, inside
         * the server's sixty-minute bound on `exp − nbf` (§33.2).
         */
        val SIGNED_REQUEST_LIFETIME: Duration = Duration.ofMinutes(5)

        private val RANDOM = SecureRandom()

        /**
         * A signer from a PKCS#8 PEM private key (the unencrypted `PRIVATE KEY` block)
         * and the algorithm it signs under.
         *
         * @param alg the registered algorithm
         * @param pem the PKCS#8 PEM; read once and not retained
         * @param kid the `kid` header to send, or `null`
         * @return the signer
         * @throws ValidationError locally, before any request, when the PEM is
         *   not a private key, or not one that signs under [alg]
         */
        fun fromPem(alg: CibaSigningAlg, pem: Sensitive<String>, kid: String? = null): CibaRequestSigner {
            val body = pem.expose().lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("-----") }
                .joinToString("")
            if (body.isEmpty()) throw refusal()
            val family = when (alg) {
                CibaSigningAlg.EDDSA -> "Ed25519"
                CibaSigningAlg.ES256 -> "EC"
                CibaSigningAlg.PS256 -> "RSA"
            }
            val key = try {
                KeyFactory.getInstance(family).generatePrivate(PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(body)))
            } catch (_: Exception) {
                throw refusal()
            }
            return of(alg, key, kid)
        }

        /**
         * A signer from a JCA [PrivateKey] and the algorithm it signs under:
         * an `EdECPrivateKey` (Ed25519) for [CibaSigningAlg.EDDSA], an
         * `ECPrivateKey` on P-256 for [CibaSigningAlg.ES256], an
         * `RSAPrivateKey` for [CibaSigningAlg.PS256].
         *
         * @param alg the registered algorithm
         * @param key the private key
         * @param kid the `kid` header to send, or `null`
         * @return the signer
         * @throws ValidationError locally, before any request, when [key]
         *   cannot sign under [alg]
         */
        fun of(alg: CibaSigningAlg, key: PrivateKey, kid: String? = null): CibaRequestSigner {
            val signer: JWSSigner = try {
                when (alg) {
                    CibaSigningAlg.EDDSA -> ed25519(key)
                    CibaSigningAlg.ES256 -> ECDSASigner(key as? ECPrivateKey ?: throw refusal())
                    CibaSigningAlg.PS256 -> RSASSASigner(key as? RSAPrivateKey ?: throw refusal())
                }.also { candidate ->
                    // A key that parses is not yet a key for this algorithm: prove it signs.
                    JWSObject(JWSHeader(alg.jose), Payload("axiam-ciba-probe")).sign(candidate)
                }
            } catch (e: ValidationError) {
                throw e
            } catch (_: Exception) {
                throw refusal()
            }
            return CibaRequestSigner(alg, signer, kid)
        }

        private fun ed25519(key: PrivateKey): JWSSigner {
            val ed = key as? EdECPrivateKey ?: throw refusal()
            if (!ed.params.name.equals("Ed25519", ignoreCase = true)) throw refusal()
            val seed = ed.bytes.orElseThrow { refusal() }
            val publicKey = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).publicKey
            val okp = OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey))
                .d(Base64URL.encode(seed))
                .build()
            return Ed25519Signer(okp)
        }

        private fun refusal() = ValidationError(
            "cibaInitiate: the signing key is not a private key that signs under the given algorithm " +
                "(CONTRACT.md §33.2)",
        )
    }
}

/**
 * Arguments to [io.axiam.sdk.AxiamClient.cibaInitiate] — §33.2's
 * `CibaInitiateRequest`, plus the call's routing.
 *
 * Exactly the members set are sent. `binding_message` and `login_hint` can be
 * personal data: the SDK never logs them. There is no parameter for
 * `login_hint_token`, `user_code` or `request_uri` — AXIAM refuses each
 * (§33.3 rule 3) — and none for extra form members, so the signed form cannot
 * be mixed with plain ones.
 *
 * @property scope space-separated; must include `openid`
 * @property hint whom to authenticate
 * @property bindingMessage shown to the user on the approval page — what lets
 *   them tell the request they started from one an attacker did; required for
 *   a `fapi2` client
 * @property requestedExpiry the requested lifetime in seconds, 30–600 (absent:
 *   300); sent as a string on the form, as a number inside a signed request
 * @property acrValues space-separated authentication context classes
 * @property resource an RFC 8707 resource indicator
 * @property delivery poll or ping, as the client registered
 * @property signer non-`null` sends the request as one signed JWT (`request`)
 *   — required of a client that registered a signing algorithm, refused from
 *   one that did not
 * @property tenantId tenant UUID for the `tenant_id` query parameter (§12.1
 *   note 2), or `null` for the client's own
 * @property configuration a pre-fetched discovery document, or `null` to use
 *   the cached one
 */
data class CibaInitiateParams(
    val scope: String,
    val hint: CibaUserHint,
    val bindingMessage: String? = null,
    val requestedExpiry: Int? = null,
    val acrValues: String? = null,
    val resource: String? = null,
    val delivery: CibaDelivery = CibaDelivery.Poll,
    val signer: CibaRequestSigner? = null,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * §33.2's `CibaInitiateResponse`.
 *
 * @property authReqId the request's id at the token endpoint — a bearer
 *   credential for the grant (§33.5). Never parse or length-check it.
 * @property expiresIn the request's lifetime in seconds — authoritative
 *   (§33.7 rule 4)
 * @property interval the minimum seconds between token requests: the
 *   response's value, or [DEFAULT_CIBA_INTERVAL_SECONDS] when it was absent or zero
 * @property receivedAt when the response was received; `cibaAwait`'s deadline
 *   is this plus [expiresIn]
 */
data class CibaInitiateResponse(
    val authReqId: Sensitive<String>,
    val expiresIn: Long,
    val interval: Long,
    val receivedAt: Instant,
)

/**
 * Arguments to [io.axiam.sdk.AxiamClient.cibaPoll].
 *
 * @property authReqId the `auth_req_id` from [CibaInitiateResponse] or a ping
 * @property tenantId tenant UUID for the `tenant_id` query parameter, or `null`
 * @property configuration a pre-fetched discovery document, or `null`
 */
data class CibaPollParams(
    val authReqId: Sensitive<String>,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * The clock [io.axiam.sdk.AxiamClient.cibaAwait] waits on — injectable, so its
 * schedule is testable without sleeping (§33.8 tests 6 and 7).
 */
interface CibaClock {
    /** The current instant. */
    fun now(): Instant

    /**
     * Waits [duration]. The system clock uses coroutine `delay`, so cancelling
     * the caller cancels the wait.
     *
     * @param duration how long to wait
     */
    suspend fun sleep(duration: Duration)

    companion object {
        /** The real clock: `Instant.now()` and `delay`. */
        val SYSTEM: CibaClock = object : CibaClock {
            override fun now(): Instant = Instant.now()
            override suspend fun sleep(duration: Duration) = delay(duration.toMillis())
            override fun toString(): String = "CibaClock.SYSTEM"
        }
    }
}

/**
 * Arguments to [io.axiam.sdk.AxiamClient.cibaAwait].
 *
 * @property tenantId tenant UUID for the `tenant_id` query parameter, or `null`
 * @property configuration a pre-fetched discovery document, or `null`
 * @property clock the clock to wait on
 */
data class CibaAwaitParams(
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
    val clock: CibaClock = CibaClock.SYSTEM,
)

/** The interval used when the initiate response carries none (§33.7 rule 2). */
const val DEFAULT_CIBA_INTERVAL_SECONDS: Long = 5

/** Seconds added to the interval per `slow_down`, permanently (§33.7 rule 3). */
const val CIBA_SLOW_DOWN_INCREMENT_SECONDS: Long = 5

/** `grant_type` of the CIBA token request (CIBA Core §10.1). */
const val CIBA_GRANT_TYPE: String = "urn:openid:params:grant-type:ciba"
