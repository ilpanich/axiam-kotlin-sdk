package io.axiam.sdk.internal

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.JSONObjectUtils
import io.axiam.sdk.errors.AuthError
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs

/**
 * DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
 *
 * The resource-server half of DPoP: given the `DPoP` header a caller
 * presented, decide whether it proves possession for **this** request and
 * **this** access token, and return the key thumbprint that
 * [JwksVerifier.verifyTokenBinding] then matches against the token's
 * `cnf.jkt`.
 *
 * ## Why this lives in the SDK
 *
 * §21.7.2 is a ten-check list, and the contract is blunt about partial
 * implementations: *"Partial verification is worse than none, because it
 * produces a guard that reports success."* Nine of the ten look optional until
 * someone builds an attack out of the one that was skipped, so they belong in
 * one audited place rather than in every application guarding an endpoint.
 *
 * The two most often missing, and what they cost:
 *
 * - **`typ`** — without pinning it to `dpop+jwt`, any *other* JWT signed by
 *   the same key (an access token, an ID token) is replayable as a proof.
 * - **`ath`** — without it, a proof captured on one request can be re-aimed at
 *   a different token held by the same key. `ath` binds the proof to the token
 *   rather than merely to the key.
 *
 * ## The algorithm comes from the key, never from the header
 *
 * `alg: none` and RSA-public-key-as-HMAC-secret are the same bug wearing
 * different clothes: *the token told the verifier how to check the token*.
 * This object picks the verifier from the embedded key's own type, so an HMAC
 * verifier is never a candidate no matter what the header says.
 */
object DpopVerifier {

    /**
     * §21.7.2 check 7 — the `iat` acceptance window, applied in **both**
     * directions. RFC 9449 recommends a small window without fixing a number;
     * 60 seconds is the contract's RECOMMENDED value. A named constant,
     * because a bare `60` three call frames deep is a number nobody ever
     * revisits.
     */
    val IAT_LEEWAY: Duration = Duration.ofSeconds(60)

    /**
     * RFC 9449 §4.3 — private key material that must never appear in a proof's
     * embedded public `jwk`. `k` is the symmetric-key member: its presence
     * means the "public key" is a shared secret.
     */
    private val PRIVATE_JWK_MEMBERS = listOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")

    /**
     * §21.7.2 check 8 — single-use `jti` tracking.
     *
     * One method, and its contract is the point: [claim] must be atomic. A
     * contains-then-add pair read as two calls is a race that two concurrent
     * replays of the same proof can both win.
     */
    fun interface JtiStore {
        /**
         * Record [jti] as used until [expiresAt].
         *
         * @return `true` if this is the first sighting, `false` if it is a replay.
         */
        fun claim(jti: String, expiresAt: Instant): Boolean
    }

    /**
     * A [JtiStore] for a single JVM.
     *
     * **Per-process, therefore per-instance.** Four replicas behind a load
     * balancer give an attacker four chances to replay a proof inside its
     * freshness window, and a restart clears the window entirely. Any
     * deployment running more than one process needs a shared store (Redis, a
     * database table).
     */
    class InMemoryJtiStore : JtiStore {
        private val seen = ConcurrentHashMap<String, Instant>()

        override fun claim(jti: String, expiresAt: Instant): Boolean {
            val now = Instant.now()
            // Prune inline. Entries only ever live for the freshness window,
            // so this stays small without a background sweeper.
            if (seen.size > 128) {
                seen.entries.removeIf { !it.value.isAfter(now) }
            }
            // putIfAbsent is the atomic half that matters: two concurrent
            // replays cannot both observe "absent" and both insert.
            val existing = seen.putIfAbsent(jti, expiresAt) ?: return true
            if (existing.isAfter(now)) return false
            // The recorded entry has expired; take it over.
            return seen.replace(jti, existing, expiresAt)
        }
    }

    /** What [verifyProof] needs about the current request. */
    data class DpopRequest(
        val httpMethod: String,
        val httpUri: String,
        val accessToken: String,
        /**
         * The token's `cnf.jkt`, when the caller has it. Supplying it performs
         * check 10 here; leaving it null means the caller must do that
         * comparison itself, which [JwksVerifier.verifyTokenBinding] does.
         */
        val expectedJkt: String? = null,
        val leeway: Duration = IAT_LEEWAY,
        /** Override for the current time, for tests. */
        val now: Instant? = null,
    )

    /**
     * Verify a DPoP proof against this request — all ten §21.7.2 checks.
     *
     * Returns the proof key's RFC 7638 thumbprint (`jkt`) on success. Feed it
     * to [JwksVerifier.verifyTokenBinding] as [PresentedProofs.dpopThumbprint];
     * returning it rather than `Unit` is deliberate, so the value a guard
     * passes onward could only have come from a proof that actually verified.
     *
     * There is no "just check the signature" mode, because that is exactly the
     * partial verification the contract calls worse than none.
     *
     * @throws AuthError on any failing check.
     */
    fun verifyProof(proof: String, request: DpopRequest, jtiStore: JtiStore): String {
        if (proof.isEmpty()) throw AuthError("DPoP proof is missing or empty")
        // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats
        // picking the first, which is how a verifier and a downstream parser
        // end up reading different proofs.
        if (proof.contains(',') || proof.trim().any { it.isWhitespace() }) {
            throw AuthError("DPoP header must carry exactly one proof")
        }

        val jws = try {
            JWSObject.parse(proof)
        } catch (e: Exception) {
            throw AuthError("DPoP proof is not a compact JWS: ${e.message}")
        }

        // Check 1 — typ. First, because it is what stops any other JWT signed
        // by the same key from standing in as a proof.
        val typ = jws.header.type?.toString().orEmpty()
        if (!typ.equals("dpop+jwt", ignoreCase = true)) {
            throw AuthError("DPoP proof typ header must be 'dpop+jwt', got '$typ'")
        }

        // Check 3 (first half) — the header carries a public jwk.
        val jwk = jws.header.jwk ?: throw AuthError("DPoP proof header must carry a public 'jwk'")

        // Check 4 — no private material, tested against the RAW header JSON.
        //
        // Nimbus would already refuse a private JWK at parse, but this check
        // runs against the raw JSON on purpose: §21.7.2 check 4 requires it,
        // because many JWK libraries quietly drop d/p/q when parsing into a
        // public-key type — the check would then pass by virtue of the library
        // having hidden the evidence.
        val rawJwk = rawHeaderJwk(proof)
        PRIVATE_JWK_MEMBERS.firstOrNull { rawJwk.containsKey(it) }?.let {
            throw AuthError("DPoP proof jwk carries private key material ($it) — RFC 9449 §4.3")
        }

        // Checks 2 and 3 (second half) — the verifier is chosen by the KEY's
        // own type, and the signature must verify under it.
        val verifier = verifierFor(jwk)
        val ok = try {
            jws.verify(verifier)
        } catch (e: Exception) {
            throw AuthError("DPoP proof signature could not be checked: ${e.message}")
        }
        if (!ok) throw AuthError("DPoP proof signature is invalid")

        val claims = try {
            JSONObjectUtils.parse(jws.payload.toString())
        } catch (e: Exception) {
            throw AuthError("DPoP proof payload is not a JSON object")
        }

        // Check 5 — htm.
        val htm = claims["htm"] as? String
        if (htm != request.httpMethod) {
            throw AuthError("DPoP proof htm $htm does not match request method ${request.httpMethod}")
        }

        // Check 6 — htu, with query and fragment stripped from BOTH sides and
        // nothing else touched.
        val htu = claims["htu"] as? String
        val expectedHtu = canonicalHtu(request.httpUri)
        if (htu == null || canonicalHtu(htu) != expectedHtu) {
            throw AuthError("DPoP proof htu $htu does not match request URI $expectedHtu")
        }

        // Check 7 — iat freshness, in both directions. A proof from the future
        // is as suspect as a stale one: it is how a one-sided skew allowance
        // becomes a long-lived proof.
        val iatNum = claims["iat"] as? Number ?: throw AuthError("DPoP proof iat must be a number")
        val iat = Instant.ofEpochSecond(iatNum.toLong())
        val now = request.now ?: Instant.now()
        if (abs(Duration.between(iat, now).seconds) > request.leeway.seconds) {
            throw AuthError("DPoP proof iat is outside the ${request.leeway.seconds}s freshness window")
        }

        // Check 9 — ath ties the proof to this specific access token.
        val ath = claims["ath"] as? String
        if (ath.isNullOrEmpty()) throw AuthError("DPoP proof is missing the ath claim")
        if (!MessageDigest.isEqual(
                ath.toByteArray(Charsets.UTF_8),
                accessTokenHash(request.accessToken).toByteArray(Charsets.UTF_8),
            )
        ) {
            throw AuthError("DPoP proof ath does not match the presented access token")
        }

        // Check 10 — the thumbprint that ties the proof to the token's cnf.
        val jkt = thumbprintS256(jwk)
        val expectedJkt = request.expectedJkt
        if (expectedJkt != null &&
            !MessageDigest.isEqual(
                jkt.toByteArray(Charsets.UTF_8),
                expectedJkt.toByteArray(Charsets.UTF_8),
            )
        ) {
            throw AuthError("DPoP proof key does not match the token's cnf.jkt")
        }

        // Check 8 — jti single-use. LAST on purpose: claiming a jti is a
        // mutation, and doing it before the cheap checks would let an attacker
        // burn arbitrary jti values out of the store with proofs that were
        // never going to verify.
        val jti = claims["jti"] as? String
        if (jti.isNullOrEmpty()) throw AuthError("DPoP proof is missing a non-empty jti")
        if (!jtiStore.claim(jti, iat.plus(request.leeway))) {
            throw AuthError("DPoP proof jti has already been used (replay)")
        }

        return jkt
    }

    /**
     * §21.7.2 check 2 — pick the verifier from the key itself.
     *
     * This function is why the proof header's `alg` never selects anything:
     * the key's own type determines how a signature over it can be checked,
     * and that is not a matter the presenter gets an opinion on. An HMAC
     * verifier is not reachable from here at all, which is what defeats the
     * public-key-as-shared-secret forgery.
     */
    private fun verifierFor(jwk: JWK): JWSVerifier = try {
        when {
            jwk is RSAKey -> RSASSAVerifier(jwk.toRSAPublicKey())
            jwk is ECKey && jwk.curve == Curve.P_256 -> ECDSAVerifier(jwk.toECPublicKey())
            jwk is OctetKeyPair && jwk.curve == Curve.Ed25519 -> Ed25519Verifier(jwk.toPublicJWK())
            else -> throw AuthError(
                "DPoP proof key type is not permitted by CONTRACT.md §21.7.2 " +
                    "(permitted: ES256, EdDSA, PS256)",
            )
        }
    } catch (e: AuthError) {
        throw e
    } catch (e: Exception) {
        throw AuthError("DPoP proof jwk is not a usable public key: ${e.message}")
    }

    /** The proof's `jwk` header member as raw JSON, for check 4. */
    private fun rawHeaderJwk(proof: String): Map<String, Any?> {
        val segments = proof.split(".")
        if (segments.size != 3) {
            throw AuthError("DPoP proof is not a compact JWS with three segments")
        }
        return try {
            val header = JSONObjectUtils.parse(
                String(Base64.getUrlDecoder().decode(segments[0]), Charsets.UTF_8),
            )
            @Suppress("UNCHECKED_CAST")
            (header["jwk"] as? Map<String, Any?>) ?: emptyMap()
        } catch (e: Exception) {
            throw AuthError("DPoP proof header is not valid base64url JSON")
        }
    }

    /**
     * RFC 7638 SHA-256 thumbprint of a JWK — the `jkt`.
     *
     * Only the members RFC 7638 names for the key type take part. Members
     * outside that set (`kid`, `use`, `alg`, `x5c`) are excluded by the spec,
     * which is what makes the thumbprint stable across two encodings of the
     * same key.
     */
    fun thumbprintS256(jwk: JWK): String = try {
        jwk.computeThumbprint().toString()
    } catch (e: Exception) {
        throw AuthError("DPoP proof jwk cannot be fingerprinted: ${e.message}")
    }

    /**
     * The `ath` claim value for [accessToken] — RFC 9449 §4.2.
     *
     * base64url-unpadded SHA-256 over the token's bytes exactly as they
     * travelled in the `Authorization` header, not over anything decoded out
     * of them.
     */
    fun accessTokenHash(accessToken: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.US_ASCII)),
        )

    /**
     * The `htu` comparison form — §21.7.2 check 6.
     *
     * Query and fragment removed, and **nothing else**. No case folding, no
     * default-port elision, no percent-decoding, no trailing-slash fixing: a
     * normalising comparison is precisely where two unequal URIs become equal,
     * and an attacker who finds such a pair can aim a proof at an endpoint it
     * was never minted for.
     */
    fun canonicalHtu(uri: String): String =
        uri.substringBefore('#').substringBefore('?')
}
