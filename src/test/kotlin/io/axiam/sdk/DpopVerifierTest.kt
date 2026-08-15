package io.axiam.sdk

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.DpopVerifier
import io.axiam.sdk.internal.DpopVerifier.DpopRequest
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
 *
 * Each check gets a negative test, because §21.7.2's whole premise is that a
 * verifier missing one of them still reports success. A suite that only proved
 * a good proof passes would not distinguish this object from returning the
 * thumbprint unconditionally.
 */
class DpopVerifierTest {

    private val method = "POST"
    private val uri = "https://rs.example.com/v1/things"
    private val token = "eyJhbGciOiJFZERTQSJ9.e30.sig"

    private lateinit var store: DpopVerifier.InMemoryJtiStore

    @BeforeEach
    fun setUp() {
        store = DpopVerifier.InMemoryJtiStore()
    }

    private fun newKey(): OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519).generate()

    private fun claims(overrides: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val c = linkedMapOf<String, Any?>(
            "htm" to method,
            "htu" to uri,
            "iat" to Instant.now().epochSecond,
            "jti" to "jti-${seq.incrementAndGet()}",
            "ath" to DpopVerifier.accessTokenHash(token),
        )
        overrides.forEach { (k, v) -> if (v == null) c.remove(k) else c[k] = v }
        return c
    }

    private fun header(jwk: JWK, typ: String = "dpop+jwt"): JWSHeader =
        JWSHeader.Builder(JWSAlgorithm.EdDSA).type(JOSEObjectType(typ)).jwk(jwk).build()

    private fun sign(key: OctetKeyPair, h: JWSHeader, c: Map<String, Any?>): String =
        JWSObject(h, Payload(c)).apply { sign(Ed25519Signer(key)) }.serialize()

    private fun goodProof(key: OctetKeyPair): String =
        sign(key, header(key.toPublicJWK()), claims())

    private fun request() = DpopRequest(method, uri, token)

    /**
     * Splice a new header onto an existing proof, leaving its signature
     * intact. Needed because Nimbus refuses to *emit* a header carrying
     * private key material, which is exactly what check 4 must be tested
     * against.
     */
    private fun spliceHeader(proof: String, h: Map<String, Any?>): String {
        val parts = proof.split(".")
        val encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(JSONObjectUtils.toJSONString(h).toByteArray(Charsets.UTF_8))
        return "$encoded.${parts[1]}.${parts[2]}"
    }

    // ------------------------------------------------------------------------
    // The happy path
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("a well-formed proof verifies and returns its thumbprint")
    fun wellFormedProofVerifies() {
        val key = newKey()
        val jkt = DpopVerifier.verifyProof(goodProof(key), request(), store)
        // Returning the thumbprint rather than Unit is what lets a guard pass a
        // value onward that could only have come from a verified proof.
        assertEquals(key.toPublicJWK().computeThumbprint().toString(), jkt)
        assertEquals(43, jkt.length)
    }

    @Test
    @DisplayName("query and fragment are stripped from both sides of htu")
    fun queryStringDoesNotMatter() {
        val key = newKey()
        val r = DpopRequest(method, "$uri?page=2#frag", token)
        DpopVerifier.verifyProof(goodProof(key), r, store)
    }

    /**
     * All three algorithms §21.7.2 check 2 permits, each verified through the
     * key type that implies it. HMAC families are absent from that list on
     * purpose — a symmetric "proof" verifiable with a key the verifier also
     * holds proves possession of nothing.
     */
    @Test
    @DisplayName("check 2: all three permitted algorithms verify")
    fun allPermittedAlgorithms() {
        val rsa = RSAKeyGenerator(2048).generate()
        val rsaProof = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.PS256).type(JOSEObjectType("dpop+jwt"))
                .jwk(rsa.toPublicJWK()).build(),
            Payload(claims()),
        ).apply { sign(RSASSASigner(rsa)) }.serialize()
        assertEquals(
            rsa.toPublicJWK().computeThumbprint().toString(),
            DpopVerifier.verifyProof(rsaProof, request(), store),
        )

        val ec = ECKeyGenerator(Curve.P_256).generate()
        val ecProof = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("dpop+jwt"))
                .jwk(ec.toPublicJWK()).build(),
            Payload(claims()),
        ).apply { sign(ECDSASigner(ec)) }.serialize()
        assertEquals(
            ec.toPublicJWK().computeThumbprint().toString(),
            DpopVerifier.verifyProof(ecProof, request(), store),
        )

        val okp = newKey()
        assertEquals(
            okp.toPublicJWK().computeThumbprint().toString(),
            DpopVerifier.verifyProof(goodProof(okp), request(), store),
        )
    }

    // ------------------------------------------------------------------------
    // One negative test per check
    // ------------------------------------------------------------------------

    /**
     * Without pinning typ, any other JWT signed by the same key — an access
     * token, an ID token — is replayable as a proof.
     */
    @Test
    @DisplayName("check 1: a proof without the dpop+jwt typ is refused")
    fun check1WrongTyp() {
        val key = newKey()
        val proof = sign(key, header(key.toPublicJWK(), typ = "JWT"), claims())
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("typ"), e.message)
    }

    @Test
    @DisplayName("check 1: the typ comparison is case-insensitive")
    fun check1TypCaseInsensitive() {
        val key = newKey()
        val proof = sign(key, header(key.toPublicJWK(), typ = "DPoP+JWT"), claims())
        DpopVerifier.verifyProof(proof, request(), store)
    }

    /**
     * The attack check 2 exists for, run for real.
     *
     * The attacker holds no private key. They take the *public* key out of a
     * proof they observed, use its raw bytes as an HMAC secret, sign a proof of
     * their own with HS256, and embed the same public jwk. A verifier that
     * reads alg from the header computes HMAC with that public key, gets a
     * match, and reports success — the signature is valid, just not proof of
     * anything.
     */
    @Test
    @DisplayName("check 2: the public-key-as-HMAC-secret forgery is refused")
    fun check2HmacForgery() {
        val key = newKey()
        val forged = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build(),
            Payload(claims()),
        ).apply { sign(MACSigner(key.x.decode())) }.serialize()

        assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(forged, request(), store)
        }
    }

    @Test
    @DisplayName("check 2: an unpermitted key type is refused")
    fun check2UnpermittedKeyType() {
        val key = newKey()
        val spliced = spliceHeader(
            goodProof(key),
            mapOf(
                "alg" to "EdDSA",
                "typ" to "dpop+jwt",
                "jwk" to mapOf("kty" to "EC", "crv" to "P-521", "x" to "AA", "y" to "AA"),
            ),
        )
        assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(spliced, request(), store)
        }
    }

    @Test
    @DisplayName("check 3: no jwk, or a signature by a different key, is refused")
    fun check3BadSignature() {
        val key = newKey()

        val stripped = spliceHeader(goodProof(key), mapOf("alg" to "EdDSA", "typ" to "dpop+jwt"))
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(stripped, request(), store)
        }
        assertTrue(e.message!!.contains("jwk"), e.message)

        // Signed by a DIFFERENT key than the one it embeds.
        val other = newKey()
        val forged = sign(other, header(key.toPublicJWK()), claims())
        assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(forged, request(), store)
        }
    }

    /**
     * RFC 9449 §4.3. Two layers refuse private key material: Nimbus rejects `d`
     * at parse time (it knows OKP's private member), and this SDK's own
     * raw-JSON check catches the other seven, which mean nothing to an OKP key.
     *
     * That is exactly why check 4 demands the raw header JSON rather than a
     * parsed key object: relying on the library alone would leave seven
     * unguarded here, and on a library that silently *drops* unknown members it
     * would leave all eight unguarded while appearing to pass.
     */
    @Test
    @DisplayName("check 4: private key material is refused, by whichever layer sees it")
    fun check4PrivateKeyMaterial() {
        val key = newKey()
        val proof = goodProof(key)
        for (member in listOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")) {
            val leaky = key.toPublicJWK().toJSONObject().toMutableMap()
            leaky[member] = "c2VjcmV0"
            val spliced = spliceHeader(
                proof,
                mapOf("alg" to "EdDSA", "typ" to "dpop+jwt", "jwk" to leaky),
            )
            assertThrows(AuthError::class.java, { DpopVerifier.verifyProof(spliced, request(), store) },
                "member $member was not caught")
        }
    }

    @Test
    @DisplayName("check 4: the raw-JSON check catches what the JOSE library does not")
    fun check4RawJsonCheckIsNotDeadCode() {
        val key = newKey()
        val proof = goodProof(key)
        for (member in listOf("p", "q", "dp", "dq", "qi", "oth", "k")) {
            val leaky = key.toPublicJWK().toJSONObject().toMutableMap()
            leaky[member] = "c2VjcmV0"
            val spliced = spliceHeader(
                proof,
                mapOf("alg" to "EdDSA", "typ" to "dpop+jwt", "jwk" to leaky),
            )
            val e = assertThrows(AuthError::class.java) {
                DpopVerifier.verifyProof(spliced, request(), store)
            }
            assertTrue(
                e.message!!.contains("private key material"),
                "member $member should be caught by this SDK's own check, got: ${e.message}",
            )
        }
    }

    @Test
    @DisplayName("check 5: a proof minted for another method is refused")
    fun check5WrongMethod() {
        val key = newKey()
        val proof = sign(key, header(key.toPublicJWK()), claims(mapOf("htm" to "GET")))
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("htm"), e.message)
    }

    @Test
    @DisplayName("check 6: a proof minted for another URI is refused")
    fun check6WrongUri() {
        val key = newKey()
        val proof = sign(
            key, header(key.toPublicJWK()),
            claims(mapOf("htu" to "https://rs.example.com/v1/other")),
        )
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("htu"), e.message)
    }

    /**
     * A normalising comparison is where two unequal URIs become equal. Only
     * query and fragment come off; case, default ports and trailing slashes are
     * left exactly as they are.
     */
    @Test
    @DisplayName("check 6: htu is compared without normalisation")
    fun check6NoNormalisation() {
        assertEquals("https://a.example/p", DpopVerifier.canonicalHtu("https://a.example/p?q=1#f"))
        assertNotEquals(
            DpopVerifier.canonicalHtu("https://A.example/P"),
            DpopVerifier.canonicalHtu("https://a.example/p"),
        )
        assertNotEquals(
            DpopVerifier.canonicalHtu("https://a.example:443/p"),
            DpopVerifier.canonicalHtu("https://a.example/p"),
        )
        assertNotEquals(
            DpopVerifier.canonicalHtu("https://a.example/p/"),
            DpopVerifier.canonicalHtu("https://a.example/p"),
        )
    }

    /**
     * Both directions. A proof from the future is as suspect as a stale one: it
     * is how a one-sided skew allowance becomes a long-lived proof.
     */
    @Test
    @DisplayName("check 7: a stale or future proof is refused")
    fun check7Freshness() {
        val key = newKey()
        val now = Instant.now()
        for (offset in listOf(-65L, 65L)) {
            val proof = sign(
                key, header(key.toPublicJWK()),
                claims(mapOf("iat" to now.epochSecond + offset)),
            )
            val r = DpopRequest(method, uri, token, now = now)
            val e = assertThrows(AuthError::class.java, { DpopVerifier.verifyProof(proof, r, store) },
                "offset $offset was accepted")
            assertTrue(e.message!!.contains("freshness window"), e.message)
        }
    }

    /**
     * Freshness bounds the window; the jti guard is what makes the window
     * unusable. Without this the same proof works repeatedly for a full minute.
     */
    @Test
    @DisplayName("check 8: a replayed proof is refused")
    fun check8Replay() {
        val key = newKey()
        val proof = goodProof(key)
        DpopVerifier.verifyProof(proof, request(), store)
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("replay"), e.message)
    }

    /**
     * The jti claim is a mutation, so it runs last. Claiming it earlier would
     * let an attacker burn arbitrary jti values out of the store using proofs
     * that were never going to verify — turning the replay guard into a
     * denial-of-service surface against legitimate proofs.
     */
    @Test
    @DisplayName("check 8: the jti is claimed only after every other check passes")
    fun check8JtiClaimedLast() {
        val key = newKey()
        val doomed = sign(
            key, header(key.toPublicJWK()),
            claims(mapOf("htm" to "GET", "jti" to "precious")),
        )
        assertThrows(AuthError::class.java) { DpopVerifier.verifyProof(doomed, request(), store) }

        assertTrue(
            store.claim("precious", Instant.now().plusSeconds(60)),
            "a failed proof must not burn its jti",
        )
    }

    /**
     * Without ath, a proof captured on one request can be re-aimed at a
     * different token held by the same key.
     */
    @Test
    @DisplayName("check 9: a proof aimed at another token is refused")
    fun check9WrongAth() {
        val key = newKey()
        val proof = sign(
            key, header(key.toPublicJWK()),
            claims(mapOf("ath" to DpopVerifier.accessTokenHash("some.other.token"))),
        )
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("ath"), e.message)
    }

    @Test
    @DisplayName("check 9: a proof with no ath at all is refused")
    fun check9MissingAth() {
        val key = newKey()
        val proof = sign(key, header(key.toPublicJWK()), claims(mapOf("ath" to null)))
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(proof, request(), store)
        }
        assertTrue(e.message!!.contains("ath"), e.message)
    }

    /**
     * This is the step that ties the proof to the token; the other nine are
     * what make the proof mean anything.
     */
    @Test
    @DisplayName("check 10: a proof by the wrong key is refused")
    fun check10WrongKey() {
        val key = newKey()
        val other = newKey()
        val r = request().copy(expectedJkt = other.toPublicJWK().computeThumbprint().toString())
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof(goodProof(key), r, store)
        }
        assertTrue(e.message!!.contains("cnf.jkt"), e.message)
    }

    // ------------------------------------------------------------------------
    // Thumbprint and framing
    // ------------------------------------------------------------------------

    /**
     * The RFC's own worked example. A thumbprint implementation that is
     * self-consistent but wrong agrees with itself on every round trip, so the
     * only useful test is against a published vector.
     */
    @Test
    @DisplayName("the thumbprint matches the RFC 7638 appendix A vector")
    fun rfc7638Vector() {
        val rsa = JWK.parse(
            """{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV""" +
                """T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9""" +
                """yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0""" +
                """zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3""" +
                """XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}""",
        )
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", DpopVerifier.thumbprintS256(rsa))
    }

    @Test
    @DisplayName("ath is base64url-unpadded SHA-256 over the token as it travelled")
    fun athShape() {
        val ath = DpopVerifier.accessTokenHash(token)
        assertEquals(43, ath.length)
        assertTrue(!ath.contains('='))
        assertEquals(ath, DpopVerifier.accessTokenHash(token))
        assertNotEquals(ath, DpopVerifier.accessTokenHash(token + "x"))
    }

    /**
     * RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the
     * first, which is how a verifier and a downstream parser end up reading
     * different proofs.
     */
    @Test
    @DisplayName("a header carrying two proofs is refused")
    fun twoProofsRefused() {
        val key = newKey()
        val proof = goodProof(key)
        val e = assertThrows(AuthError::class.java) {
            DpopVerifier.verifyProof("$proof,$proof", request(), store)
        }
        assertTrue(e.message!!.contains("exactly one proof"), e.message)
    }

    @Test
    @DisplayName("malformed proofs are refused as AuthError, not something else")
    fun malformedProofs() {
        for (junk in listOf("", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$")) {
            assertThrows(AuthError::class.java, { DpopVerifier.verifyProof(junk, request(), store) },
                "accepted $junk")
        }
    }

    private companion object {
        val seq = AtomicInteger()
    }
}
