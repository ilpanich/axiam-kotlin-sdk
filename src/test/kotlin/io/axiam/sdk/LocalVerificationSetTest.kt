package io.axiam.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.JwksVerifier
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64
import java.util.Date

/**
 * CONTRACT.md §10.1 "Minimum local-verification set (normative)".
 *
 * One test per rule plus the full mandated negative set: expired; no `exp`;
 * non-numeric `exp`; future `nbf`; different tenant; no `tenant_id`;
 * `alg: none`; an HS-signed token bearing an EdDSA `kid`; and — since this SDK
 * supports the optional configuration — issuer and audience mismatches.
 *
 * Everything here goes through [AxiamClient.verifySession], the documented
 * guard entry point. The signature-only primitive is exercised only to pin
 * that it really does skip the claim checks (which is why it is named
 * `verifySignatureOnlyUnchecked`).
 */
class LocalVerificationSetTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: OctetKeyPair

    private val issuer = "https://issuer.axiam.test"
    private val audience = "axiam:user"

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                if ((request.path ?: "").startsWith("/oauth2/jwks")) {
                    MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(com.nimbusds.jose.jwk.JWKSet(signingKey.toPublicJWK()).toString())
                } else {
                    MockResponse().setResponseCode(404)
                }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    // ---- fixtures -------------------------------------------------------

    private fun claims(
        tenant: String? = TestSupport.TENANT_ID,
        expOffsetSec: Long? = 3600,
        nbfOffsetSec: Long? = null,
        iss: String? = null,
        aud: String? = null,
    ): JWTClaimsSet {
        val b = JWTClaimsSet.Builder().subject("user-1").claim("scope", "documents:read")
        if (tenant != null) b.claim("tenant_id", tenant)
        if (expOffsetSec != null) b.expirationTime(Date(System.currentTimeMillis() + expOffsetSec * 1000))
        if (nbfOffsetSec != null) b.notBeforeTime(Date(System.currentTimeMillis() + nbfOffsetSec * 1000))
        if (iss != null) b.issuer(iss)
        if (aud != null) b.audience(aud)
        return b.build()
    }

    private fun signEd25519(claims: JWTClaimsSet, kid: String = "k1"): String {
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(kid).build(), claims)
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    /** A hand-rolled compact JWS whose payload is arbitrary JSON (so `exp` can be a string). */
    private fun signEd25519Raw(payloadJson: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"EdDSA","kid":"k1","typ":"JWT"}""".toByteArray())
        val payload = enc.encodeToString(payloadJson.toByteArray())
        val signer = Ed25519Signer(signingKey)
        val sig = signer.sign(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(),
            "$header.$payload".toByteArray(),
        )
        return "$header.$payload.$sig"
    }

    private fun client(expectedIssuer: String? = null, expectedAudience: String? = null): AxiamClient =
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .apply {
                if (expectedIssuer != null) expectedIssuer(expectedIssuer)
                if (expectedAudience != null) expectedAudience(expectedAudience)
            }
            .build()

    private fun assertRejected(token: String, expectedIssuer: String? = null, expectedAudience: String? = null) {
        client(expectedIssuer, expectedAudience).use { c ->
            assertThrows(AuthError::class.java) { c.verifySession(token) }
        }
    }

    // ---- rule 1: signature, alg pinned to EdDSA before key lookup -------

    @Test
    fun `rule 1 - an alg none token is rejected without consulting a key`() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none","kid":"k1","typ":"JWT"}""".toByteArray())
        val payload = enc.encodeToString(claims().toString().toByteArray())
        assertRejected("$header.$payload.")
        // Key lookup never happened: the JWKS endpoint was never called.
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `rule 1 - an HS-signed token bearing an EdDSA kid is rejected before key lookup`() {
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.HS256).keyID("k1").build(), claims())
        jwt.sign(MACSigner(ByteArray(32) { 7 }))
        assertRejected(jwt.serialize())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `rule 1 - a token with an unparseable header is rejected`() {
        assertRejected("bm90LWpzb24.bm90LWpzb24.c2ln")
    }

    @Test
    fun `rule 1 - a well-formed EdDSA header with an empty signature is rejected`() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"EdDSA","kid":"k1","typ":"JWT"}""".toByteArray())
        val payload = enc.encodeToString(claims().toString().toByteArray())
        assertRejected("$header.$payload.")
    }

    @Test
    fun `rule 1 - a JWKS key that is not Ed25519 is refused rather than used`() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                MockResponse().setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(
                        """{"keys":[{"kty":"OKP","crv":"Ed448","x":"${"A".repeat(76)}",""" +
                            """"kid":"k1","use":"sig","alg":"EdDSA"}]}""",
                    )
        }
        assertRejected(signEd25519(claims()))
    }

    // ---- rule 2: exp is REQUIRED ---------------------------------------

    @Test
    fun `rule 2 - an expired token is rejected`() {
        assertRejected(signEd25519(claims(expOffsetSec = -3600)))
    }

    @Test
    fun `rule 2 - a token with NO exp claim is rejected`() {
        val token = signEd25519(claims(expOffsetSec = null))
        client().use { c ->
            val error = assertThrows(AuthError::class.java) { c.verifySession(token) }
            assertTrue(error.message!!.contains("exp"), error.message)
        }
    }

    @Test
    fun `rule 2 - a token with a non-numeric exp is rejected`() {
        val token = signEd25519Raw("""{"sub":"user-1","tenant_id":"acme","exp":"tomorrow"}""")
        assertRejected(token)
    }

    // ---- rule 3: nbf honoured when present ------------------------------

    @Test
    fun `rule 3 - a token whose nbf is in the future is rejected`() {
        val token = signEd25519(claims(nbfOffsetSec = 3600))
        client().use { c ->
            val error = assertThrows(AuthError::class.java) { c.verifySession(token) }
            assertTrue(error.message!!.contains("nbf"), error.message)
        }
    }

    @Test
    fun `rule 3 - a token whose nbf is in the past is accepted`() {
        val token = signEd25519(claims(nbfOffsetSec = -3600))
        client().use { c -> assertEquals("user-1", c.verifySession(token).userId) }
    }

    // ---- rule 4: tenant_id REQUIRED and asserted ------------------------

    @Test
    fun `rule 4 - a token for a different tenant is rejected`() {
        assertRejected(signEd25519(claims(tenant = "another-tenant")))
    }

    @Test
    fun `rule 4 - a token with NO tenant_id claim is rejected`() {
        val token = signEd25519(claims(tenant = null))
        client().use { c ->
            val error = assertThrows(AuthError::class.java) { c.verifySession(token) }
            assertTrue(error.message!!.contains("tenant"), error.message)
        }
    }

    @Test
    fun `rule 4 - a blank configured tenant fails closed`() {
        val error = assertThrows(AuthError::class.java) {
            JwksVerifier.assertTenant(claims(), "")
        }
        assertTrue(error.message!!.contains("no configured tenant"), error.message)
    }

    // ---- rule 5: iss checked only when configured -----------------------

    @Test
    fun `rule 5 - iss is not checked when no expected issuer is configured`() {
        val token = signEd25519(claims(iss = "https://somebody-else.example"))
        client().use { c -> assertEquals("user-1", c.verifySession(token).userId) }
    }

    @Test
    fun `rule 5 - a mismatched iss is rejected when an expected issuer is configured`() {
        assertRejected(
            signEd25519(claims(iss = "https://somebody-else.example")),
            expectedIssuer = issuer,
        )
    }

    @Test
    fun `rule 5 - a missing iss is rejected when an expected issuer is configured`() {
        val token = signEd25519(claims())
        client(expectedIssuer = issuer).use { c ->
            val error = assertThrows(AuthError::class.java) { c.verifySession(token) }
            assertTrue(error.message!!.contains("iss"), error.message)
        }
    }

    // ---- rule 6: aud checked only when configured -----------------------

    @Test
    fun `rule 6 - aud is not checked when no expected audience is configured`() {
        val token = signEd25519(claims(aud = "some-other-api"))
        client().use { c -> assertEquals("user-1", c.verifySession(token).userId) }
    }

    @Test
    fun `rule 6 - a mismatched aud is rejected when an expected audience is configured`() {
        assertRejected(signEd25519(claims(aud = "some-other-api")), expectedAudience = audience)
    }

    @Test
    fun `rule 6 - a missing aud is rejected when an expected audience is configured`() {
        assertRejected(signEd25519(claims()), expectedAudience = audience)
    }

    // ---- rule 7: named, bounded clock skew ------------------------------

    @Test
    fun `iss and aud default to unconfigured on the assertion itself`() {
        // The guard always passes both explicitly; this pins the defaulted overload, i.e. that
        // "not configured" really is the default rather than something the caller must opt into.
        JwksVerifier.assertLocalClaims(
            claims(iss = "https://whoever.example", aud = "whatever"),
            TestSupport.TENANT_ID,
        )
    }

    @Test
    fun `rule 7 - the leeway is a bounded named constant of 60 seconds`() {
        assertEquals(60L, JwksVerifier.CLOCK_SKEW_SECONDS)
    }

    @Test
    fun `rule 7 - exp and nbf are compared within the named leeway`() {
        // 10s past exp and 10s before nbf both fall inside the 60s constant.
        val token = signEd25519(claims(expOffsetSec = -10, nbfOffsetSec = 10))
        client().use { c -> assertEquals("user-1", c.verifySession(token).userId) }
    }

    // ---- the full set applied together ----------------------------------

    @Test
    fun `a token satisfying every rule is accepted`() {
        val token = signEd25519(claims(nbfOffsetSec = -60, iss = issuer, aud = audience))
        client(expectedIssuer = issuer, expectedAudience = audience).use { c ->
            val user = c.verifySession(token)
            assertEquals("user-1", user.userId)
            assertEquals(TestSupport.TENANT_ID, user.tenantId)
        }
    }

    /**
     * The signature-only primitive is deliberately blind to every claim — this
     * pins WHY it may not be used as a guard, and why its name says so.
     */
    @Test
    fun `verifySignatureOnlyUnchecked accepts a permanent cross-tenant token`() {
        val token = signEd25519(claims(tenant = "another-tenant", expOffsetSec = null))
        client().use { c ->
            val claims = c.jwksVerifier().verifySignatureOnlyUnchecked(token)
            assertEquals("user-1", claims.subject)
            // ...and the guard rejects exactly that token.
            assertThrows(AuthError::class.java) { c.verifySession(token) }
        }
    }

    // --- Rule 9: sender-constrained (certificate-bound) access tokens -----------
    //
    // CONTRACT.md §10.1 rule 9 (contract 1.15, RFC 8705 §3 / RFC 7800). A token
    // carrying `cnf` is not a bearer token and must not be accepted as one.
    //
    // Three negatives and one positive. The POSITIVE is the one that matters most:
    // rule 9 must not become "every caller must present a certificate", which would
    // break every deployment that does not use mTLS at all.

    /** A real 43-character base64url x5t#S256, and a different one. */
    private val thumbprint = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    private val otherThumbprint = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18"

    private fun boundClaims(tp: String): JWTClaimsSet =
        JWTClaimsSet.Builder(claims()).claim("cnf", mapOf("x5t#S256" to tp)).build()

    /** The regression test that keeps rule 9 from becoming a certificate mandate. */
    @Test
    fun `rule 9 - an unbound token is accepted with or without a certificate`() {
        val unbound = claims()
        JwksVerifier.verifyCertificateBinding(unbound, null)
        JwksVerifier.verifyCertificateBinding(unbound, thumbprint)
    }

    @Test
    fun `rule 9 - a bound token is accepted with its own certificate`() {
        JwksVerifier.verifyCertificateBinding(boundClaims(thumbprint), thumbprint)
    }

    @Test
    fun `rule 9 - a bound token is rejected with no certificate`() {
        val e = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyCertificateBinding(boundClaims(thumbprint), null)
        }
        assertTrue(e.message!!.contains("no client certificate was presented"))
    }

    @Test
    fun `rule 9 - a bound token is rejected with a different certificate`() {
        val e = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyCertificateBinding(boundClaims(thumbprint), otherThumbprint)
        }
        assertTrue(e.message!!.contains("different client certificate"))
    }

    /**
     * The subtle one. A `cnf` naming a confirmation method this SDK cannot check is
     * an unverifiable constraint, never *no* constraint — read the other way, a
     * sender-constrained token silently degrades to a bearer token the day a newer
     * AXIAM issues a confirmation this SDK predates.
     */
    @Test
    fun `rule 9 - an unverifiable confirmation is rejected not ignored`() {
        val dpopish = JWTClaimsSet.Builder(claims())
            .claim("cnf", mapOf("jkt" to "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"))
            .build()

        for (presented in listOf(null, thumbprint)) {
            val e = assertThrows(AuthError::class.java) {
                JwksVerifier.verifyCertificateBinding(dpopish, presented)
            }
            assertTrue(e.message!!.contains("cannot verify"), e.message)
        }
    }

    /**
     * `assertLocalClaims` (rules 2-7) deliberately does not apply rule 9 — it has no
     * transport to ask for a peer certificate. Asserted so the split cannot be
     * collapsed by accident.
     */
    @Test
    fun `rule 9 - assertLocalClaims does not apply it`() {
        val bound = boundClaims(thumbprint)
        JwksVerifier.assertLocalClaims(bound, TestSupport.TENANT_ID)
        assertThrows(AuthError::class.java) {
            JwksVerifier.verifyCertificateBinding(bound, null)
        }
    }

    /**
     * RFC 7515 §2 base64url: unpadded, `-`/`_` rather than `+`/`/`. A padded or
     * standard-base64 value will not compare equal to what AXIAM put in the token.
     */
    @Test
    fun `rule 9 - the thumbprint helper produces unpadded base64url`() {
        val der = ByteArray(512) { 0x42 }
        val tp = JwksVerifier.certificateThumbprintS256(der)

        assertEquals(43, tp.length)
        assertTrue(!tp.contains("=") && !tp.contains("+") && !tp.contains("/"))
        assertEquals(tp, JwksVerifier.certificateThumbprintS256(der))
    }
}
