package io.axiam.sdk

import com.nimbusds.jwt.JWTClaimsSet
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.PresentedProofs
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/** CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16). */
class TokenBindingTest {

    private val thumb = "bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM"
    private val jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    private val otherJkt = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    private fun claims(cnf: Map<String, Any>?): JWTClaimsSet =
        JWTClaimsSet.Builder().subject("u").apply { cnf?.let { claim("cnf", it) } }.build()

    /**
     * THE POSITIVE REGRESSION TEST, and the one this change is most likely to
     * break: an unbound token must still pass with no certificate and no proof.
     * The likeliest wrong implementation of rule 9 is one that starts demanding
     * evidence from every caller.
     */
    @Test
    @DisplayName("an unbound token is accepted with no proofs at all")
    fun unboundTokenNeedsNothing() {
        JwksVerifier.verifyTokenBinding(claims(null), PresentedProofs.none())
        // ...and proofs it never asked for do not make it invalid.
        JwksVerifier.verifyTokenBinding(claims(null), PresentedProofs(thumb, jkt))
    }

    @Test
    @DisplayName("a DPoP-bound token accepts the matching key")
    fun dpopBoundAcceptsMatchingKey() {
        JwksVerifier.verifyTokenBinding(claims(mapOf("jkt" to jkt)), PresentedProofs.dpop(jkt))
    }

    @Test
    @DisplayName("a DPoP-bound token is rejected without a proof or with the wrong key")
    fun dpopBoundRejectsMissingOrWrong() {
        val missing = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(claims(mapOf("jkt" to jkt)), PresentedProofs.none())
        }
        assertTrue(missing.message!!.contains("no verified DPoP proof"), missing.message)

        val wrong = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(
                claims(mapOf("jkt" to jkt)), PresentedProofs.dpop(otherJkt),
            )
        }
        assertTrue(wrong.message!!.contains("different DPoP key"), wrong.message)
    }

    @Test
    @DisplayName("a certificate-bound token still behaves exactly as before")
    fun certificateBoundUnchanged() {
        JwksVerifier.verifyTokenBinding(
            claims(mapOf("x5t#S256" to thumb)), PresentedProofs.certificate(thumb),
        )
        assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(claims(mapOf("x5t#S256" to thumb)), PresentedProofs.none())
        }
        assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(
                claims(mapOf("x5t#S256" to thumb)), PresentedProofs.certificate(otherJkt),
            )
        }
    }

    /**
     * BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints
     * asked for two; satisfying the more convenient one is not compliance. Each
     * half is asserted to fail alone, because "check whichever we can" is the
     * likeliest wrong implementation.
     */
    @Test
    @DisplayName("a cnf naming both methods requires both")
    fun bothNamedIsAConjunction() {
        val both = claims(mapOf("x5t#S256" to thumb, "jkt" to jkt))

        JwksVerifier.verifyTokenBinding(both, PresentedProofs(thumb, jkt))

        assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(both, PresentedProofs.certificate(thumb))
        }
        assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(both, PresentedProofs.dpop(jkt))
        }
    }

    /**
     * An empty cnf names nothing checkable and is refused, not read as unbound.
     * Over gRPC this is also how proto3 delivers an empty CnfClaim message,
     * which is why §10.3 rule 3 spells it out separately.
     */
    @Test
    @DisplayName("an empty cnf is refused rather than read as unbound")
    fun emptyCnfIsRefused() {
        val e = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyTokenBinding(claims(emptyMap()), PresentedProofs.none())
        }
        assertTrue(e.message!!.contains("no method this SDK can verify"), e.message)
    }

    /**
     * The narrow entry point refuses a DPoP-bound token rather than ignoring
     * the jkt it cannot check. That refusal is what lets it stay in the API
     * without becoming a downgrade path.
     */
    @Test
    @DisplayName("the certificate-only entry point refuses DPoP-bound and both-bound tokens")
    fun certificateOnlyEntryPointRefusesDpop() {
        for (presented in listOf(null, thumb)) {
            val e = assertThrows(AuthError::class.java) {
                JwksVerifier.verifyCertificateBinding(claims(mapOf("jkt" to jkt)), presented)
            }
            assertTrue(e.message!!.contains("cannot verify"), e.message)
        }

        val both = assertThrows(AuthError::class.java) {
            JwksVerifier.verifyCertificateBinding(
                claims(mapOf("x5t#S256" to thumb, "jkt" to jkt)), thumb,
            )
        }
        assertTrue(both.message!!.contains("both must hold"), both.message)
    }
}
