package io.axiam.sdk.oidc

import com.nimbusds.jwt.JWTClaimsSet
import io.axiam.sdk.errors.AuthError
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Date

/** CONTRACT.md §12.4 rules 3-6 (issuer, audience, time, nonce) via [OidcIdToken.checkClaims]. */
class OidcIdTokenClaimsTest {

    private val issuer = "https://issuer.example.com"
    private val clientId = "test-client"
    private val now = 1_000_000L

    private fun claims(
        iss: String? = issuer,
        sub: String = "user-1",
        aud: List<String> = listOf(clientId),
        exp: Long? = now + 3600,
        iat: Long? = now,
        nbf: Long? = null,
        nonce: String? = "the-nonce",
        azp: String? = null,
    ): JWTClaimsSet {
        val builder = JWTClaimsSet.Builder().subject(sub)
        iss?.let { builder.issuer(it) }
        if (aud.size == 1) builder.audience(aud[0]) else if (aud.isNotEmpty()) builder.audience(aud)
        exp?.let { builder.expirationTime(Date(it * 1000)) }
        iat?.let { builder.issueTime(Date(it * 1000)) }
        nbf?.let { builder.notBeforeTime(Date(it * 1000)) }
        nonce?.let { builder.claim("nonce", it) }
        azp?.let { builder.claim("azp", it) }
        builder.claim("email", "u@example.com")
        return builder.build()
    }

    private fun expectations(nonce: String? = "the-nonce", hasNonce: Boolean = true, clockSkewSec: Int? = null) =
        OidcIdToken.Expectations(issuer = issuer, clientId = clientId, nonce = nonce, hasNonce = hasNonce, clockSkewSec = clockSkewSec)

    @Test
    fun `valid claims pass and produce the expected IdTokenClaims, preserving unknown claims`() {
        val result = OidcIdToken.checkClaims(claims(), expectations(), nowEpochSec = now)
        assertEquals(issuer, result.iss)
        assertEquals("user-1", result.sub)
        assertEquals(listOf(clientId), result.aud)
        assertEquals("the-nonce", result.nonce)
        assertEquals("u@example.com", result.extra["email"])
    }

    @Test
    fun `invalid_issuer - mismatched iss is rejected with no normalization`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(iss = "https://issuer.example.com/"), expectations(), nowEpochSec = now)
        }
        assertEquals("invalid_issuer", ex.reason)
    }

    @Test
    fun `invalid_issuer - a missing iss claim is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(iss = null), expectations(), nowEpochSec = now)
        }
        assertEquals("invalid_issuer", ex.reason)
    }

    @Test
    fun `invalid_audience - aud without our client_id is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(aud = listOf("someone-else")), expectations(), nowEpochSec = now)
        }
        assertEquals("invalid_audience", ex.reason)
    }

    @Test
    fun `invalid_audience - multiple audiences without a matching azp is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(aud = listOf(clientId, "other-aud")), expectations(), nowEpochSec = now)
        }
        assertEquals("invalid_audience", ex.reason)
    }

    @Test
    fun `multiple audiences with a matching azp is accepted`() {
        val result = OidcIdToken.checkClaims(
            claims(aud = listOf(clientId, "other-aud"), azp = clientId),
            expectations(),
            nowEpochSec = now,
        )
        assertEquals(listOf(clientId, "other-aud"), result.aud)
    }

    @Test
    fun `token_expired - exp in the past beyond the clock-skew allowance is rejected`() {
        // 10s in the past would be tolerated by the default 60s skew (rule
        // 5); use a delta that exceeds it to test the boundary cleanly.
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(exp = now - 120), expectations(), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `token_expired - a missing exp claim is rejected (treated as required)`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(exp = null), expectations(), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `token_expired - a missing iat claim is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(iat = null), expectations(), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `token_expired - a future iat is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(iat = now + 3600), expectations(), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `token_expired - a future nbf is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(nbf = now + 3600), expectations(), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `a past nbf within skew is accepted`() {
        val result = OidcIdToken.checkClaims(claims(nbf = now - 10), expectations(), nowEpochSec = now)
        assertEquals(now - 10, result.nbf)
    }

    @Test
    fun `clock skew of up to 60s tolerates a just-expired token`() {
        val result = OidcIdToken.checkClaims(claims(exp = now - 30), expectations(clockSkewSec = 60), nowEpochSec = now)
        assertEquals(now - 30, result.exp)
    }

    @Test
    fun `clock skew above 60s is clamped to the 60s ceiling`() {
        // exp is 90s in the past: within a requested (but clamped) 300s skew
        // this would pass if the clamp did not apply; it must still fail.
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(exp = now - 90), expectations(clockSkewSec = 300), nowEpochSec = now)
        }
        assertEquals("token_expired", ex.reason)
    }

    @Test
    fun `nonce_mismatch - a different nonce is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(nonce = "other-nonce"), expectations(nonce = "the-nonce"), nowEpochSec = now)
        }
        assertEquals("nonce_mismatch", ex.reason)
    }

    @Test
    fun `nonce_mismatch - a missing nonce claim is rejected when one is expected`() {
        val ex = assertThrows(AuthError::class.java) {
            OidcIdToken.checkClaims(claims(nonce = null), expectations(nonce = "the-nonce"), nowEpochSec = now)
        }
        assertEquals("nonce_mismatch", ex.reason)
    }

    @Test
    fun `rule 6 is skipped entirely for a refresh-issued id_token`() {
        val result = OidcIdToken.checkClaims(
            claims(nonce = null),
            expectations(nonce = null, hasNonce = false),
            nowEpochSec = now,
        )
        assertEquals(null, result.nonce)
    }

    @Test
    fun `constantTimeEquals is false for differing lengths and true for identical strings`() {
        assertFalse(OidcIdToken.constantTimeEquals("abc", "abcd"))
        assertTrue(OidcIdToken.constantTimeEquals("abc", "abc"))
        assertFalse(OidcIdToken.constantTimeEquals("abc", "xyz"))
    }

    @Test
    fun `resolveClockSkewSec defaults only when unset (null) and clamps into 0 through 60`() {
        assertEquals(60, OidcIdToken.resolveClockSkewSec(null))
        assertEquals(0, OidcIdToken.resolveClockSkewSec(0), "an explicit 0 means no tolerance, not unset")
        assertEquals(0, OidcIdToken.resolveClockSkewSec(-5))
        assertEquals(60, OidcIdToken.resolveClockSkewSec(500))
        assertEquals(30, OidcIdToken.resolveClockSkewSec(30))
    }
}
