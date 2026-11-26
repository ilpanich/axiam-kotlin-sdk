package io.axiam.sdk

import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.AccessTokenFixtures.str
import io.axiam.sdk.AccessTokenFixtures.strings
import io.axiam.sdk.errors.AuthError
import kotlinx.serialization.json.JsonNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §10.1 rules 10-12 (contract 1.68; N14, N10, D-7): the token must
 * be an ACCESS token.
 *
 * AXIAM signs the MFA challenge, MFA setup and WebAuthn-state tokens with the
 * access-token key. Each carries `sub`, `tenant_id`, `iss` and `exp` — all that
 * rules 1-5 look at — and no `aud`, so a guard with no expected audience (the
 * default) admitted them as the user they name. Every verifier below is
 * therefore built with NO expected audience, and the tokens are otherwise
 * valid, so a rejection can only be the new rule's.
 *
 * Rule 12 (`kid` required) is already enforced by this SDK's key selection —
 * nimbus's single-key fallback is never taken — so its test is a pin, not a
 * regression test.
 */
class AccessTokenRulesTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    private fun assertRefused(token: String, label: String) {
        jwks.client().use { c ->
            assertThrows(AuthError::class.java, { c.verifySession(token) }, "[$label] must be refused")
        }
    }

    private fun assertAccepted(token: String, label: String) {
        jwks.client().use { c ->
            assertEquals("user-1", c.verifySession(token).userId, "[$label] must be accepted")
        }
    }

    // ---- rule 10: typ ------------------------------------------------------

    @Test
    fun `rule 10 - typ JWT is refused`() =
        assertRefused(AccessTokenFixtures.mint(key, typ = "JWT"), "typ JWT")

    @Test
    fun `rule 10 - an MFA challenge typ is refused`() =
        assertRefused(AccessTokenFixtures.mint(key, typ = "axiam-mfa-challenge+jwt"), "typ axiam-mfa-challenge+jwt")

    @Test
    fun `rule 10 - the WebAuthn state typ is refused`() =
        assertRefused(AccessTokenFixtures.mint(key, typ = "axiam-webauthn-state+jwt"), "typ axiam-webauthn-state+jwt")

    @Test
    fun `rule 10 - a logout token typ is refused`() =
        assertRefused(AccessTokenFixtures.mint(key, typ = "logout+jwt"), "typ logout+jwt")

    @Test
    fun `rule 10 - at+jwt in any case and with the application prefix is accepted`() {
        assertAccepted(AccessTokenFixtures.mint(key, typ = "at+jwt"), "at+jwt")
        assertAccepted(AccessTokenFixtures.mint(key, typ = "AT+JWT"), "AT+JWT")
        assertAccepted(AccessTokenFixtures.mint(key, typ = "application/at+jwt"), "application/at+jwt")
    }

    @Test
    fun `rule 10 - a header with no typ is not refused by this rule`() =
        assertAccepted(AccessTokenFixtures.mint(key, typ = null), "no typ")

    // ---- rule 11: purpose --------------------------------------------------

    @Test
    fun `rule 11 - a purpose claim is refused whatever typ says`() {
        assertRefused(
            AccessTokenFixtures.mint(key, typ = "at+jwt", claims = mapOf("purpose" to str("mfa_challenge"))),
            "purpose mfa_challenge with typ at+jwt",
        )
        // A pre-1.67 purpose token carries the generic typ.
        assertRefused(
            AccessTokenFixtures.mint(key, typ = "JWT", claims = mapOf("purpose" to str("mfa_challenge"))),
            "purpose mfa_challenge with typ JWT",
        )
        assertRefused(
            AccessTokenFixtures.mint(key, typ = null, claims = mapOf("purpose" to str("mfa_challenge"))),
            "purpose mfa_challenge with no typ",
        )
    }

    @Test
    fun `rule 11 - a null purpose is still a purpose`() =
        assertRefused(AccessTokenFixtures.mint(key, claims = mapOf("purpose" to JsonNull)), "purpose null")

    @Test
    fun `rule 11 - the WebAuthn discoverable state shape is refused`() =
        assertRefused(
            AccessTokenFixtures.mint(
                key,
                typ = "at+jwt",
                claims = mapOf(
                    "sub" to str("00000000-0000-0000-0000-000000000000"),
                    "purpose" to str("webauthn_authenticate_discoverable"),
                ),
            ),
            "WebAuthn discoverable state",
        )

    // ---- rule 12: kid (pin; already enforced) -------------------------------

    @Test
    fun `rule 12 - a header with no kid is refused even against a one-key JWKS`() {
        // The fallback "use the only key in the set" must not exist on this path.
        assertRefused(AccessTokenFixtures.mint(key, kid = null), "no kid")
    }

    // ---- the happy path ----------------------------------------------------

    @Test
    fun `a normal access token with scope but no purpose and no audience is accepted`() {
        val token = AccessTokenFixtures.mint(
            key,
            claims = mapOf("scope" to str("openid profile"), "roles" to strings("admin")),
        )
        jwks.client().use { c ->
            val user = c.verifySession(token)
            assertEquals("user-1", user.userId)
            assertEquals(TestSupport.TENANT_ID, user.tenantId)
        }
    }
}
