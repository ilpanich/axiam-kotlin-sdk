package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** CONTRACT.md §12.5: the five secret fields never leak via `toString()`. */
class OidcRedactionTest {

    private val secretMarker = "TOP-SECRET-VALUE-MUST-NOT-LEAK"

    @Test
    fun `OidcTokenSet toString redacts accessToken, refreshToken, and idToken but prints idClaims`() {
        val claims = IdTokenClaims(
            iss = "https://issuer.example.com",
            sub = "user-1",
            aud = listOf("client-1"),
            exp = 111,
            iat = 222,
        )
        val tokenSet = OidcTokenSet(
            accessToken = Sensitive.of(secretMarker),
            tokenType = "Bearer",
            expiresIn = 3600,
            refreshToken = Sensitive.of(secretMarker),
            idToken = Sensitive.of(secretMarker),
            idClaims = claims,
        )
        val text = tokenSet.toString()
        assertFalse(text.contains(secretMarker))
        assertTrue(text.contains("[SENSITIVE]"))
        assertTrue(text.contains("user-1"), "idClaims (non-secret) should still print")
    }

    @Test
    fun `AuthorizationRequest toString redacts codeVerifier but shows state and nonce`() {
        val request = AuthorizationRequest(
            url = "https://idp.example.com/authorize?...",
            state = "state-visible",
            nonce = "nonce-visible",
            codeVerifier = Sensitive.of(secretMarker),
        )
        val text = request.toString()
        assertFalse(text.contains(secretMarker))
        assertTrue(text.contains("state-visible"))
        assertTrue(text.contains("nonce-visible"))
    }

    @Test
    fun `OidcStateEntry toString redacts codeVerifier`() {
        val entry = OidcStateEntry(
            state = "s",
            nonce = "n",
            codeVerifier = Sensitive.of(secretMarker),
            redirectUri = "https://app.example.com/cb",
        )
        assertFalse(entry.toString().contains(secretMarker))
    }

    @Test
    fun `IntrospectParams and RevokeParams toString redact the token field`() {
        val introspect = IntrospectParams(token = Sensitive.of(secretMarker))
        val revoke = RevokeParams(token = Sensitive.of(secretMarker))
        assertFalse(introspect.toString().contains(secretMarker))
        assertFalse(revoke.toString().contains(secretMarker))
    }

    @Test
    fun `OidcExchangeParams and OidcRefreshParams toString redact their secret fields`() {
        val exchange = OidcExchangeParams(
            code = "auth-code",
            codeVerifier = Sensitive.of(secretMarker),
            redirectUri = "https://app.example.com/cb",
            nonce = "n",
        )
        val refresh = OidcRefreshParams(refreshToken = Sensitive.of(secretMarker))
        assertFalse(exchange.toString().contains(secretMarker))
        assertTrue(exchange.toString().contains("auth-code"))
        assertFalse(refresh.toString().contains(secretMarker))
    }
}
