package io.axiam.sdk.errors

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §12 port addendum item 17: [OAuthProtocolError] is a SUB-TYPE
 * of [AuthError], not a fourth peer error type — existing `catch (e:
 * AuthError)` / `is AuthError` handling must keep matching it unchanged.
 */
class OAuthProtocolErrorTest {

    @Test
    fun `is a subclass of AuthError, so existing AuthError handling still matches it`() {
        val error: AuthError = OAuthProtocolError("invalid_grant", "the code was already used")
        assertTrue(error is AuthError)
        assertTrue(error is AxiamException)
    }

    @Test
    fun `message is exactly error colon error_description`() {
        val error = OAuthProtocolError("invalid_client", "unknown client_id")
        assertEquals("invalid_client: unknown client_id", error.message)
        assertEquals("invalid_client", error.error)
        assertEquals("unknown client_id", error.errorDescription)
    }

    @Test
    fun `reason is not set for an OAuthProtocolError - it is a distinct field from error`() {
        val error = OAuthProtocolError("invalid_grant", "expired")
        assertNull(error.reason)
    }

    @Test
    fun `a plain AuthError still defaults reason to null, backward compatibly`() {
        val error = AuthError("some failure")
        assertNull(error.reason)
        assertEquals("some failure", error.message)
    }

    @Test
    fun `an AuthError can carry a machine-readable reason code`() {
        val error = AuthError("id_token validation failed (invalid_issuer): iss mismatch", "invalid_issuer")
        assertEquals("invalid_issuer", error.reason)
    }
}
