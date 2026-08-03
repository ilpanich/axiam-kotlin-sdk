package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.TokenPair
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

class BuilderAndSensitiveTest {

    @Test
    fun `missing tenant is a construction error`() {
        assertThrows(AuthError::class.java) {
            AxiamClient.builder("https://axiam.example.com", null)
        }
        assertThrows(AuthError::class.java) {
            AxiamClient.builder("https://axiam.example.com", "  ")
        }
    }

    @Test
    fun `missing base url is a construction error`() {
        assertThrows(AuthError::class.java) {
            AxiamClient.builder("", "acme")
        }
    }

    // ---- SEC-073: plaintext base URL rejection (CONTRACT.md §6) -----------

    @Test
    fun `a plaintext http base url against a routable host is rejected`() {
        val ex = assertThrows(AuthError::class.java) {
            AxiamClient.builder("http://axiam.example.com", "acme")
        }
        assertTrue(ex.message!!.contains("https"))
    }

    @Test
    fun `a plaintext http base url against localhost is allowed`() {
        AxiamClient.builder("http://localhost:8080", "acme").build().use { client ->
            assertEquals("acme", client.tenantId())
            assertEquals("http://localhost:8080", client.baseUrl())
        }
    }

    @Test
    fun `a plaintext http base url against 127-0-0-1 or -- 1 is allowed`() {
        AxiamClient.builder("http://127.0.0.1:8080", "acme").build().close()
        AxiamClient.builder("http://[::1]:8080", "acme").build().close()
    }

    @Test
    fun `a non-http-s scheme base url is rejected`() {
        assertThrows(AuthError::class.java) {
            AxiamClient.builder("ftp://axiam.example.com", "acme")
        }
    }

    @Test
    fun `orgSlug and orgId are mutually exclusive - last call wins`() {
        val id = UUID.randomUUID()
        val b1 = AxiamClient.builder("https://x", "acme").orgSlug("slug").orgId(id)
        assertEquals(id, b1.orgId)
        assertNull(b1.orgSlug)

        val b2 = AxiamClient.builder("https://x", "acme").orgId(id).orgSlug("slug")
        assertEquals("slug", b2.orgSlug)
        assertNull(b2.orgId)
    }

    @Test
    fun `client builds and exposes tenant and base url`() {
        AxiamClient.builder("https://axiam.example.com/", "acme").build().use { client ->
            assertEquals("acme", client.tenantId())
            assertEquals("https://axiam.example.com", client.baseUrl())
        }
    }

    @Test
    fun `Sensitive redacts toString but exposes value internally`() {
        val s = Sensitive.of("super-secret-token")
        assertEquals("[SENSITIVE]", s.toString())
        assertFalse(s.toString().contains("secret"))
        assertEquals("super-secret-token", s.expose())
    }

    @Test
    fun `Sensitive works over byte arrays too`() {
        val bytes = "key-material".toByteArray()
        val s = Sensitive.of(bytes)
        assertEquals("[SENSITIVE]", s.toString())
        assertTrue(bytes.contentEquals(s.expose()))
    }

    @Test
    fun `TokenPair toString never prints tokens`() {
        val tp = TokenPair("access-xyz", "refresh-xyz", 123L)
        val str = tp.toString()
        assertFalse(str.contains("access-xyz"))
        assertFalse(str.contains("refresh-xyz"))
        assertTrue(str.contains("123"))
        assertEquals("access-xyz", tp.access)
        assertEquals("refresh-xyz", tp.refresh)
    }
}
