package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthFlowTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `login success returns a user and sends the tenant header`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        TestSupport.clientFor(server).use { client ->
            val result = client.login("alice@example.com", "pw")
            assertFalse(result.mfaRequired)
            assertNotNull(result.user)
            assertEquals("user-1", result.user!!.userId)
            assertTrue(result.user!!.roles.contains("documents:read"))
        }
        val recorded = server.takeRequest()
        assertEquals("/api/v1/auth/login", recorded.path)
        assertEquals("acme", recorded.getHeader("X-Tenant-ID"))
    }

    @Test
    fun `login 202 signals MFA required with a sensitive challenge token`() = runBlocking {
        server.enqueue(TestSupport.json(202, """{"challenge_token":"chal-123"}"""))
        TestSupport.clientFor(server).use { client ->
            val result = client.login("alice@example.com", "pw")
            assertTrue(result.mfaRequired)
            assertNotNull(result.challengeToken)
            assertEquals("[SENSITIVE]", result.challengeToken.toString())
            assertNull(result.user)
        }
    }

    @Test
    fun `verifyMfa completes the login`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        TestSupport.clientFor(server).use { client ->
            val result = client.verifyMfa(Sensitive.of("chal-123"), "000000")
            assertFalse(result.mfaRequired)
            assertNotNull(result.user)
        }
        val recorded = server.takeRequest()
        assertEquals("/api/v1/auth/mfa/verify", recorded.path)
    }

    @Test
    fun `login wrong credentials maps 401 to AuthError`(): Unit = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) {
                runBlocking { client.login("alice@example.com", "bad") }
            }
        }
    }

    @Test
    fun `logout posts the session id and clears state`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            client.login("alice@example.com", "pw")
            server.takeRequest() // login
            client.logout()
            val recorded = server.takeRequest()
            assertEquals("/api/v1/auth/logout", recorded.path)
            assertTrue(recorded.body.readUtf8().contains("session-1"))
        }
    }

    @Test
    fun `logout without a session throws AuthError`() {
        assertThrows(AuthError::class.java) {
            runBlocking { TestSupport.clientFor(server).use { it.logout() } }
        }
    }

    @Test
    fun `cookie jar persists the session across requests`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        TestSupport.clientFor(server).use { client ->
            client.login("alice@example.com", "pw")
            server.takeRequest() // login
            client.checkAccess("read", "r-1")
            val check = server.takeRequest()
            // The bearer sourced from the axiam_access cookie is present on the
            // follow-up request — proof the jar persisted the session (§4).
            assertNotNull(check.getHeader("Authorization"))
            assertTrue(check.getHeader("Authorization")!!.startsWith("Bearer "))
        }
    }

    @Test
    fun `CSRF token captured on login is echoed on the next state-changing request`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse()) // sets X-CSRF-Token: csrf-abc
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        TestSupport.clientFor(server).use { client ->
            client.login("alice@example.com", "pw")
            server.takeRequest()
            client.checkAccess("read", "r-1")
            val check = server.takeRequest()
            assertEquals("csrf-abc", check.getHeader("X-CSRF-Token"))
        }
    }
}
