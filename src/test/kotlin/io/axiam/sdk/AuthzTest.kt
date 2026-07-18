package io.axiam.sdk

import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthzTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `checkAccess allowed`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true,"reason":null}"""))
        TestSupport.clientFor(server).use { client ->
            val result = client.checkAccess("read", "r-1")
            assertTrue(result.allowed)
        }
        val recorded = server.takeRequest()
        assertEquals("/api/v1/authz/check", recorded.path)
        assertEquals("acme", recorded.getHeader("X-Tenant-ID"))
    }

    @Test
    fun `checkAccess denied with reason`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":false,"reason":"no grant"}"""))
        TestSupport.clientFor(server).use { client ->
            val result = client.checkAccess("delete", "r-1", "field")
            assertFalse(result.allowed)
            assertEquals("no grant", result.reason)
        }
        val recorded = server.takeRequest()
        assertTrue(recorded.body.readUtf8().contains("\"scope\":\"field\""))
    }

    @Test
    fun `can returns the boolean decision`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        TestSupport.clientFor(server).use { client ->
            assertTrue(client.can("read", "r-1"))
        }
    }

    @Test
    fun `checkAccess with explicit subject sends subject_id`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        TestSupport.clientFor(server).use { client ->
            client.checkAccess("user-9", "read", "r-1", null)
        }
        val recorded = server.takeRequest()
        assertTrue(recorded.body.readUtf8().contains("\"subject_id\":\"user-9\""))
    }

    @Test
    fun `batchCheck preserves order`() = runBlocking {
        server.enqueue(
            TestSupport.json(
                200,
                """{"results":[{"allowed":true},{"allowed":false,"reason":"x"},{"allowed":true}]}""",
            ),
        )
        TestSupport.clientFor(server).use { client ->
            val results = client.batchCheck(
                listOf(
                    AccessCheck("read", "a"),
                    AccessCheck("write", "b"),
                    AccessCheck("read", "c", "s"),
                ),
            )
            assertEquals(3, results.size)
            assertTrue(results[0].allowed)
            assertFalse(results[1].allowed)
            assertEquals("x", results[1].reason)
            assertTrue(results[2].allowed)
        }
        val recorded = server.takeRequest()
        assertEquals("/api/v1/authz/check/batch", recorded.path)
    }

    @Test
    fun `403 maps to AuthzError with action and resource id from the body`() {
        server.enqueue(
            MockResponse().setResponseCode(403)
                .setBody("""{"error":"authorization_denied","action":"documents:delete","resource_id":"r-9"}"""),
        )
        TestSupport.clientFor(server).use { client ->
            val ex = assertThrows(AuthzError::class.java) {
                runBlocking { client.checkAccess("documents:delete", "r-9") }
            }
            assertEquals("documents:delete", ex.action)
            assertEquals("r-9", ex.resourceId)
        }
    }

    @Test
    fun `409 maps to AuthzError`() {
        server.enqueue(MockResponse().setResponseCode(409).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthzError::class.java) {
                runBlocking { client.checkAccess("read", "r-1") }
            }
        }
    }

    @Test
    fun `500 maps to NetworkError and redacts non-allowlisted headers`() {
        server.enqueue(
            MockResponse().setResponseCode(500)
                .addHeader("X-Secret", "leak-me")
                .setBody("boom"),
        )
        TestSupport.clientFor(server).use { client ->
            val ex = assertThrows(NetworkError::class.java) {
                runBlocking { client.checkAccess("read", "r-1") }
            }
            assertFalse((ex.summary ?: "").contains("leak-me"))
            assertTrue((ex.summary ?: "").contains("[REDACTED]"))
        }
    }
}
