package io.axiam.sdk

import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlinx.coroutines.runBlocking

/** Direct [ErrorMapper] edges not reachable through a normal 403-with-JSON-body call. */
class ErrorMapperTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `fromHttpStatus with a 403 and a null response yields a bare AuthzError`() {
        val error = ErrorMapper.fromHttpStatus(403, "denied", null)
        assertEquals(true, error is AuthzError)
        error as AuthzError
        assertNull(error.action)
        assertNull(error.resourceId)
    }

    @Test
    fun `fromHttpStatus with a 409 and a blank body yields a bare AuthzError`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(409).setBody(""))
        TestSupport.clientFor(server).use { client ->
            try {
                client.checkAccess("write", "r-1")
                error("expected AuthzError")
            } catch (e: AuthzError) {
                assertNull(e.action)
                assertNull(e.resourceId)
            }
        }
    }

    @Test
    fun `NetworkError single-arg constructor carries no summary or cause`() {
        val e = NetworkError("boom")
        assertEquals("boom", e.message)
        assertNull(e.summary)
        assertNull(e.cause)
    }
}
