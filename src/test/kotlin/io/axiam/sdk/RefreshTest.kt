package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.RefreshGuard
import io.axiam.sdk.internal.TokenPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class RefreshTest {

    @Test
    fun `single-flight guard collapses concurrent refreshes to one`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val doRefresh: suspend () -> TokenPair = {
            calls.incrementAndGet()
            delay(150) // hold the flight open so waiters queue behind the leader
            TokenPair("new-access", "new-refresh", System.currentTimeMillis() + 60_000)
        }

        val results = (1..8).map {
            async(Dispatchers.IO) { guard.refreshIfNeeded("stale-access", doRefresh) }
        }.awaitAll()

        assertEquals(1, calls.get(), "exactly one refresh must run for N concurrent callers (§9)")
        assertTrue(results.all { it.access == "new-access" })
    }

    @Test
    fun `guard propagates refresh failure to every waiter with no retry`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val failing: suspend () -> TokenPair = {
            calls.incrementAndGet()
            delay(100)
            throw AuthError("refresh rejected")
        }

        val outcomes = (1..5).map {
            async(Dispatchers.IO) {
                runCatching { guard.refreshIfNeeded("stale-access", failing) }
            }
        }.awaitAll()

        assertEquals(1, calls.get(), "a failed refresh is not retried (§9.3)")
        assertTrue(outcomes.all { it.isFailure })
        assertTrue(outcomes.all { it.exceptionOrNull() is AuthError })
    }

    @Test
    fun `client reactively refreshes on 401 and retries exactly once`() = runBlocking {
        val server = MockWebServer()
        val refreshCount = AtomicInteger(0)
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path ?: ""
                return when {
                    path.startsWith("/api/v1/auth/login") -> TestSupport.loginOkResponse()
                    path.startsWith("/api/v1/auth/refresh") -> {
                        refreshCount.incrementAndGet()
                        Thread.sleep(120) // keep the single flight open for concurrent waiters
                        MockResponse().setResponseCode(200)
                            .addHeader("Set-Cookie", "axiam_access=${TestSupport.fakeJwt(jti = "s2")}; Path=/")
                            .addHeader("Set-Cookie", "axiam_refresh=r2; Path=/")
                            .setBody("{}")
                    }
                    path.startsWith("/api/v1/authz/check") ->
                        if (refreshCount.get() == 0) {
                            MockResponse().setResponseCode(401).setBody("{}")
                        } else {
                            TestSupport.json(200, """{"allowed":true}""")
                        }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()

        TestSupport.clientFor(server).use { client ->
            client.login("alice@example.com", "pw")
            val results = (1..6).map {
                async(Dispatchers.IO) { client.checkAccess("read", "r-$it") }
            }.awaitAll()
            assertTrue(results.all { it.allowed })
        }
        assertEquals(1, refreshCount.get(), "concurrent 401s trigger exactly one refresh (§9)")
        server.shutdown()
    }

    @Test
    fun `refresh without a session throws AuthError`() {
        val server = MockWebServer()
        server.start()
        assertThrows(AuthError::class.java) {
            runBlocking { TestSupport.clientFor(server).use { it.refresh() } }
        }
        server.shutdown()
    }

    @Test
    fun `a caller observing an already-stale token gets the cached pair without a new refresh`() = runBlocking {
        val guard = RefreshGuard()
        val calls = AtomicInteger(0)
        val doRefresh: suspend () -> TokenPair = {
            calls.incrementAndGet()
            TokenPair("second-access", "second-refresh", System.currentTimeMillis() + 60_000)
        }

        // First round: establishes `current`.
        val first = guard.refreshIfNeeded("first-access", doRefresh)
        assertEquals("second-access", first.access)
        assertEquals("second-access", guard.cachedAccessToken())

        // Second round: this caller still observed the now-superseded
        // "first-access" token — the double-check in refreshIfNeeded must
        // return the already-current pair WITHOUT invoking doRefresh again.
        val second = guard.refreshIfNeeded("first-access", doRefresh)
        assertEquals("second-access", second.access)
        assertEquals(1, calls.get(), "a caller behind the current token must not trigger another refresh")
    }
}
