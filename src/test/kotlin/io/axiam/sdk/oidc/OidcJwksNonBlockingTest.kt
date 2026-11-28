package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * #108: the suspend OIDC verifiers wait on the JWKS fetch (cold cache), which must not park the caller's
 * dispatcher thread. The JWKS endpoint stalls; a second coroutine on the SAME single thread must keep running.
 */
class OidcJwksNonBlockingTest {

    // The fetch's read timeout is 250 ms, so the stall is a slow body (20 bytes per 100 ms), not a late header.
    private val stallMs = 800L
    private lateinit var server: MockWebServer
    private lateinit var signing: com.nimbusds.jose.jwk.OctetKeyPair
    private val executor = Executors.newSingleThreadExecutor()
    private val single: CoroutineDispatcher = executor.asCoroutineDispatcher()

    @BeforeEach
    fun setUp() {
        signing = OidcTestKit.generateSigningKey("k1")
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path?.substringBefore('?') ?: ""
                return when (path) {
                    "/.well-known/openid-configuration" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(OidcTestKit.discoveryJson(server.url("/").toString()))
                    "/oauth2/jwks" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(OidcTestKit.jwksJson(signing.toPublicJWK()))
                        .throttleBody(20, 100, TimeUnit.MILLISECONDS)
                    "/oauth2/token" -> MockResponse().setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(
                            OidcTestKit.tokenResponseJson(
                                idToken = OidcTestKit.signIdToken(signing, server.url("/").toString().trimEnd('/'), nonce = null),
                            ),
                        )
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        executor.shutdownNow()
    }

    private fun client(): AxiamClient = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)

    /**
     * Runs [call] on [single] next to a ticker on the same thread (25 ms steps for 2 s) and returns the longest
     * gap between two ticks: a parked thread shows up as a gap as long as the stall.
     */
    private fun longestTickGapWhile(call: suspend () -> Unit): Long = runBlocking(single) {
        // The ticker is started first so it is already ticking when the call begins.
        val ticker = async {
            var last = System.nanoTime()
            var longest = 0L
            repeat(80) {
                delay(25)
                val now = System.nanoTime()
                longest = maxOf(longest, (now - last) / 1_000_000)
                last = now
            }
            longest
        }
        val work = async { call() }
        val gap = ticker.await()
        work.await()
        gap
    }

    @Test
    fun `verifyLogoutToken does not park the caller's dispatcher thread on the JWKS fetch`() {
        val client = client()
        val issuer = server.url("/").toString().trimEnd('/')
        val token = OidcTestKit.signLogoutToken(signing, issuer)
        runBlocking { client.oidcDiscover() } // warm: only the JWKS fetch remains
        val gap = longestTickGapWhile {
            assertEquals(OidcTestKit.LOGOUT_SID, client.verifyLogoutToken(token).sid)
        }
        assertTrue(gap < 400, "a coroutine on the same thread was held for $gap ms")
    }

    @Test
    fun `an ID token in a token response does not park the caller's dispatcher thread on the JWKS fetch`() {
        val client = client()
        runBlocking { client.oidcDiscover() } // warm: only the token call and the JWKS fetch remain
        val gap = longestTickGapWhile {
            val tokens = client.loginClientCredentials(
                LoginClientCredentialsParams(tenantId = "22222222-2222-2222-2222-222222222222"),
            )
            assertEquals("user-1", tokens.idClaims?.sub)
        }
        assertTrue(gap < 400, "a coroutine on the same thread was held for $gap ms")
    }

    @Test
    fun `a caller cancelled during the JWKS wait sees a cancellation, not a verification failure`() {
        val client = client()
        val token = OidcTestKit.signLogoutToken(signing, server.url("/").toString().trimEnd('/'))
        runBlocking { client.oidcDiscover() }
        val outcome = runBlocking {
            val job = async(Dispatchers.Default) { client.verifyLogoutToken(token) }
            delay(100) // inside the stalled fetch
            job.cancel()
            runCatching { job.await() }.exceptionOrNull()
        }
        assertTrue(outcome is CancellationException, "expected a cancellation, got $outcome")
    }
}
