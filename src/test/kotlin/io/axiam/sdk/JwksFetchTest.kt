package io.axiam.sdk

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import io.axiam.sdk.errors.AuthError
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * CONTRACT.md §12.4 rule 2: the fetch's concurrency (never under the lock, single-flight, bounded by
 * its own deadline, detached from the caller) and the real HTTP transport's success rules.
 */
class JwksFetchTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks
    private val t0 = 1_000_000_000_000L
    private val now = AtomicLong(t0)
    private val s = 1_000_000_000L
    private val ttl = 300 * s

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    private fun at(offset: Long) = now.set(t0 + offset)

    private fun validBody() = JWKSet(listOf(key.toPublicJWK())).toString()

    private fun v(c: AxiamClient, token: String) =
        try {
            c.verifySession(token)
        } finally {
            c.jwksVerifier().awaitIdleForTesting()
        }

    @Test
    fun `a stalled fetch does not delay a known-kid verification inside TTL plus 300 s`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            // The refresh will stall for seconds: a dripped body, far below the 6 s deadline's end.
            jwks.drip = true
            jwks.padBytes = 100_000
            c.jwksVerifier().fetchTotalTimeoutMs = 6_000
            at(ttl + 1 * s)
            val t1 = System.nanoTime()
            assertEquals("user-1", c.verifySession(known).userId) // starts the stalled refresh behind it
            val first = (System.nanoTime() - t1) / 1_000_000
            // wait until the refresh is really on the wire and still in flight
            val limit = System.nanoTime() + 3_000_000_000L
            while (jwks.fetches.get() < 2 && System.nanoTime() < limit) Thread.sleep(5)
            assertEquals(2, jwks.fetches.get(), "the refresh is in flight")
            val t2 = System.nanoTime()
            assertEquals("user-1", c.verifySession(known).userId)
            val second = (System.nanoTime() - t2) / 1_000_000
            assertTrue(first < 200 && second < 200, "known-kid calls must not wait for the fetch: $first ms, $second ms")
            c.jwksVerifier().awaitIdleForTesting() // the deadline ends it
            assertEquals(2, jwks.fetches.get())
        }
    }

    @Test
    fun `concurrent callers on a cold cache cause one fetch`() {
        jwks.headersDelayMs = 150
        jwks.client().use { c ->
            val pool = Executors.newFixedThreadPool(8)
            try {
                val go = CountDownLatch(1)
                val token = AccessTokenFixtures.mint(key)
                val futures = (1..8).map { pool.submit<String> { go.await(); c.verifySession(token).userId } }
                go.countDown()
                futures.forEach { assertEquals("user-1", it.get()) }
                assertEquals(1, jwks.fetches.get())
            } finally {
                pool.shutdownNow()
            }
        }
    }

    @Test
    fun `an interrupted caller records no failure and the window is stamped by the fetch's completion`() {
        jwks.status = 500
        jwks.headersDelayMs = 300
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val token = AccessTokenFixtures.mint(key)
            val outcome = AtomicReference<Throwable?>()
            val started = CountDownLatch(1)
            val t = Thread {
                started.countDown()
                try {
                    c.verifySession(token)
                } catch (e: Throwable) {
                    outcome.set(e)
                }
            }
            t.start()
            started.await()
            val limit = System.nanoTime() + 3_000_000_000L
            while (jwks.fetches.get() < 1 && System.nanoTime() < limit) Thread.sleep(2)
            assertEquals(1, jwks.fetches.get(), "the fetch is on the wire")
            t.interrupt()
            t.join(5_000)
            assertTrue(outcome.get() is AuthError, "the interrupted caller is refused: ${outcome.get()}")
            // The fake clock moves while the fetch is still stalled (the endpoint answers after 300 ms):
            // only the fetch's own completion may stamp the window, at THIS instant.
            at(10 * s)
            c.jwksVerifier().awaitIdleForTesting()
            at(10 * s + 59 * s)
            assertThrows(AuthError::class.java) { v(c, token) }
            assertEquals(1, jwks.fetches.get(), "inside the window stamped at the fetch's completion: no fetch")
            at(10 * s + 61 * s)
            assertThrows(AuthError::class.java) { v(c, token) }
            assertEquals(2, jwks.fetches.get(), "past that window: one more fetch")
        }
    }

    @Test
    fun `a server dripping the response headers is abandoned at the deadline and a new fetch follows the window`() {
        val accepts = java.util.concurrent.atomic.AtomicInteger()
        val server = java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())
        val sockets = java.util.concurrent.CopyOnWriteArrayList<java.net.Socket>()
        val acceptor = Thread {
            try {
                while (true) {
                    val sock = server.accept()
                    sockets.add(sock)
                    accepts.incrementAndGet()
                    Thread {
                        try {
                            sock.getInputStream().read(ByteArray(4096)) // the request
                            val out = sock.getOutputStream()
                            out.write("HTTP/1.1 200 OK\r\nX-Drip: ".toByteArray())
                            out.flush()
                            repeat(600) {
                                out.write('a'.code)
                                out.flush()
                                Thread.sleep(100)
                            }
                        } catch (_: Exception) {
                            // the client closed
                        }
                    }.apply { isDaemon = true }.start()
                }
            } catch (_: Exception) {
                // server closed
            }
        }.apply { isDaemon = true }
        acceptor.start()
        try {
            io.axiam.sdk.AxiamClient.builder("http://127.0.0.1:${server.localPort}/", TestSupport.TENANT_ID)
                .orgId(TestSupport.ORG_ID)
                .build().use { c ->
                    c.jwksVerifier().setClockForTesting { now.get() }
                    c.jwksVerifier().fetchTotalTimeoutMs = 1_000
                    val token = AccessTokenFixtures.mint(key)
                    val started = System.nanoTime()
                    assertThrows(AuthError::class.java) { c.verifySession(token) }
                    val ms = (System.nanoTime() - started) / 1_000_000
                    assertTrue(ms < 3_500, "the header-dripping fetch must be abandoned near its 1 s deadline, took $ms ms")
                    c.jwksVerifier().awaitIdleForTesting()
                    assertEquals(1, accepts.get())
                    // Inside the window: no new fetch. Past it: the in-flight slot is free, a new fetch is made.
                    at(10 * s)
                    assertThrows(AuthError::class.java) { c.verifySession(token) }
                    assertEquals(1, accepts.get())
                    at(61 * s + 10 * s)
                    assertThrows(AuthError::class.java) { c.verifySession(token) }
                    assertEquals(2, accepts.get())
                }
        } finally {
            sockets.forEach { runCatching { it.close() } }
            server.close()
        }
    }

    @Test
    fun `a drip-feeding endpoint is abandoned at the total timeout`() {
        jwks.drip = true
        jwks.padBytes = 100_000
        jwks.client().use { c ->
            c.jwksVerifier().fetchTotalTimeoutMs = 800
            val started = System.nanoTime()
            assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
            val ms = (System.nanoTime() - started) / 1_000_000
            assertTrue(ms < 4_000, "the fetch must be abandoned near its 800 ms deadline, took $ms ms")
            c.jwksVerifier().awaitIdleForTesting()
            // the abandoned fetch is a failure that opened the cooldown: no second fetch
            assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
            assertEquals(1, jwks.fetches.get())
        }
    }

    @Test
    fun `a 203 with a valid body is a failed refresh`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            jwks.status = 203
            jwks.rawBody = validBody()
            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())
            at(ttl + 301 * s) // the 203 did not move the anchor
            assertThrows(AuthError::class.java) { v(c, known) }
        }
    }

    @Test
    fun `a 304 to an unconditional request is a failure`() {
        jwks.status = 304
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            assertThrows(AuthError::class.java) { v(c, AccessTokenFixtures.mint(key)) }
            assertEquals(1, jwks.fetches.get())
        }
    }

    @Test
    fun `a 304 carrying max-age takes the new TTL`() {
        jwks.etag = "\"v1\""
        jwks.honour304 = true
        jwks.cacheControl304 = "max-age=60"
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId) // the 304: TTL is now 60 s, anchor ttl+1
            assertEquals(2, jwks.fetches.get())
            assertEquals(listOf("\"v1\""), jwks.ifNoneMatches.toList())
            at(ttl + 1 * s + 30 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get(), "inside the 304's 60 s TTL: no fetch")
            at(ttl + 1 * s + 61 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(3, jwks.fetches.get(), "past the 304's 60 s TTL a refresh is due")
        }
    }

    @Test
    fun `a body over the size limit is a failure and one of exactly the limit is accepted`() {
        val limit = RemoteJWKSet.resolveDefaultHTTPSizeLimit()
        val base = validBody().toByteArray().size
        jwks.padBytes = limit - base + 1
        jwks.client().use { c ->
            assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
        }
        val exact = AccessTokenFixtures.Jwks(key)
        try {
            exact.padBytes = limit - base
            exact.client().use { c ->
                assertEquals("user-1", c.verifySession(AccessTokenFixtures.mint(key)).userId)
            }
        } finally {
            exact.shutdown()
        }
    }

    @Test
    fun `a redirect is not followed`() {
        jwks.status = 302
        jwks.rawBody = validBody()
        jwks.location = "/oauth2/jwks?next"
        jwks.client().use { c ->
            assertThrows(AuthError::class.java) { v(c, AccessTokenFixtures.mint(key)) }
            assertEquals(1, jwks.fetches.get())
        }
    }

    @Test
    fun `an oversized ETag is not echoed in If-None-Match`() {
        jwks.etag = "\"" + "a".repeat(300) + "\""
        jwks.honour304 = true
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())
            assertTrue(jwks.ifNoneMatches.isEmpty(), "a >256-byte ETag must not be echoed")
        }
    }

    @Test
    fun `max-age 0 never means one fetch per verification`() {
        jwks.cacheControl = "max-age=0"
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            for (i in 0 until 20) assertEquals("user-1", v(c, known).userId)
            assertEquals(1, jwks.fetches.get(), "a TTL-driven refresh respects the 60 s window")
            at(61 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())
            for (i in 0 until 20) assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())
        }
    }
}
