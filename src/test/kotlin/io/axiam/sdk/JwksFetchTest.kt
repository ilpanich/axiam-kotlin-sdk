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
            jwks.headersDelayMs = 3_000
            at(ttl + 1 * s)
            val started = System.nanoTime()
            assertEquals("user-1", c.verifySession(known).userId) // starts the stalled refresh behind it
            // a second known-kid call while the fetch is in flight is not blocked either
            assertEquals("user-1", c.verifySession(known).userId)
            val ms = (System.nanoTime() - started) / 1_000_000
            assertTrue(ms < 1_500, "a usable held key must not wait for the in-flight fetch, took $ms ms")
            c.jwksVerifier().awaitIdleForTesting()
            assertEquals(2, jwks.fetches.get())
        }
    }

    @Test
    fun `concurrent callers on a cold cache cause one fetch`() {
        jwks.headersDelayMs = 400
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
    fun `an interrupted caller records no failure and opens no cooldown`() {
        jwks.headersDelayMs = 150
        jwks.client().use { c ->
            val token = AccessTokenFixtures.mint(key)
            val outcome = AtomicReference<Throwable?>()
            val t = Thread {
                try {
                    c.verifySession(token)
                } catch (e: Throwable) {
                    outcome.set(e)
                }
            }
            t.start()
            Thread.sleep(40)
            t.interrupt()
            t.join(5_000)
            assertTrue(outcome.get() is AuthError, "the interrupted caller is refused: ${outcome.get()}")
            // The detached fetch is unaffected by the caller: it completes and publishes the set.
            c.jwksVerifier().awaitIdleForTesting()
            assertEquals("user-1", c.verifySession(token).userId)
            assertEquals(1, jwks.fetches.get(), "the caller's interrupt did not cost or repeat a fetch")
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
