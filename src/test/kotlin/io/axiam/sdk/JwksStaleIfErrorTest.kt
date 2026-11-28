package io.axiam.sdk

import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.errors.AuthError
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong

/**
 * CONTRACT.md §12.4 rule 2, "Stale-if-error, bounded" (contract 1.69; D-10) — the conformance test,
 * with an injected clock that is never slept.
 */
class JwksStaleIfErrorTest {

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

    @Test
    fun `conformance - failing refresh, bound at TTL plus 300 s, recovery after one fetch`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(1, jwks.fetches.get())

            jwks.status = 500
            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get(), "one failed refresh is attempted")

            at(ttl + 250 * s)
            assertThrows(AuthError::class.java) { v(c, AccessTokenFixtures.mint(key, kid = "unknown")) }
            assertEquals("user-1", v(c, known).userId, "the held kid is still accepted")

            at(ttl + 301 * s)
            assertThrows(AuthError::class.java) { v(c, known) }

            jwks.status = 200
            at(ttl + 400 * s)
            val before = jwks.fetches.get()
            assertEquals("user-1", v(c, known).userId)
            assertEquals(before + 1, jwks.fetches.get(), "accepted again after one successful fetch")
        }
    }

    @Test
    fun `an empty key set is a failed refresh - the held kid is still accepted`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)

            jwks.emptyKeys = true
            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())

            // The empty answer never moved the anchor: the bound still runs from t0.
            at(ttl + 301 * s)
            assertThrows(AuthError::class.java) { v(c, known) }
        }
    }

    @Test
    fun `a failed unknown-kid refresh neither opens nor extends the stale window`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)

            jwks.status = 500
            // Inside the TTL: an unknown kid (past the cooldown) fails its refresh, is refused,
            // and the held set is kept.
            at(100 * s)
            assertThrows(AuthError::class.java) { v(c, AccessTokenFixtures.mint(key, kid = "unknown")) }
            assertEquals(2, jwks.fetches.get())
            assertEquals("user-1", v(c, known).userId)
            // The bound is still t0 + TTL + 300 s, not 100 s later.
            at(ttl + 301 * s)
            assertThrows(AuthError::class.java) { v(c, known) }
        }
    }

    @Test
    fun `a 304 to the conditional request moves the anchor`() {
        jwks.etag = "\"v1\""
        jwks.honour304 = true
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)

            at(ttl + 1 * s)
            assertEquals("user-1", v(c, known).userId) // 304: anchor now t0 + TTL + 1
            assertEquals(2, jwks.fetches.get())

            jwks.status = 500
            at(ttl + 1 * s + ttl + 250 * s) // beyond the ORIGINAL bound, inside the moved one
            assertEquals("user-1", v(c, known).userId)
            at(ttl + 1 * s + ttl + 301 * s)
            assertThrows(AuthError::class.java) { v(c, known) }
        }
    }

    @Test
    fun `an advertised max-age above 300 s is clamped, a smaller one is honoured`() {
        jwks.cacheControl = "public, max-age=86400"
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            jwks.status = 500
            at(ttl + 1 * s) // refresh due at 300 s despite max-age=86400
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get())
            at(ttl + 301 * s) // and the bound is 600 s, not 86400 s + 300 s
            assertThrows(AuthError::class.java) { v(c, known) }
        }
        jwks.cacheControl = "max-age=60"
        jwks.status = 200
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            at(0)
            assertEquals("user-1", v(c, AccessTokenFixtures.mint(key)).userId)
            val n = jwks.fetches.get()
            at(61 * s)
            assertEquals("user-1", v(c, AccessTokenFixtures.mint(key)).userId)
            assertEquals(n + 1, jwks.fetches.get(), "max-age=60 is honoured: a refresh is due after 60 s")
        }
    }

    @Test
    fun `a keys array with no JWK object is a failed refresh like the empty set`() {
        for (body in listOf("{\"keys\":[{}]}", "{\"keys\":{}}", "{\"keys\":[0]}", "{\"keys\":[null]}", "[]", "not json")) {
            val j = AccessTokenFixtures.Jwks(key)
            try {
                j.client().use { c ->
                    c.jwksVerifier().setClockForTesting { now.get() }
                    at(0)
                    val known = AccessTokenFixtures.mint(key)
                    assertEquals("user-1", v(c, known).userId)
                    j.rawBody = body
                    at(ttl + 1 * s)
                    assertEquals("user-1", v(c, known).userId, "held kid kept for $body")
                    at(ttl + 301 * s)
                    assertThrows(AuthError::class.java) { v(c, known) }
                }
            } finally {
                j.shutdown()
            }
        }
    }

    @Test
    fun `a failing first fetch on a cold cache costs one fetch per window`() {
        jwks.status = 500
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            for (i in 0 until 20) {
                assertThrows(AuthError::class.java) { v(c, AccessTokenFixtures.mint(key)) }
            }
            assertEquals(1, jwks.fetches.get())
        }
    }

    @Test
    fun `a clock moving backwards makes a refresh due, never fresh`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            at(-10 * s)
            assertEquals("user-1", v(c, known).userId)
            assertEquals(2, jwks.fetches.get(), "negative age: a refresh, not a cache hit")
        }
    }

    @Test
    fun `a well-formed but unusable JWK still counts as a key and the usable ones are kept`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val pub = key.toPublicJWK().toJSONString()
            jwks.rawBody = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\"},$pub]}"
            assertEquals("user-1", v(c, AccessTokenFixtures.mint(key)).userId)
        }
    }

    @Test
    fun `a clock stepped back with a failing refresh does not trust the held keys`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val known = AccessTokenFixtures.mint(key)
            assertEquals("user-1", v(c, known).userId)
            jwks.status = 500
            at(-10 * s)
            assertThrows(AuthError::class.java) { v(c, known) }
        }
    }

    /** Verifies, then waits for any refresh the call started behind a usable held key to publish its outcome. */
    private fun v(c: AxiamClient, token: String) =
        try {
            c.verifySession(token)
        } finally {
            c.jwksVerifier().awaitIdleForTesting()
        }
}
