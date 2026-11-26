package io.axiam.sdk

import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.JwksVerifier
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong

/**
 * CONTRACT.md §12.4 rule 2, "Conformance test for the window" (contract 1.68; C5).
 *
 * One re-fetch per cooldown window, not per token. nimbus's
 * `DefaultJWKSetCache` refetches on every `kid` miss, so the window is kept by
 * [JwksVerifier] itself; its clock is injected here and held still, never slept.
 */
class JwksUnknownKidCooldownTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks
    private val now = AtomicLong(1_000_000_000_000L)

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    @Test
    fun `fifty unknown kids in one window cause at most one JWKS fetch`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            // Warm the cache with one token carrying the served kid.
            assertEquals("user-1", c.verifySession(AccessTokenFixtures.mint(key)).userId)
            val warm = jwks.fetches.get()
            assertEquals(1, warm)

            for (i in 0 until 50) {
                val forged = AccessTokenFixtures.mint(key, kid = "forged-$i")
                assertThrows(AuthError::class.java) { c.verifySession(forged) }
            }
            val duringBurst = jwks.fetches.get() - warm
            assertTrue(duringBurst <= 1, "50 unknown kids must cause at most one JWKS fetch, saw $duringBurst")
        }
    }

    @Test
    fun `a rotated key is accepted after one fetch once the window has passed`() {
        val rotated = AccessTokenFixtures.newKey("key-2")
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            assertEquals("user-1", c.verifySession(AccessTokenFixtures.mint(key)).userId)

            jwks.published.set(listOf(rotated))
            val token = AccessTokenFixtures.mint(rotated, kid = "key-2")

            // Inside the window: refused, and no fetch.
            val before = jwks.fetches.get()
            assertThrows(AuthError::class.java) { c.verifySession(token) }
            assertEquals(before, jwks.fetches.get(), "no JWKS fetch inside the cooldown window")

            // Past the window: one fetch picks the new key up. "Never re-fetch" would fail here.
            now.addAndGet(JwksVerifier.UNKNOWN_KID_COOLDOWN_NANOS + 1)
            assertEquals("user-1", c.verifySession(token).userId)
            assertEquals(before + 1, jwks.fetches.get())
        }
    }

    @Test
    fun `a cold cache and an unknown kid cause one fetch, not a load plus a miss fetch`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            val forged = AccessTokenFixtures.mint(key, kid = "forged")
            assertThrows(AuthError::class.java) { c.verifySession(forged) }
            assertEquals(1, jwks.fetches.get(), "a cold cache and a forged kid must cost one JWKS fetch")
            // And the window holds from there.
            for (i in 0 until 49) {
                assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key, kid = "forged-$i")) }
            }
            assertEquals(1, jwks.fetches.get())
        }
    }

    @Test
    fun `the first unknown kid after the window costs exactly one fetch`() {
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            assertEquals("user-1", c.verifySession(AccessTokenFixtures.mint(key)).userId)
            val warm = jwks.fetches.get()
            now.addAndGet(JwksVerifier.UNKNOWN_KID_COOLDOWN_NANOS + 1)
            assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key, kid = "forged")) }
            assertEquals(warm + 1, jwks.fetches.get(), "one fetch for the first miss after the window")
            for (i in 0 until 49) {
                assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key, kid = "forged-$i")) }
            }
            assertEquals(warm + 1, jwks.fetches.get())
        }
    }

    @Test
    fun `fifty tokens against a failing JWKS endpoint cause at most one fetch per window`() {
        jwks.status = 500
        jwks.client().use { c ->
            c.jwksVerifier().setClockForTesting { now.get() }
            for (i in 0 until 50) {
                assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
            }
            assertEquals(1, jwks.fetches.get(), "a failing endpoint is fetched once per window, not once per token")

            // The endpoint recovers: after the window one fetch brings the key in.
            jwks.status = 200
            now.addAndGet(JwksVerifier.UNKNOWN_KID_COOLDOWN_NANOS + 1)
            assertEquals("user-1", c.verifySession(AccessTokenFixtures.mint(key)).userId)
            assertEquals(2, jwks.fetches.get())
        }
    }
}
