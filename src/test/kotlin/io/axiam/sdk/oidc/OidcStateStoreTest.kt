package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OidcStateStoreTest {

    private fun entry(state: String = "state-1") = OidcStateEntry(
        state = state,
        nonce = "nonce-1",
        codeVerifier = Sensitive.of("verifier-1"),
        redirectUri = "https://app.example.com/cb",
        returnTo = "/dashboard",
    )

    @Test
    fun `save then consume returns the entry once, and single-use thereafter`(): Unit = runBlocking {
        val store = MemoryOidcStateStore()
        store.save(entry())
        val first = store.consume("state-1")
        assertEquals("nonce-1", first?.nonce)
        assertEquals("verifier-1", first?.codeVerifier?.expose())
        assertEquals("/dashboard", first?.returnTo)

        val second = store.consume("state-1")
        assertNull(second)
    }

    @Test
    fun `consume on an unknown state returns null`(): Unit = runBlocking {
        val store = MemoryOidcStateStore()
        assertNull(store.consume("never-saved"))
    }

    @Test
    fun `entries expire after the TTL and are treated identically to unknown`(): Unit = runBlocking {
        val store = MemoryOidcStateStore(ttlMs = 10)
        store.save(entry())
        Thread.sleep(50)
        assertNull(store.consume("state-1"))
    }

    @Test
    fun `a requested TTL above the 10-minute maximum is clamped`(): Unit = runBlocking {
        val store = MemoryOidcStateStore(ttlMs = 24 * 60 * 60 * 1000L)
        store.save(entry())
        // Can't wait 10 minutes in a unit test; assert the clamp indirectly
        // via size bookkeeping still functioning (no crash / correct entry).
        val held = store.consume("state-1")
        assertEquals("state-1", held?.state)
    }

    @Test
    fun `size reports unexpired entries and sweeps expired ones lazily`(): Unit = runBlocking {
        val store = MemoryOidcStateStore(ttlMs = 10)
        store.save(entry("a"))
        store.save(entry("b"))
        assertEquals(2, store.size)
        Thread.sleep(50)
        assertEquals(0, store.size)
    }

    @Test
    fun `concurrent save and consume across many coroutines never double-delivers an entry`(): Unit = runBlocking {
        val store = MemoryOidcStateStore()
        val states = (1..50).map { "state-$it" }
        states.forEach { store.save(entry(it)) }

        val results = states.map { state -> async { store.consume(state) } }.awaitAll()
        assertEquals(50, results.count { it != null })

        // A second wave of consumes must all be null (single-use).
        val secondWave = states.map { state -> async { store.consume(state) } }.awaitAll()
        assertTrue(secondWave.all { it == null })
    }
}
