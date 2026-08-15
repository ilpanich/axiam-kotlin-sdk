package io.axiam.sdk.reactor

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID
import kotlin.time.Duration.Companion.seconds

/**
 * The edges of the §22 primitives: a body that is not a body, a signature that
 * is not a signature, the nonce store's bound, and the small accessors the happy
 * path never reaches.
 *
 * [ReactorVectorTest] proves the protocol produces the *right* bytes against the
 * server's own vectors. This class proves it refuses the wrong ones without
 * throwing into a delivery loop — every predicate below has to answer `false`
 * rather than blow up, because a verifier that throws on a malformed body is a
 * verifier an attacker can use to kill the consumer.
 */
class ReactorEdgeCaseTest {

    private val key = ByteArray(32) { it.toByte() }
    private val tenant: UUID = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val correlation: UUID = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val nonce: UUID = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    private val issuedAt: Instant = Instant.parse("2026-07-10T12:00:00Z")

    // ---- canonicalization --------------------------------------------------

    @Test
    fun `canonicalEventBytes rewrites the signature to null in place`() {
        val signed = ReactorProtocol.signedReply(
            key, correlation, tenant, ReactorEvents.LOGIN_POST_AUTH,
            ReactorDecision.allow(), nonce, issuedAt,
        )
        assertTrue(signed.decodeToString().contains("\"hmac_signature\":\""))

        val canonical = ReactorProtocol.canonicalEventBytes(signed).decodeToString()
        assertTrue(
            canonical.endsWith("\"hmac_signature\":null}"),
            "the field keeps its position and its key — only the value becomes null: $canonical",
        )
        assertEquals(
            ReactorProtocol.canonicalReplyBytes(
                correlation, tenant, ReactorEvents.LOGIN_POST_AUTH,
                ReactorDecision.allow(), nonce, issuedAt,
            ).decodeToString(),
            canonical,
            "re-canonicalizing a signed body reproduces exactly the bytes that were signed",
        )
    }

    @Test
    fun `a body that is not a JSON object is refused rather than canonicalized`() {
        assertThrows(IllegalArgumentException::class.java) {
            ReactorProtocol.canonicalEventBytes("[1,2,3]".toByteArray())
        }
        assertThrows(IllegalArgumentException::class.java) {
            ReactorProtocol.canonicalEventBytes("not json at all".toByteArray())
        }
    }

    // ---- verification answers false; it never throws -----------------------

    @Test
    fun `every malformed body fails verification rather than throwing`() {
        val cases = mapOf(
            "not JSON" to "}{".toByteArray(),
            "a JSON array" to "[]".toByteArray(),
            "empty" to ByteArray(0),
            "no signature field" to """{"key_version":2}""".toByteArray(),
            "a null signature" to """{"key_version":2,"hmac_signature":null}""".toByteArray(),
            "a numeric signature" to """{"key_version":2,"hmac_signature":7}""".toByteArray(),
            "an odd-length hex signature" to """{"key_version":2,"hmac_signature":"abc"}""".toByteArray(),
            "a non-hex signature" to """{"key_version":2,"hmac_signature":"zzzz"}""".toByteArray(),
            "a short but valid hex signature" to """{"key_version":2,"hmac_signature":"ab"}""".toByteArray(),
        )
        for ((name, body) in cases) {
            assertFalse(
                ReactorProtocol.verifyEvent(key, body),
                "$name must verify as false — there is no accept-when-absent path",
            )
        }
    }

    @Test
    fun `an unusable signing key fails loudly rather than signing with something else`() {
        assertThrows(IllegalArgumentException::class.java) {
            ReactorProtocol.signedReply(
                ByteArray(0), correlation, tenant, ReactorEvents.LOGIN_POST_AUTH,
                ReactorDecision.allow(), nonce, issuedAt,
            )
        }
    }

    // ---- patch key ordering ------------------------------------------------

    @Test
    fun `patch keys are ordered by UTF-8 bytes, including the prefix case`() {
        val body = ReactorProtocol.canonicalReplyBytes(
            correlation, tenant, ReactorEvents.TOKEN_PRE_ISSUE,
            // "ext.a" is a strict prefix of "ext.ab": equal on every shared byte,
            // so the comparator has to fall through to the length difference.
            ReactorDecision.mutate(
                linkedMapOf("ext.b" to "3", "ext.ab" to "2", "ext.a" to "1"),
            ),
            nonce, issuedAt,
        ).decodeToString()

        assertTrue(
            body.contains("""{"ext.a":"1","ext.ab":"2","ext.b":"3"}"""),
            "the server's patch is a BTreeMap, so its order is UTF-8 byte order: $body",
        )
    }

    // ---- the field readers -------------------------------------------------

    @Test
    fun `the field readers refuse a value of the wrong JSON type`() {
        val obj: JsonObject = buildJsonObject {
            put("text", JsonPrimitive("hello"))
            put("number", JsonPrimitive(42))
            put("numeric_text", JsonPrimitive("42"))
            put("nothing", JsonNull)
            put("nested", buildJsonObject { })
        }

        assertEquals("hello", ReactorProtocol.stringField(obj, "text"))
        assertNull(ReactorProtocol.stringField(obj, "number"), "a number is not a string field")
        assertNull(ReactorProtocol.stringField(obj, "nothing"))
        assertNull(ReactorProtocol.stringField(obj, "nested"))
        assertNull(ReactorProtocol.stringField(obj, "absent"))

        assertEquals(42, ReactorProtocol.intField(obj, "number"))
        assertNull(
            ReactorProtocol.intField(obj, "numeric_text"),
            "\"42\" is a quoted string on the wire; reading it as an int would accept a body the server signs differently",
        )
        assertNull(ReactorProtocol.intField(obj, "text"))
        assertNull(ReactorProtocol.intField(obj, "nested"))
        assertNull(ReactorProtocol.intField(obj, "absent"))

        assertNull(ReactorProtocol.parseUuid(null))
        assertNull(ReactorProtocol.parseUuid("not-a-uuid"))
        assertEquals(tenant, ReactorProtocol.parseUuid(tenant.toString()))
    }

    // ---- the nonce store ---------------------------------------------------

    @Test
    fun `the nonce store rejects a replay inside the window and forgets it after`() {
        val store = ReactorNonceStore(10.seconds)
        val now = issuedAt

        assertTrue(store.observe("n1", now), "first sighting")
        assertFalse(store.observe("n1", now), "second sighting inside the window is a replay")
        assertEquals(1, store.size())
        assertTrue(
            store.observe("n1", now.plusSeconds(11)),
            "past the TTL the nonce is no longer replay-rejecting — its issued_at can no longer pass freshness either",
        )
    }

    @Test
    fun `the nonce store is bounded and prunes expired entries when it fills`() {
        val store = ReactorNonceStore(1.seconds, maxTrackedNonces = 2)
        val now = issuedAt

        store.observe("a", now)
        store.observe("b", now)
        assertEquals(2, store.size())

        // At capacity and past the TTL: the next observe prunes rather than
        // growing without bound under a flood of distinct nonces.
        assertTrue(store.observe("c", now.plusSeconds(5)))
        assertTrue(store.size() <= 2, "the bound is enforced, not merely documented")
    }

    @Test
    fun `the nonce store refuses a non-positive TTL or bound`() {
        assertThrows(IllegalArgumentException::class.java) { ReactorNonceStore(0.seconds) }
        assertThrows(IllegalArgumentException::class.java) { ReactorNonceStore((-1).seconds) }
        assertThrows(IllegalArgumentException::class.java) {
            ReactorNonceStore(1.seconds, maxTrackedNonces = 0)
        }
    }

    // ---- the registry's small accessors ------------------------------------

    @Test
    fun `an unknown or absent failure policy wire form reads as null rather than a default`() {
        assertNull(FailurePolicy.fromWire(null))
        assertNull(FailurePolicy.fromWire("fail_sideways"))
        assertNull(FailurePolicy.fromWire(""))
        assertEquals(FailurePolicy.FAIL_CLOSED, FailurePolicy.fromWire("  FAIL_CLOSED  "))
    }

    @Test
    fun `an unknown event has no spec and contributes no failure-policy default`() {
        assertNull(ReactorEvents.spec(null))
        assertNull(ReactorEvents.spec("authz.check"))
        assertEquals(
            FailurePolicy.FAIL_OPEN,
            ReactorEvents.defaultFailurePolicyFor(listOf("authz.check")),
            "an event the server would refuse at registration must not be guessed a policy for",
        )
        assertEquals(FailurePolicy.FAIL_OPEN, ReactorEvents.defaultFailurePolicyFor(emptyList()))
    }
}
