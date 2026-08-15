package io.axiam.sdk.reactor

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID

/**
 * CONTRACT.md §22.13 conformance, against the server-generated vectors in
 * `reactor_v2_reference_vectors.json`.
 *
 * These are the tests the contract asks for by name, in its own order: sign
 * direction, verify direction, replay, and the topology strings. The
 * expectations are the fixture's — nothing here is hand-rolled, which is the
 * point of shipping vectors rather than a prose description of the
 * canonicalization.
 */
class ReactorVectorTest {

    private val verifiedAt: Instant = Instant.parse("2026-07-10T12:00:00Z")

    // ---- the key both directions sign with ---------------------------------

    /**
     * The §8 v2 HKDF derivation, checked against BOTH fixtures — which carry the
     * same master key, tenant and derived subkey precisely so this can be one
     * assertion rather than two implementations.
     */
    @Test
    fun `the tenant subkey derives from the master key exactly as the server derives it`() {
        val reactorFixture = ReactorVectors.load()
        val amqpFixture = ReactorVectors.load("/v2_reference_vectors.json")

        val derived = ReactorProtocol.deriveTenantKey(
            ReactorVectors.masterKey(reactorFixture),
            ReactorVectors.tenantId(reactorFixture),
        )
        assertEquals(
            ReactorVectors.toHex(ReactorVectors.subkey(reactorFixture)),
            ReactorVectors.toHex(derived),
        )
        assertEquals(
            ReactorVectors.toHex(ReactorVectors.subkey(amqpFixture)),
            ReactorVectors.toHex(derived),
            "§22.13: the §8 and §22 fixtures share a derived subkey, so one loader serves both",
        )

        val otherTenant = ReactorProtocol.deriveTenantKey(
            ReactorVectors.masterKey(reactorFixture),
            UUID.fromString("33333333-3333-3333-3333-333333333333"),
        )
        assertNotEquals(ReactorVectors.toHex(derived), ReactorVectors.toHex(otherTenant))
    }

    // ---- sign direction (reactor → server) ---------------------------------

    @Test
    fun `every committed reply reproduces its canonical bytes and its MAC`() {
        val root = ReactorVectors.load()
        val key = ReactorVectors.subkey(root)
        val tenant = ReactorVectors.tenantId(root)
        val correlation = ReactorVectors.correlationId(root)

        for (name in listOf("allow", "deny", "mutate", "require_mfa")) {
            val vector = root["reactor_to_server"]!!.jsonObject[name]!!.jsonObject
            val message = vector["message"]!!.jsonObject
            val event = ReactorVectors.text(message, "event")
            val nonce = UUID.fromString(ReactorVectors.text(message, "nonce"))
            val issuedAt = Instant.parse(ReactorVectors.text(message, "issued_at"))
            val decision = decisionOf(message)

            assertEquals(
                ReactorVectors.text(vector, "canonical_signed_json"),
                ReactorProtocol.canonicalReplyBytes(correlation, tenant, event, decision, nonce, issuedAt)
                    .decodeToString(),
                "$name: the reply this SDK builds must reproduce canonical_signed_json byte-for-byte, " +
                    "\"hmac_signature\": null placeholder included",
            )

            val signed = ReactorProtocol.signedReply(key, correlation, tenant, event, decision, nonce, issuedAt)
            assertEquals(
                ReactorVectors.text(vector, "hmac_signature_hex"),
                macOf(signed),
                "$name: recomputed MAC must equal the server's",
            )
            assertTrue(
                ReactorProtocol.verifyEvent(key, signed),
                "$name: a reply this SDK signed must verify under the same subkey",
            )
        }
    }

    /**
     * §22.2: the three conditionally-omitted fields are load-bearing. A reply
     * that serializes `"require_mfa": false` rather than omitting it produces
     * different canonical bytes and therefore a different MAC.
     */
    @Test
    fun `the omission rules are reproduced, not just the values`() {
        val root = ReactorVectors.load()
        val tenant = ReactorVectors.tenantId(root)
        val correlation = ReactorVectors.correlationId(root)
        val nonce = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

        val allow = ReactorProtocol.canonicalReplyBytes(
            correlation, tenant, ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(), nonce, verifiedAt,
        ).decodeToString()
        assertFalse(allow.contains("require_mfa"), "require_mfa MUST NOT be serialized when false")
        assertFalse(allow.contains("reason"), "reason MUST be omitted when absent")
        assertFalse(allow.contains("patch"), "patch MUST be omitted when absent")
        assertTrue(
            allow.endsWith("\"hmac_signature\":null}"),
            "the signed bytes carry hmac_signature present and null, not omitted",
        )

        val denyNoReason = ReactorProtocol.canonicalReplyBytes(
            correlation, tenant, ReactorEvents.GRANT_PRE_ASSIGN, ReactorDecision.deny(), nonce, verifiedAt,
        ).decodeToString()
        assertFalse(
            denyNoReason.contains("reason"),
            "a deny with no reason omits the field rather than sending null",
        )

        val stepUp = ReactorProtocol.canonicalReplyBytes(
            correlation, tenant, ReactorEvents.LOGIN_POST_AUTH,
            ReactorDecision.allowRequiringStepUp(), nonce, verifiedAt,
        ).decodeToString()
        assertTrue(stepUp.contains("\"require_mfa\":true"), "require_mfa IS serialized when true")
    }

    /**
     * §22.2: two replies differing in nothing but the nonce carry different MACs
     * — the nonce is inside the signed bytes, which is the only uniqueness a
     * reply body has beyond its timestamp.
     */
    @Test
    fun `the nonce is inside the signed bytes`() {
        val root = ReactorVectors.load()
        val binding = root["nonce_binding"]!!.jsonObject
        val key = ReactorVectors.subkey(root)
        val tenant = ReactorVectors.tenantId(root)
        val correlation = ReactorVectors.correlationId(root)

        val macA = macOf(
            ReactorProtocol.signedReply(
                key, correlation, tenant, ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(ReactorVectors.text(binding, "nonce_a")), verifiedAt,
            ),
        )
        val macB = macOf(
            ReactorProtocol.signedReply(
                key, correlation, tenant, ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(ReactorVectors.text(binding, "nonce_b")), verifiedAt,
            ),
        )

        assertEquals(ReactorVectors.text(binding, "hmac_a_hex"), macA)
        assertEquals(ReactorVectors.text(binding, "hmac_b_hex"), macB)
        assertNotEquals(macA, macB, "a nonce swap must change the MAC")
    }

    // ---- verify direction (server → reactor) -------------------------------

    @Test
    fun `every committed event verifies under the derived subkey and no other`() {
        val root = ReactorVectors.load()
        val key = ReactorVectors.subkey(root)
        val wrongKey = ByteArray(key.size)

        for (name in listOf("token_pre_issue", "login_post_auth")) {
            val body = ReactorVectors.wireBody(root["server_to_reactor"]!!.jsonObject[name]!!.jsonObject)
            assertTrue(ReactorProtocol.verifyEvent(key, body), "$name: must verify under the derived subkey")
            assertFalse(ReactorProtocol.verifyEvent(wrongKey, body), "$name: must NOT verify under any other key")
        }
    }

    @Test
    fun `tampering with any signed field invalidates the event`() {
        val root = ReactorVectors.load()
        val key = ReactorVectors.subkey(root)
        val vector = root["server_to_reactor"]!!.jsonObject["token_pre_issue"]!!.jsonObject
        val signed = ReactorVectors.withSignature(
            ReactorVectors.canonicalObject(vector),
            ReactorVectors.text(vector, "hmac_signature_hex"),
        )

        val payloadTampered = JsonObject(
            signed + ("payload" to JsonObject(mapOf("sub" to JsonPrimitive("root")))),
        )
        assertFalse(
            ReactorProtocol.verifyEvent(key, ReactorVectors.encode(payloadTampered)),
            "rewriting the payload must invalidate the event",
        )

        val stretched = JsonObject(signed + ("timeout_ms" to JsonPrimitive(60_000)))
        assertFalse(
            ReactorProtocol.verifyEvent(key, ReactorVectors.encode(stretched)),
            "widening the window an actor thinks it has is tampering too",
        )

        val crossTenant = JsonObject(
            signed + ("tenant_id" to JsonPrimitive("33333333-3333-3333-3333-333333333333")),
        )
        assertFalse(
            ReactorProtocol.verifyEvent(key, ReactorVectors.encode(crossTenant)),
            "re-aiming an event at another tenant must invalidate it",
        )

        val nonceSwapped = JsonObject(
            signed + ("nonce" to JsonPrimitive("dddddddd-dddd-dddd-dddd-dddddddddddd")),
        )
        assertFalse(
            ReactorProtocol.verifyEvent(key, ReactorVectors.encode(nonceSwapped)),
            "the nonce is inside the signed bytes",
        )
    }

    @Test
    fun `a stale or future timestamp is outside the window in both directions`() {
        val now = verifiedAt
        assertTrue(ReactorProtocol.isFresh(now, now))
        assertTrue(
            ReactorProtocol.isFresh(now.minusSeconds(300), now),
            "exactly ±300 s is inside the window",
        )
        assertFalse(ReactorProtocol.isFresh(now.minusSeconds(301), now), "stale")
        assertFalse(
            ReactorProtocol.isFresh(now.plusSeconds(301), now),
            "a future timestamp is not extra fresh — it is a captured message held for later",
        )
    }

    /**
     * The fixture's `stale` and `stale_future` reply vectors, checked against
     * their own `verified_at`: both carry a perfectly valid signature and are
     * still outside the window.
     */
    @Test
    fun `the committed stale vectors are refused on freshness, not on signature`() {
        val root = ReactorVectors.load()
        val key = ReactorVectors.subkey(root)
        val now = Instant.parse(ReactorVectors.text(root, "verified_at"))

        for (name in listOf("stale", "stale_future")) {
            val vector = root["rejected_replies"]!!.jsonObject[name]!!.jsonObject
            assertTrue(
                ReactorProtocol.verifyEvent(key, ReactorVectors.wireBody(vector)),
                "$name: the signature itself is valid — the refusal is a freshness one",
            )
            val issuedAt = Instant.parse(ReactorVectors.text(vector["message"]!!.jsonObject, "issued_at"))
            assertFalse(ReactorProtocol.isFresh(issuedAt, now), "$name: must be refused as stale")
        }
    }

    /**
     * §22.13 replay: the accepted reply verbatim — valid signature, inside the
     * window — is refused when presented against a different `correlation_id`,
     * and this SDK cannot re-aim it, because the correlation lives inside the
     * signed bytes.
     */
    @Test
    fun `a captured reply cannot be re-aimed at another correlation`() {
        val root = ReactorVectors.load()
        val vector = root["rejected_replies"]!!.jsonObject["correlation_replay"]!!.jsonObject
        val key = ReactorVectors.subkey(root)
        val tenant = ReactorVectors.tenantId(root)
        val message = vector["message"]!!.jsonObject

        val captured = UUID.fromString(ReactorVectors.text(message, "correlation_id"))
        val presentedAgainst = UUID.fromString(ReactorVectors.text(vector, "verify_against_correlation_id"))
        assertNotEquals(captured, presentedAgainst)
        assertEquals("wrong_correlation", ReactorVectors.text(vector, "expected_rejection"))

        assertTrue(
            ReactorProtocol.verifyEvent(key, ReactorVectors.wireBody(vector)),
            "the captured reply's signature is perfectly valid; the correlation is what refuses it",
        )

        val reAimed = macOf(
            ReactorProtocol.signedReply(
                key, presentedAgainst, tenant, ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(ReactorVectors.text(message, "nonce")), verifiedAt,
            ),
        )
        assertNotEquals(
            ReactorVectors.text(vector, "hmac_signature_hex"),
            reAimed,
            "changing the correlation changes the MAC — a captured reply cannot be re-aimed",
        )
    }

    // ---- topology (§22.1) --------------------------------------------------

    @Test
    fun `topology strings match the server's own`() {
        val root = ReactorVectors.load()
        val topology = root["topology"]!!.jsonObject
        val tenant = ReactorVectors.tenantId(root)
        val reactorId = UUID.fromString(ReactorVectors.text(root, "reactor_id"))

        assertEquals(ReactorVectors.text(topology, "exchange"), ReactorProtocol.EXCHANGE)
        assertEquals("topic", ReactorVectors.text(topology, "exchange_type"))
        assertEquals(ReactorVectors.text(topology, "queue"), ReactorProtocol.queueName(tenant, reactorId))
        assertEquals(
            ReactorVectors.text(topology, "routing_key_token_pre_issue"),
            ReactorProtocol.routingKey(tenant, ReactorEvents.TOKEN_PRE_ISSUE),
        )
        assertEquals(
            ReactorVectors.text(topology, "routing_key_login_post_auth"),
            ReactorProtocol.routingKey(tenant, ReactorEvents.LOGIN_POST_AUTH),
        )
    }

    @Test
    fun `the fixture's field order is the order this SDK writes`() {
        val root = ReactorVectors.load()
        val order = root["field_order"]!!.jsonObject

        // The fixture annotates its last entry in prose ("hmac_signature
        // (SERIALIZED AS null while signing, not omitted)"), so the field name is
        // the token before the parenthesis.
        assertEquals(
            listOf(
                "tenant_id", "event", "correlation_id", "payload", "timeout_ms",
                "key_version", "nonce", "issued_at", "hmac_signature",
            ),
            order["reactor_event"]!!.jsonArrayNames(),
        )
        assertEquals(
            listOf(
                "correlation_id", "tenant_id", "event", "decision", "reason", "patch",
                "require_mfa", "key_version", "nonce", "issued_at", "hmac_signature",
            ),
            order["reactor_reply"]!!.jsonArrayNames(),
        )

        // The mutate vector exercises the longest reply: decision + patch, with
        // reason and require_mfa omitted. Its key order is the contract's, minus
        // the omissions.
        val mutate = ReactorVectors.canonicalObject(
            root["reactor_to_server"]!!.jsonObject["mutate"]!!.jsonObject,
        )
        assertEquals(
            listOf(
                "correlation_id", "tenant_id", "event", "decision", "patch",
                "key_version", "nonce", "issued_at", "hmac_signature",
            ),
            mutate.keys.toList(),
        )
    }

    // ---- helpers -----------------------------------------------------------

    private fun kotlinx.serialization.json.JsonElement.jsonArrayNames(): List<String> =
        (this as kotlinx.serialization.json.JsonArray).map { it.jsonPrimitive.content.substringBefore(" ") }

    private fun macOf(signedBody: ByteArray): String =
        ReactorVectors.json.parseToJsonElement(signedBody.decodeToString())
            .jsonObject["hmac_signature"]!!.jsonPrimitive.content

    private fun decisionOf(message: JsonObject): ReactorDecision =
        when (val decision = ReactorVectors.text(message, "decision")) {
            "allow" ->
                if (message["require_mfa"]?.jsonPrimitive?.content == "true") {
                    ReactorDecision.allowRequiringStepUp()
                } else {
                    ReactorDecision.allow()
                }

            "deny" -> ReactorDecision.deny(message["reason"]?.jsonPrimitive?.content)

            "mutate" -> ReactorDecision.mutate(
                message["patch"]!!.jsonObject.entries.associate { it.key to it.value.jsonPrimitive.content },
            )

            else -> error("unknown decision $decision")
        }
}
