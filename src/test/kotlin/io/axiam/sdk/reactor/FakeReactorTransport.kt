package io.axiam.sdk.reactor

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.Collections
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * A [ReactorTransport] that records everything and talks to no broker.
 *
 * The runtime's whole contact with AMQP is these five verbs, so a fake that
 * records them proves the §22.13 "Runtime" claims — zero published messages for
 * a handler that threw, the settle decision on every refusal path, and the
 * consumer cancel on shutdown — without a live broker anywhere.
 */
internal class FakeReactorTransport(
    private val cancelFails: Boolean = false,
) : ReactorTransport {

    val published: MutableList<Published> = Collections.synchronizedList(mutableListOf())
    val settled: MutableList<Settle> = Collections.synchronizedList(mutableListOf())
    val consumed: MutableList<String> = Collections.synchronizedList(mutableListOf())
    val cancelled: MutableList<String> = Collections.synchronizedList(mutableListOf())

    var onDelivery: ((ReactorDelivery) -> Unit)? = null
        private set

    data class Published(val replyTo: String, val correlationId: String, val body: ByteArray)

    data class Settle(val deliveryTag: Long, val acked: Boolean, val requeue: Boolean)

    override fun consume(queue: String, onDelivery: (ReactorDelivery) -> Unit): String {
        consumed += queue
        this.onDelivery = onDelivery
        return "consumer-tag"
    }

    override fun publishReply(replyTo: String, correlationId: String, body: ByteArray) {
        published += Published(replyTo, correlationId, body)
    }

    override fun ack(deliveryTag: Long) {
        settled += Settle(deliveryTag, acked = true, requeue = false)
    }

    override fun nack(deliveryTag: Long, requeue: Boolean) {
        settled += Settle(deliveryTag, acked = false, requeue = requeue)
    }

    override fun cancel(consumerTag: String) {
        if (cancelFails) {
            throw IllegalStateException("channel already closed")
        }
        cancelled += consumerTag
    }
}

/**
 * Builds server-side event bodies for tests: the same declared field order and
 * the same `"hmac_signature": null` canonicalization the AXIAM server uses,
 * written out longhand here rather than delegating to [ReactorProtocol].
 *
 * Writing it twice is the point. If a test signed events with the very code
 * under test, a canonicalization bug would cancel out and every assertion would
 * still pass — which is exactly the failure mode the §22.13 vectors exist to
 * catch. Those vectors remain the ground truth; this helper only exists to vary
 * the fields the fixture pins (nonce, timestamp, timeout, payload).
 */
internal object EventFactory {

    fun signEvent(
        key: ByteArray,
        tenantId: UUID,
        event: String,
        nonce: UUID = UUID.randomUUID(),
        issuedAt: Instant,
        timeoutMs: Int = 500,
        correlationId: UUID = UUID.randomUUID(),
        payload: JsonObject = buildJsonObject { put("sub", JsonPrimitive("alice")) },
    ): ByteArray {
        val canonical = buildJsonObject {
            put("tenant_id", JsonPrimitive(tenantId.toString()))
            put("event", JsonPrimitive(event))
            put("correlation_id", JsonPrimitive(correlationId.toString()))
            put("payload", payload)
            put("timeout_ms", JsonPrimitive(timeoutMs))
            put("key_version", JsonPrimitive(2))
            put("nonce", JsonPrimitive(nonce.toString()))
            put("issued_at", JsonPrimitive(ReactorProtocol.formatInstant(issuedAt)))
            put("hmac_signature", JsonNull)
        }
        return sign(key, canonical)
    }

    /** Signs a tree whose `hmac_signature` is already present and null. */
    fun sign(key: ByteArray, canonical: JsonObject): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        val hex = mac.doFinal(ReactorVectors.encode(canonical)).joinToString("") { "%02x".format(it) }
        return ReactorVectors.encode(ReactorVectors.withSignature(canonical, hex))
    }
}
