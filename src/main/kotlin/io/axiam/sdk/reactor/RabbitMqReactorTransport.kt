package io.axiam.sdk.reactor

import com.rabbitmq.client.AMQP
import com.rabbitmq.client.CancelCallback
import com.rabbitmq.client.Channel
import com.rabbitmq.client.ConnectionFactory
import com.rabbitmq.client.DeliverCallback
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.TlsFactory
import java.net.URI

/**
 * [ReactorTransport] over the RabbitMQ Java client.
 *
 * The RabbitMQ client is a **`compileOnly`** dependency of this SDK, exactly as
 * Ktor is: the core compiles and runs without it, and a consumer who does not
 * write reactors never carries it. A reactor author adds
 * `com.rabbitmq:amqp-client` themselves.
 *
 * This class is deliberately thin. It maps five verbs onto the channel and adds
 * nothing else — in particular it declares no exchange, no queue and no binding,
 * because [ReactorTransport] has no method that could and §22.1 makes topology
 * the server's job.
 *
 * @param channel an open AMQP channel; the caller owns its lifecycle. Open its
 *   connection with [reactorConnectionFactory] so §8b's transport rules hold.
 * @param prefetch the channel QoS applied on construction. The server's own
 *   per-tenant in-flight cap is
 *   [ReactorProtocol.DEFAULT_MAX_IN_FLIGHT_PER_TENANT].
 */
public class RabbitMqReactorTransport(
    private val channel: Channel,
    prefetch: Int = 16,
) : ReactorTransport {

    init {
        require(prefetch > 0) { "prefetch must be positive" }
        channel.basicQos(prefetch)
    }

    override fun consume(queue: String, onDelivery: (ReactorDelivery) -> Unit): String {
        val deliver = DeliverCallback { _, delivery ->
            onDelivery(
                ReactorDelivery(
                    deliveryTag = delivery.envelope.deliveryTag,
                    routingKey = delivery.envelope.routingKey,
                    replyTo = delivery.properties?.replyTo,
                    body = delivery.body,
                ),
            )
        }
        val cancel = CancelCallback {
            // The broker cancelled us (queue deleted, or the registration was
            // removed). Nothing to do: the caller owns the channel, and a
            // transport that re-declared the queue here would be doing exactly
            // what §22.1 forbids.
        }
        // autoAck = false: the runtime settles each delivery itself.
        return channel.basicConsume(queue, false, deliver, cancel)
    }

    override fun publishReply(replyTo: String, correlationId: String, body: ByteArray) {
        val properties = AMQP.BasicProperties.Builder()
            .contentType("application/json")
            .correlationId(correlationId)
            .build()
        // Default exchange, routing key = the reply queue: standard AMQP RPC.
        // Publishing to "" is not declaring topology — every broker routes the
        // default exchange to the same-named queue with no declaration at all.
        channel.basicPublish("", replyTo, properties, body)
    }

    override fun ack(deliveryTag: Long) {
        channel.basicAck(deliveryTag, false)
    }

    override fun nack(deliveryTag: Long, requeue: Boolean) {
        channel.basicNack(deliveryTag, false, requeue)
    }

    override fun cancel(consumerTag: String) {
        channel.basicCancel(consumerTag)
    }
}

/**
 * Builds a [ConnectionFactory] that satisfies CONTRACT.md §8b for a reactor
 * connection.
 *
 * Reactors connect across a trust boundary, so §8b applies in full and this
 * function enforces its rules rather than documenting them:
 *
 * - **`amqps://` only.** A `amqp://` (or any other) scheme is refused here
 *   rather than downgraded. HMAC gives end-to-end authenticity across broker
 *   hops; it does not give confidentiality, and a reactor event names the
 *   subject whose login is being decided.
 * - **A custom CA is supported**, because an in-cluster broker's certificate is
 *   not issued by a public CA — which is the whole reason nobody needs a
 *   verification-skip switch.
 * - **There is no verification-skip switch**, under any name, in any build.
 * - **Half a client identity fails closed**: a certificate without its key, or
 *   the mirror case, is refused before dialling.
 * - **No plaintext fallback.** A failed `amqps://` connection is an error to
 *   surface, not a condition to work around, so this function never retries on a
 *   different scheme.
 *
 * The TLS stack itself is [TlsFactory] — the same strict builder the REST client
 * uses for §6/§6.1, rather than a second one that could drift from it.
 *
 * @param uri the broker URI; must be `amqps://`
 * @param customCaPem optional PEM CA to add to the system trust store
 * @param clientCertPem optional PEM client certificate chain (mutual TLS)
 * @param clientKeyPem optional PEM PKCS#8 private key, wrapped [Sensitive]
 * @return a factory ready to open a connection
 * @throws NetworkError when the URI is not `amqps://`, when the CA or client
 *   identity is invalid, or when only half a client identity was supplied
 */
public fun reactorConnectionFactory(
    uri: String,
    customCaPem: ByteArray? = null,
    clientCertPem: ByteArray? = null,
    clientKeyPem: Sensitive<ByteArray>? = null,
): ConnectionFactory {
    val scheme = try {
        URI(uri).scheme?.lowercase()
    } catch (e: Exception) {
        throw NetworkError("reactor broker URI is not a valid URI: ${e.message}", e)
    }
    if (scheme != "amqps") {
        throw NetworkError(
            "a reactor MUST connect over amqps:// (CONTRACT.md §8b rules 1 and 5) — " +
                "got '${scheme ?: "no scheme"}'. HMAC gives authenticity, not confidentiality, " +
                "and there is no plaintext fallback.",
        )
    }

    val tls = TlsFactory.build(customCaPem, clientCertPem, clientKeyPem)
    return ConnectionFactory().apply {
        setUri(uri)
        useSslProtocol(tls.sslContext)
        // Verify the broker's hostname against its certificate. There is
        // deliberately no switch anywhere in this SDK to turn this back off.
        enableHostnameVerification()
        isAutomaticRecoveryEnabled = true
    }
}
