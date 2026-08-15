package io.axiam.sdk.reactor

/**
 * One delivery handed up from the broker.
 *
 * @property deliveryTag the broker's settle handle for this message.
 * @property routingKey `<tenant_id>.<event>`, used only for diagnostics — the
 *   authoritative event name is inside the signed body.
 * @property replyTo the queue to publish the reply to, from the delivery's AMQP
 *   `reply_to` basic property. `null` when the delivery carried none, in which
 *   case there is nowhere to answer.
 * @property body the raw message bytes, unverified.
 */
public class ReactorDelivery(
    public val deliveryTag: Long,
    public val routingKey: String,
    public val replyTo: String?,
    public val body: ByteArray,
)

/**
 * The broker seam (CONTRACT.md §22.1).
 *
 * Deliberately narrow: **consume, publish, settle, cancel**. There is no
 * `declareExchange`, no `declareQueue` and no `bind` on this interface, and that
 * is the point — §22.1 makes topology declaration the server's job, and a
 * reactor that can bind is a reactor that can bind itself to
 * `*.token.pre_issue` and read another tenant's issuance events. Refusing to
 * hold that capability at all is cheaper than proving each actor does not misuse
 * it, so the capability is absent from the type rather than merely unused by the
 * implementation.
 *
 * [RabbitMqReactorTransport] is the bundled implementation. The interface is
 * public so a different AMQP client, or a test harness, can drive the same
 * runtime.
 */
public interface ReactorTransport {

    /**
     * Starts consuming [queue] with manual acknowledgement.
     *
     * @param queue the server-declared queue name. An implementation MUST NOT
     *   declare or bind it.
     * @param onDelivery invoked per message, on whatever thread the transport
     *   delivers on
     * @return the consumer tag, for [cancel]
     */
    public fun consume(queue: String, onDelivery: (ReactorDelivery) -> Unit): String

    /**
     * Publishes a signed reply.
     *
     * @param replyTo the queue named by the delivery's `reply_to` property
     * @param correlationId echoed into the AMQP `correlation_id` property —
     *   standard RPC. What the server authenticates is the same value inside the
     *   signed body, which the runtime has already put there.
     * @param body the signed reply bytes
     */
    public fun publishReply(replyTo: String, correlationId: String, body: ByteArray)

    /**
     * Settles a delivery as handled.
     *
     * @param deliveryTag the delivery to acknowledge
     */
    public fun ack(deliveryTag: Long)

    /**
     * Settles a delivery as not handled.
     *
     * @param deliveryTag the delivery to reject
     * @param requeue whether the broker should redeliver it
     */
    public fun nack(deliveryTag: Long, requeue: Boolean)

    /**
     * Stops the consumer so no new delivery starts (§18).
     *
     * @param consumerTag the tag returned by [consume]
     */
    public fun cancel(consumerTag: String)
}
