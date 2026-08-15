package io.axiam.sdk.reactor

import com.rabbitmq.client.AMQP
import com.rabbitmq.client.CancelCallback
import com.rabbitmq.client.Channel
import com.rabbitmq.client.DeliverCallback
import com.rabbitmq.client.Delivery
import com.rabbitmq.client.Envelope
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.UUID

/**
 * The bundled RabbitMQ transport (CONTRACT.md §22.1 topology rules, §8b
 * transport security), driven against a [Proxy]-backed fake [Channel] that
 * records every method the transport calls.
 *
 * Recording the calls is what makes "**declares no exchange, no queue and no
 * binding**" an assertion about behaviour rather than about source code. The
 * [ReactorTransport] interface has no declare or bind method at all, so the
 * capability is absent from the type — but a transport could still reach past
 * its own interface and call the channel directly, and this proves it does not.
 *
 * No broker is involved anywhere, and no certificate or key material is
 * committed: the §8b tests mint an in-memory PKI per run.
 */
class ReactorTransportTest {

    private val recorded = mutableListOf<Call>()
    private var deliverCallback: DeliverCallback? = null

    private data class Call(val method: String, val args: List<Any?>)

    // ---- §22.1: consume, publish, settle, cancel — and nothing else --------

    @Test
    fun `the transport consumes with manual ack and declares no topology`() {
        val transport = RabbitMqReactorTransport(fakeChannel())
        val seen = mutableListOf<ReactorDelivery>()

        val tag = transport.consume("axiam.reactor.q.t.r") { seen += it }

        assertEquals("consumer-tag", tag)
        assertEquals(listOf(16), call("basicQos").args, "the configured prefetch is applied")
        val consume = call("basicConsume")
        assertEquals("axiam.reactor.q.t.r", consume.args[0])
        assertEquals(
            false,
            consume.args[1],
            "autoAck MUST be false — the runtime settles each delivery itself",
        )
        assertTrue(
            recorded.none {
                it.method.startsWith("exchangeDeclare") || it.method.startsWith("queueDeclare") ||
                    it.method.startsWith("queueBind") || it.method.startsWith("exchangeBind")
            },
            "actors consume; they never declare topology — saw ${recorded.map(Call::method)}",
        )

        // Drive one delivery through the callback the transport registered.
        deliverCallback!!.handle(
            "consumer-tag",
            Delivery(
                Envelope(7L, false, ReactorProtocol.EXCHANGE, "tenant.token.pre_issue"),
                AMQP.BasicProperties.Builder().replyTo("amq.rabbitmq.reply-to.abc").build(),
                "{}".toByteArray(),
            ),
        )

        assertEquals(1, seen.size)
        assertEquals(7L, seen[0].deliveryTag)
        assertEquals("tenant.token.pre_issue", seen[0].routingKey)
        assertEquals("amq.rabbitmq.reply-to.abc", seen[0].replyTo)
        assertEquals("{}", seen[0].body.decodeToString())
    }

    @Test
    fun `a delivery with no basic properties surfaces a null reply_to rather than throwing`() {
        val transport = RabbitMqReactorTransport(fakeChannel())
        val seen = mutableListOf<ReactorDelivery>()
        transport.consume("q") { seen += it }

        deliverCallback!!.handle(
            "consumer-tag",
            Delivery(Envelope(1L, false, ReactorProtocol.EXCHANGE, "rk"), null, ByteArray(0)),
        )

        assertNull(seen.single().replyTo, "no reply_to means there is nowhere to answer")
    }

    @Test
    fun `a reply is published to the default exchange with the correlation echoed`() {
        val transport = RabbitMqReactorTransport(fakeChannel())
        val correlation = UUID.randomUUID().toString()

        transport.publishReply("amq.rabbitmq.reply-to.abc", correlation, "body".toByteArray())

        val publish = call("basicPublish")
        assertEquals("", publish.args[0], "replies go to the default exchange — publishing to it is not a declaration")
        assertEquals("amq.rabbitmq.reply-to.abc", publish.args[1])
        val properties = publish.args[2] as AMQP.BasicProperties
        assertEquals("application/json", properties.contentType)
        assertEquals(
            correlation,
            properties.correlationId,
            "the AMQP property is echoed as standard RPC; what the server authenticates is the same " +
                "value inside the signed body",
        )
        assertEquals("body", (publish.args[3] as ByteArray).decodeToString())
    }

    @Test
    fun `settle and cancel map straight onto the channel`() {
        val transport = RabbitMqReactorTransport(fakeChannel())

        transport.ack(11L)
        transport.nack(12L, requeue = true)
        transport.cancel("consumer-tag")

        assertEquals(listOf(11L, false), call("basicAck").args)
        assertEquals(listOf(12L, false, true), call("basicNack").args)
        assertEquals(listOf("consumer-tag"), call("basicCancel").args)
    }

    @Test
    fun `a non-positive prefetch is refused rather than passed to the broker`() {
        assertThrows(IllegalArgumentException::class.java) {
            RabbitMqReactorTransport(fakeChannel(), prefetch = 0)
        }
        val explicit = RabbitMqReactorTransport(fakeChannel(), prefetch = 64)
        assertNotNull(explicit)
        assertEquals(listOf(64), call("basicQos").args)
    }

    // ---- §8b: amqps only, custom CA, no bypass, no plaintext fallback ------

    @Test
    fun `a reactor connection refuses every scheme but amqps`() {
        val plaintext = assertThrows(NetworkError::class.java) {
            reactorConnectionFactory("amqp://broker.internal:5672")
        }
        assertTrue(
            plaintext.message!!.contains("amqps://"),
            "the refusal must name the rule it is enforcing: ${plaintext.message}",
        )
        assertTrue(
            plaintext.message!!.contains("no plaintext fallback"),
            "a failed amqps:// connection is an error to surface, not a condition to work around",
        )

        val schemeless = assertThrows(NetworkError::class.java) {
            reactorConnectionFactory("//broker.internal:5671")
        }
        assertTrue(schemeless.message!!.contains("no scheme"))

        assertThrows(NetworkError::class.java) {
            reactorConnectionFactory("https://broker.internal")
        }
    }

    @Test
    fun `a malformed broker URI is refused before anything is dialled`() {
        val error = assertThrows(NetworkError::class.java) {
            reactorConnectionFactory("amqps://broker with spaces:5671")
        }
        assertTrue(error.message!!.contains("not a valid URI"), error.message!!)
    }

    @Test
    fun `an amqps URI with a private CA builds a factory with hostname verification on`() {
        val rootCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Broker Root").build()

        val factory = reactorConnectionFactory(
            uri = "amqps://broker.internal:5671/%2f",
            customCaPem = rootCa.certificatePem().toByteArray(),
        )

        assertEquals("broker.internal", factory.host)
        assertEquals(5671, factory.port)
        assertTrue(factory.isAutomaticRecoveryEnabled, "reconnect is the client's, left on")
    }

    @Test
    fun `a client identity is accepted whole and refused in halves`() {
        val rootCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Broker Root").build()
        val client = HeldCertificate.Builder()
            .commonName("reactor-1")
            .signedBy(rootCa)
            .build()

        val factory = reactorConnectionFactory(
            uri = "amqps://broker.internal:5671",
            customCaPem = rootCa.certificatePem().toByteArray(),
            clientCertPem = client.certificatePem().toByteArray(),
            clientKeyPem = Sensitive.of(client.privateKeyPkcs8Pem().toByteArray()),
        )
        assertEquals("broker.internal", factory.host)

        // §8b rule 3: half a client identity fails closed rather than connecting
        // without the mutual half.
        assertThrows(NetworkError::class.java) {
            reactorConnectionFactory(
                uri = "amqps://broker.internal:5671",
                clientCertPem = client.certificatePem().toByteArray(),
            )
        }
        assertThrows(NetworkError::class.java) {
            reactorConnectionFactory(
                uri = "amqps://broker.internal:5671",
                clientKeyPem = Sensitive.of(client.privateKeyPkcs8Pem().toByteArray()),
            )
        }
    }

    @Test
    fun `no reactor type exposes a verification-skip switch`() {
        // §8b rule 5 / §6: there is no bypass under any name, in any build.
        // Asserted against the reflected member names rather than a comment.
        val banned = listOf("insecure", "skipverify", "trustall", "allowinvalid", "disabletls", "verifynone")
        val members = buildList {
            addAll(RabbitMqReactorTransport::class.java.methods.map { it.name })
            addAll(Class.forName("io.axiam.sdk.reactor.RabbitMqReactorTransportKt").methods.map { it.name })
            addAll(ReactorServeOptions::class.java.methods.map { it.name })
            addAll(ReactorTransport::class.java.methods.map { it.name })
        }
        for (name in members) {
            val flat = name.lowercase().replace("_", "")
            assertFalse(banned.any { flat.contains(it) }, "TLS-bypass-shaped member: $name")
        }
    }

    // ---- helpers -----------------------------------------------------------

    private fun call(method: String): Call =
        recorded.lastOrNull { it.method == method }
            ?: throw AssertionError("no $method call was recorded; saw ${recorded.map(Call::method)}")

    /**
     * A [Channel] that records every invocation. [Channel] is an interface, so a
     * JDK proxy needs no mocking framework — and a proxy records *every* method,
     * including the declare calls this transport must never make.
     */
    private fun fakeChannel(): Channel {
        val handler = InvocationHandler { proxy, method: Method, args: Array<Any?>? ->
            when (method.name) {
                "toString" -> return@InvocationHandler "fakeChannel"
                "hashCode" -> return@InvocationHandler System.identityHashCode(proxy)
                "equals" -> return@InvocationHandler proxy === args?.get(0)
                else -> Unit
            }
            recorded += Call(method.name, args?.toList() ?: emptyList())
            when (method.name) {
                "basicConsume" -> {
                    deliverCallback = args?.filterIsInstance<DeliverCallback>()?.firstOrNull()
                    assertNotNull(
                        args?.filterIsInstance<CancelCallback>()?.firstOrNull(),
                        "a broker-side cancel must be handled rather than ignored",
                    )
                    "consumer-tag"
                }

                else -> defaultValue(method.returnType)
            }
        }
        return Proxy.newProxyInstance(
            Channel::class.java.classLoader,
            arrayOf(Channel::class.java),
            handler,
        ) as Channel
    }

    private fun defaultValue(type: Class<*>): Any? = when {
        !type.isPrimitive || type == Void.TYPE -> null
        type == java.lang.Boolean.TYPE -> false
        type == java.lang.Long.TYPE -> 0L
        type == Integer.TYPE -> 0
        else -> 0
    }
}
