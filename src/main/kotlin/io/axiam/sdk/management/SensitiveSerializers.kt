package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Reads a secret off the wire into a [Sensitive], and writes it back
 * **redacted** (CONTRACT.md §27.5).
 *
 * The serializer the response reader carries. A §27 response model that a
 * caller re-serializes for a log line, a debug dump or their own cache renders
 * the secret as `[SENSITIVE]` — matching [Sensitive.toString], so the two
 * renderings cannot disagree.
 */
internal object SensitiveRedactingSerializer : KSerializer<Sensitive<String>> {

    private const val REDACTED = "[SENSITIVE]"

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("io.axiam.sdk.Sensitive", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Sensitive<String>) {
        encoder.encodeString(REDACTED)
    }

    override fun deserialize(decoder: Decoder): Sensitive<String> =
        Sensitive.of(decoder.decodeString())
}

/**
 * Writes a secret out **in the clear** — the one place a [Sensitive] is
 * allowed to reach a socket (CONTRACT.md §27.5, §7 rule 4).
 *
 * Registered on exactly one `Json`, the request writer inside
 * `ManagementTransport`. Keeping it to a single registration is what makes
 * "a §27 secret goes on the wire here" one greppable place instead of
 * fourteen request types with a hand-written wire twin.
 *
 * A caller's own `Json` has neither this serializer nor
 * [SensitiveRedactingSerializer] registered, so encoding a §27 model with one
 * throws `SerializationException` rather than quietly emitting either the
 * secret or a placeholder the server would reject. Fail-closed, and loudly.
 */
internal object SensitiveExposingSerializer : KSerializer<Sensitive<String>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("io.axiam.sdk.Sensitive", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Sensitive<String>) {
        encoder.encodeString(value.expose())
    }

    override fun deserialize(decoder: Decoder): Sensitive<String> =
        Sensitive.of(decoder.decodeString())
}

/**
 * Carries a `uuid`-formatted field as a [java.util.UUID] rather than a String.
 *
 * The typing is the point, not the convenience: CONTRACT.md §27.9 requires that
 * a non-UUID identifier fail client-side with **zero** wire calls, and a
 * parameter typed [java.util.UUID] cannot be handed one — the compiler refuses
 * the call, which is the earliest possible failure and needs no test to stay
 * true.
 *
 * Attached per-property with `@Serializable(with = ...)` rather than registered
 * contextually, so a response model stays serializable with a caller's own
 * `Json`. Only `Sensitive` is deliberately fail-closed that way.
 */
internal object UuidSerializer : KSerializer<java.util.UUID> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("java.util.UUID", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: java.util.UUID) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): java.util.UUID =
        java.util.UUID.fromString(decoder.decodeString())
}

/**
 * Carries a `date-time` field as a [java.time.Instant].
 *
 * RFC 3339 in, RFC 3339 out. An [java.time.Instant] rather than a
 * `LocalDateTime` because every timestamp on this surface is an absolute
 * moment the server stamped in UTC, and a local date-time would drop the one
 * piece of information that makes two of them comparable.
 */
internal object InstantSerializer : KSerializer<java.time.Instant> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("java.time.Instant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: java.time.Instant) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): java.time.Instant =
        java.time.Instant.parse(decoder.decodeString())
}
