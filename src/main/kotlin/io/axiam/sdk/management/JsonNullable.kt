package io.axiam.sdk.management

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull

/**
 * A member where an explicit JSON `null` is a different statement from an
 * absent member — CONTRACT.md §27.4 rule 5's "null is not absent".
 *
 * Kotlin's own `T?` has two states, and a sparse body needs three: [Absent]
 * (the member is not sent, and the stored value is kept), [Null] (the member
 * is sent as `null`, which CLEARS the stored value) and [Value] (it is sent
 * and replaces the stored value). Decoding keeps the same three apart, so a
 * response that carried `"next_credential_id": null` is told from one that
 * left the member out.
 *
 * Used only where the contract names the distinction — today
 * `UpdateDirectoryConfig.groupBaseDn` / `groupFilter` (§30.2) and
 * `SamlIdpInfo.activeCredentialId` / `nextCredentialId` (§29.8 test 8).
 * Every other optional member stays a plain `T?`, where `null` means absent.
 *
 * ```kotlin
 * // Clears the group filter; leaves everything else as stored.
 * client.directory.update(UpdateDirectoryConfig(groupFilter = JsonNullable.Null))
 * ```
 *
 * @param T the member's value type
 */
@Serializable(with = JsonNullableSerializer::class)
sealed interface JsonNullable<out T> {

    /** The member is not sent; on a read, the server did not send it. */
    data object Absent : JsonNullable<Nothing>

    /** The member is sent as JSON `null`; on a read, the server sent `null`. */
    data object Null : JsonNullable<Nothing>

    /**
     * The member carries [value].
     *
     * @property value the member's value
     */
    data class Value<out T>(val value: T) : JsonNullable<T>

    /** The value when this is [Value], else `null` (for [Absent] and [Null] alike). */
    val valueOrNull: T?
        get() = (this as? Value<T>)?.value

    companion object {
        /**
         * [Value] of [value], or [Null] when [value] is `null` — the "set this
         * member to what I hold, clearing it if I hold nothing" spelling.
         *
         * @param value the value to send, or `null` to clear
         * @return the corresponding member
         */
        fun <T> of(value: T?): JsonNullable<T> = if (value == null) Null else Value(value)
    }
}

/**
 * The [JsonNullable] serializer. [JsonNullable.Absent] never reaches it on the
 * wire writer — it is the property default, and `encodeDefaults = false`
 * omits it — so the only place it is asked to encode one is a round-trip
 * reader with `encodeDefaults = true`, where `null` is the closest JSON
 * spelling.
 *
 * @param T the member's value type
 * @param inner the value type's serializer
 */
class JsonNullableSerializer<T>(private val inner: KSerializer<T>) : KSerializer<JsonNullable<T>> {

    override val descriptor: SerialDescriptor = inner.descriptor

    override fun serialize(encoder: Encoder, value: JsonNullable<T>) {
        when (value) {
            is JsonNullable.Value -> encoder.encodeSerializableValue(inner, value.value)
            JsonNullable.Null, JsonNullable.Absent -> jsonOnly(encoder as? JsonEncoder).encodeJsonElement(JsonNull)
        }
    }

    override fun deserialize(decoder: Decoder): JsonNullable<T> {
        val input = jsonOnly(decoder as? JsonDecoder)
        val element = input.decodeJsonElement()
        if (element is JsonNull) return JsonNullable.Null
        return JsonNullable.Value(input.json.decodeFromJsonElement(inner, element))
    }

    /** JSON is the only format the §27 surface speaks; `null` here is a programming error. */
    private fun <C : Any> jsonOnly(codec: C?): C = codec ?: error("JsonNullable is a JSON-only type")
}
