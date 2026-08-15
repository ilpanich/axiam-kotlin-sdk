package io.axiam.sdk.reactor

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.UUID

/**
 * Loader for the CONTRACT.md §22.13 reference vectors
 * (`crates/axiam-amqp/tests/fixtures/reactor_v2_reference_vectors.json`, copied
 * verbatim onto this module's test classpath) and for §8's own vectors beside
 * them.
 *
 * The two fixtures share a master key, a tenant and a derived subkey, which is
 * exactly why §22.13 says one loader serves both: the only difference between
 * the two message families — `hmac_signature` present and `null` here, absent
 * there — becomes a test rather than a paragraph to remember.
 *
 * **Fixture-reading note:** a vector's `message` object is a convenience
 * rendering with alphabetically sorted keys and must never be fed to a verifier
 * directly. The one authoritative field for wire order is
 * `canonical_signed_json`, whose key order as written in the fixture text *is*
 * the declared field order. Every helper below builds its wire body from that
 * string.
 */
internal object ReactorVectors {

    val json: Json = Json

    fun load(resource: String = "/reactor_v2_reference_vectors.json"): JsonObject {
        val stream = requireNotNull(ReactorVectors::class.java.getResourceAsStream(resource)) {
            "fixture not found on classpath: $resource"
        }
        return json.parseToJsonElement(stream.readBytes().decodeToString()).jsonObject
    }

    fun subkey(root: JsonObject): ByteArray =
        hex(root["hkdf"]!!.jsonObject["derived_subkey_hex"]!!.jsonPrimitive.content)

    fun masterKey(root: JsonObject): ByteArray =
        hex(root["master_signing_key_hex"]!!.jsonPrimitive.content)

    fun tenantId(root: JsonObject): UUID = UUID.fromString(root["tenant_id"]!!.jsonPrimitive.content)

    fun correlationId(root: JsonObject): UUID =
        UUID.fromString(root["expected_correlation_id"]!!.jsonPrimitive.content)

    fun text(obj: JsonObject, field: String): String = obj[field]!!.jsonPrimitive.content

    /** The canonical (signed-over) tree: `hmac_signature` present and null. */
    fun canonicalObject(vector: JsonObject): JsonObject =
        json.parseToJsonElement(text(vector, "canonical_signed_json")).jsonObject

    /**
     * Reconstructs the signed wire body: the canonical bytes with
     * `hmac_signature` carrying the committed hex instead of `null`. Replacing
     * an existing key keeps its position, so the field stays exactly where the
     * server wrote it.
     */
    fun wireBody(vector: JsonObject): ByteArray =
        encode(withSignature(canonicalObject(vector), text(vector, "hmac_signature_hex")))

    fun withSignature(canonical: JsonObject, signatureHex: String): JsonObject =
        JsonObject(canonical + ("hmac_signature" to JsonPrimitive(signatureHex)))

    fun encode(obj: JsonObject): ByteArray =
        json.encodeToString(JsonObject.serializer(), obj).toByteArray()

    fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
