package io.axiam.sdk.reactor

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The reactor wire protocol (CONTRACT.md §22.1–§22.4): topology names, key
 * derivation, canonicalization, signing and verification.
 *
 * [ReactorServer] is built on this object, and this object is public so an
 * integrator on a transport this SDK does not wrap can satisfy §22 without
 * reimplementing the one rule that is easy to get wrong.
 *
 * ## The canonicalization rule
 *
 * A reactor body is signed with its `hmac_signature` field **present and set to
 * `null`**, in declared field order. That differs from §8's own two message
 * types (`AuthzRequest`, `AuditEventMessage`), whose `hmac_signature` is
 * *absent* from their canonical bytes — and it is the single most likely place
 * for an implementation to produce a MAC that will not verify. Everything else
 * is §8 v2 verbatim: the same HKDF-derived per-tenant subkey, the same
 * `HMAC-SHA256` compared in constant time, the same ±300 s freshness window
 * applied in **both** directions, the same `key_version` floor of 2.
 *
 * Field order, event (server → reactor): `tenant_id`, `event`,
 * `correlation_id`, `payload`, `timeout_ms`, `key_version`, `nonce`,
 * `issued_at`, `hmac_signature`.
 *
 * Field order, reply (reactor → server): `correlation_id`, `tenant_id`,
 * `event`, `decision`, `reason` (omitted when absent), `patch` (omitted when
 * absent), `require_mfa` (**omitted when `false`**), `key_version`, `nonce`,
 * `issued_at`, `hmac_signature`.
 *
 * The three conditionally-omitted fields are load-bearing: a reply that
 * serializes `"require_mfa": false` rather than omitting it produces different
 * canonical bytes and therefore a different MAC.
 *
 * ## Signing is symmetric in direction
 *
 * The server signs the event with the tenant subkey; the reactor signs its
 * reply with the same subkey. There is no second key and no asymmetric variant
 * in v1. An unsigned reply is not a weak reply — it is not a reply at all, and
 * the server discards it as though the reactor had never answered.
 */
public object ReactorProtocol {

    /** The topic exchange every reactor event is published to. */
    public const val EXCHANGE: String = "axiam.reactor.events"

    /** The §8 envelope version reactor bodies are signed under. */
    public const val KEY_VERSION: Int = 2

    /**
     * The lowest `key_version` that is even considered. A body carrying less
     * than this is refused before anything else about it is looked at — it
     * predates the mandatory `nonce`/`issued_at` replay-protection fields.
     */
    public const val MIN_ACCEPTED_KEY_VERSION: Int = 2

    /** The `timeout_ms` a registration gets when it names none (§22.8). */
    public const val DEFAULT_TIMEOUT_MS: Int = 500

    /** The largest `timeout_ms` a registration may name; above this it is refused. */
    public const val MAX_TIMEOUT_MS: Int = 5_000

    /** The chain's wall-clock ceiling: past this the remaining reactors are not contacted. */
    public const val CHAIN_CEILING_MS: Int = 5_000

    /** The server's default per-tenant in-flight interception cap. */
    public const val DEFAULT_MAX_IN_FLIGHT_PER_TENANT: Int = 64

    /** The §8 v2 freshness window applied to `issued_at`, in both directions. */
    public val DEFAULT_FRESHNESS_SKEW: Duration = 300.seconds

    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val SIGNATURE_FIELD = "hmac_signature"

    /** HKDF salt for the AMQP subkey. Salts are not secret; domain separation is the `info`. */
    private val HKDF_SALT: ByteArray = "axiam-amqp-hkdf-salt-v1".toByteArray()

    /** HKDF domain tag, so an AMQP subkey can never collide with one derived for another purpose. */
    private val HKDF_DOMAIN_TAG: ByteArray = "axiam-amqp-v1".toByteArray()

    private val json = Json { encodeDefaults = true }

    // ---- topology (§22.1) --------------------------------------------------

    /**
     * The routing key an event for [event] in [tenantId] is published under.
     *
     * @return `<tenant_id>.<event>`
     */
    public fun routingKey(tenantId: UUID, event: String): String = "$tenantId.$event"

    /**
     * The durable per-reactor queue the **server** declares.
     *
     * Actors consume; they never declare topology. This helper exists so a
     * runtime can name the queue it was registered as — never another one. A
     * reactor that can bind is a reactor that can bind itself to
     * `*.token.pre_issue` and read another tenant's issuance events, so this SDK
     * holds no declare or bind capability at all.
     *
     * @param tenantId the tenant the reactor is registered in
     * @param reactorId this reactor's own registration id
     * @return `axiam.reactor.q.<tenant_id>.<reactor_id>`
     */
    public fun queueName(tenantId: UUID, reactorId: UUID): String =
        "axiam.reactor.q.$tenantId.$reactorId"

    // ---- key derivation (§8 v2) -------------------------------------------

    /**
     * Derives a tenant's AMQP signing subkey from the deployment master key
     * (CONTRACT.md §8 v2, restated by §22.2).
     *
     * `HKDF-SHA256(salt = "axiam-amqp-hkdf-salt-v1", ikm = masterKey,
     * info = "axiam-amqp-v1" || keyVersion || tenantId_16_raw_bytes)`, 32 bytes
     * out. The `info` is domain-separated, versioned and tenant-scoped, so a
     * signature made with tenant A's subkey never verifies under tenant B's even
     * though both derive from one master key.
     *
     * Most deployments should fetch the derived subkey from the management API
     * rather than hold the master key in the reactor process at all; this exists
     * for the ones that derive locally, and because a derivation that cannot be
     * checked against the reference vectors is a derivation nobody can trust.
     *
     * @param masterKey the deployment's AMQP master signing key
     * @param tenantId the tenant to derive for
     * @param keyVersion the envelope key version, [KEY_VERSION] today
     * @return the 32-byte per-tenant subkey
     */
    public fun deriveTenantKey(
        masterKey: ByteArray,
        tenantId: UUID,
        keyVersion: Int = KEY_VERSION,
    ): ByteArray {
        val prk = hmac(HKDF_SALT, masterKey)
        val info = HKDF_DOMAIN_TAG + byteArrayOf(keyVersion.toByte()) + tenantIdBytes(tenantId)
        // One 32-byte output block, so the HKDF expand counter is a single 0x01.
        return hmac(prk, info + byteArrayOf(1))
    }

    // ---- canonicalization + MAC -------------------------------------------

    /**
     * The exact bytes an event was signed over: the received body with
     * `hmac_signature` set to `null` in place.
     *
     * Setting the value rather than removing the key is what makes these bytes a
     * *reactor* body rather than a §8 one. The field keeps its position:
     * `kotlinx.serialization` parses a JSON object into an insertion-ordered map
     * and re-encodes it in that order, and numeric literals survive the round
     * trip as their original text.
     *
     * @param body the raw delivery body
     * @return the canonical bytes
     * @throws IllegalArgumentException when [body] is not a JSON object
     */
    public fun canonicalEventBytes(body: ByteArray): ByteArray {
        val parsed = parseObject(body)
        return encode(JsonObject(parsed + (SIGNATURE_FIELD to JsonNull)))
    }

    /**
     * Verifies an event's MAC under [signingKey].
     *
     * This checks the signature and nothing else. [ReactorServer] applies the
     * full §22.3 order around it — reject `key_version < 2`, verify the MAC,
     * check freshness, check the nonce — and only then decodes the payload.
     *
     * Never throws: a malformed body, a missing or null signature, non-hex
     * signature text and a wrong-length signature all verify as `false`. There
     * is no accept-when-absent path.
     *
     * @param signingKey the tenant's derived AMQP subkey
     * @param body the raw delivery body
     * @return `true` only when the MAC matches, compared in constant time
     */
    public fun verifyEvent(signingKey: ByteArray, body: ByteArray): Boolean = try {
        val parsed = parseObject(body)
        val presented = (parsed[SIGNATURE_FIELD] as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.content
            ?.let { hexToBytes(it) }
        if (presented == null) {
            false
        } else {
            val canonical = encode(JsonObject(parsed + (SIGNATURE_FIELD to JsonNull)))
            MessageDigest.isEqual(hmac(signingKey, canonical), presented)
        }
    } catch (_: RuntimeException) {
        false
    }

    /**
     * The exact bytes a reply is signed over: the reply fields in declared
     * order, with the conditional omissions applied and `hmac_signature` present
     * and `null`.
     *
     * @param correlationId the event's correlation id, copied verbatim
     * @param tenantId the event's tenant
     * @param event the event's registry name
     * @param decision what the handler decided
     * @param nonce a fresh UUIDv4, unique per reply
     * @param issuedAt the reply's signing time; truncated to whole seconds so it
     *   round-trips through the server's RFC 3339 parser to byte-identical text
     * @return the canonical bytes
     */
    public fun canonicalReplyBytes(
        correlationId: UUID,
        tenantId: UUID,
        event: String,
        decision: ReactorDecision,
        nonce: UUID,
        issuedAt: Instant,
    ): ByteArray = encode(replyObject(correlationId, tenantId, event, decision, nonce, issuedAt))

    /**
     * Builds and signs a reply — the wire bytes a reactor publishes.
     *
     * @param signingKey the tenant's derived AMQP subkey, the same one the event
     *   was signed with
     * @param correlationId the event's correlation id, copied verbatim. The
     *   server authenticates this field inside the signed body, not the AMQP
     *   property.
     * @param tenantId the event's tenant
     * @param event the event's registry name
     * @param decision what the handler decided
     * @param nonce a fresh UUIDv4. It is inside the signed bytes, so a unique one
     *   is what keeps two replies from being byte-identical; a constant nonce
     *   removes the only uniqueness the reply body carries beyond its timestamp.
     * @param issuedAt the reply's signing time
     * @return the signed reply body, ready to publish
     */
    public fun signedReply(
        signingKey: ByteArray,
        correlationId: UUID,
        tenantId: UUID,
        event: String,
        decision: ReactorDecision,
        nonce: UUID,
        issuedAt: Instant,
    ): ByteArray {
        val canonicalObject = replyObject(correlationId, tenantId, event, decision, nonce, issuedAt)
        val signature = bytesToHex(hmac(signingKey, encode(canonicalObject)))
        return encode(JsonObject(canonicalObject + (SIGNATURE_FIELD to JsonPrimitive(signature))))
    }

    /**
     * Whether [issuedAt] lies within [skew] of [now], in both directions.
     *
     * A future timestamp is not "extra fresh"; it is the shape of a captured
     * message held for later.
     *
     * @param issuedAt the timestamp inside the signed body
     * @param now the verifier's clock reading
     * @param skew the acceptance window, [DEFAULT_FRESHNESS_SKEW] by default
     * @return `true` when the timestamp is inside the window
     */
    public fun isFresh(
        issuedAt: Instant,
        now: Instant,
        skew: Duration = DEFAULT_FRESHNESS_SKEW,
    ): Boolean {
        val driftMillis = kotlin.math.abs(java.time.Duration.between(issuedAt, now).toMillis())
        return driftMillis <= skew.inWholeMilliseconds
    }

    /**
     * Renders [instant] the way the server's RFC 3339 codec does, truncated to
     * whole seconds.
     *
     * The server verifies a reply by deserializing it and re-serializing the
     * body, so the timestamp text has to survive that round trip unchanged.
     * Whole seconds always do; a sub-second value whose digit count does not
     * match the server's auto-selected precision would not.
     *
     * @param instant the moment to render
     * @return an RFC 3339 UTC timestamp with no fractional part
     */
    public fun formatInstant(instant: Instant): String =
        DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS))

    // ---- internals ---------------------------------------------------------

    private fun replyObject(
        correlationId: UUID,
        tenantId: UUID,
        event: String,
        decision: ReactorDecision,
        nonce: UUID,
        issuedAt: Instant,
    ): JsonObject = buildJsonObject {
        put("correlation_id", JsonPrimitive(correlationId.toString()))
        put("tenant_id", JsonPrimitive(tenantId.toString()))
        put("event", JsonPrimitive(event))
        put("decision", JsonPrimitive(decision.wire))

        when (decision) {
            is ReactorDecision.Allow -> {
                // require_mfa is emitted ONLY when true: `"require_mfa": false`
                // would change the canonical bytes and therefore the MAC.
                if (decision.requireMfa) {
                    put("require_mfa", JsonPrimitive(true))
                }
            }

            is ReactorDecision.Deny -> decision.reason?.let { put("reason", JsonPrimitive(it)) }

            is ReactorDecision.Mutate -> {
                // The server's patch is a BTreeMap, so its serialization order is
                // UTF-8 byte order. Sent UNFILTERED: §22.4 rule 1 forbids
                // trimming a handler's patch to the allowed subset, because one
                // forbidden key rejects the whole reply and the author must find
                // out.
                val patch = buildJsonObject {
                    decision.patch.entries
                        .sortedWith(compareBy(Utf8Order) { it.key })
                        .forEach { put(it.key, JsonPrimitive(it.value)) }
                }
                put("patch", patch)
            }
        }

        put("key_version", JsonPrimitive(KEY_VERSION))
        put("nonce", JsonPrimitive(nonce.toString()))
        put("issued_at", JsonPrimitive(formatInstant(issuedAt)))
        put(SIGNATURE_FIELD, JsonNull)
    }

    private object Utf8Order : Comparator<String> {
        override fun compare(left: String, right: String): Int {
            val a = left.toByteArray()
            val b = right.toByteArray()
            for (i in 0 until minOf(a.size, b.size)) {
                val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (diff != 0) return diff
            }
            return a.size - b.size
        }
    }

    private fun parseObject(body: ByteArray): JsonObject {
        val element: JsonElement = try {
            json.parseToJsonElement(body.decodeToString())
        } catch (e: Exception) {
            throw IllegalArgumentException("reactor body is not valid JSON", e)
        }
        return element as? JsonObject
            ?: throw IllegalArgumentException("reactor body is not a JSON object")
    }

    private fun encode(value: JsonObject): ByteArray =
        json.encodeToString(JsonObject.serializer(), value).toByteArray()

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray = try {
        Mac.getInstance(HMAC_ALGORITHM).apply { init(SecretKeySpec(key, HMAC_ALGORITHM)) }
            .doFinal(message)
    } catch (e: Exception) {
        // An empty or otherwise unusable key. Fail loudly rather than sign with
        // something that is not the tenant's subkey.
        throw IllegalArgumentException("HMAC-SHA256 could not be initialized with this key", e)
    }

    private fun tenantIdBytes(tenantId: UUID): ByteArray =
        java.nio.ByteBuffer.allocate(16)
            .putLong(tenantId.mostSignificantBits)
            .putLong(tenantId.leastSignificantBits)
            .array()

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        return try {
            ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: NumberFormatException) {
            null
        }
    }

    /** Parses a UUID, returning `null` rather than throwing. */
    internal fun parseUuid(raw: String?): UUID? = raw?.let {
        try {
            UUID.fromString(it)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Reads a field as a JSON string, or `null` when absent or not a string. */
    internal fun stringField(obj: JsonObject, field: String): String? =
        (obj[field] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** Reads a field as a JSON integer, or `null` when absent or not an integer. */
    internal fun intField(obj: JsonObject, field: String): Int? =
        (obj[field] as? JsonPrimitive)?.takeIf { !it.isString }?.jsonPrimitive?.content?.toIntOrNull()
}
