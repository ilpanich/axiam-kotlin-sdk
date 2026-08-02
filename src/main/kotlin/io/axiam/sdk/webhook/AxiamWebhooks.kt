package io.axiam.sdk.webhook

import io.axiam.sdk.Sensitive
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * T-145 — the SDK-side verifier for AXIAM's Stripe-style signed-timestamp
 * webhook scheme (CONTRACT.md §13, server implementation
 * `crates/axiam-api-rest/src/webhook.rs::compute_signature_v2`).
 *
 * On every delivery the server POSTs the event body with:
 *
 * | Header | Value |
 * |---|---|
 * | `X-Axiam-Timestamp` | unix seconds, decimal ASCII |
 * | `X-Axiam-Signature` | `t=<unix_seconds>,v1=<hex_lowercase_hmac>` |
 * | `X-Axiam-Event` | event type string |
 * | `X-Axiam-Delivery` | delivery UUID (at-least-once dedup key) |
 *
 * `v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`, hex-encoded
 * lowercase, where `<timestamp>` is byte-identical to the `t=` field.
 */
object AxiamWebhooks {

    /** Default freshness window (CONTRACT.md §13.2): ±300 seconds. */
    val DEFAULT_TOLERANCE: Duration = Duration.ofSeconds(300)

    private const val HMAC_ALGORITHM = "HmacSHA256"

    /**
     * Verifies a webhook delivery and, on success, returns the parsed
     * [WebhookEvent]. Never throws on a bad signature/timestamp/header — every
     * failure is a typed [WebhookVerifyResult.Failure] (CONTRACT.md §13.3
     * rule 6: fail closed and quiet, never surface the expected signature).
     *
     * **The body MUST be the exact raw bytes received off the wire.**
     * Re-serializing parsed JSON before calling this changes key order and/or
     * whitespace and breaks the MAC — always pass the untouched request body.
     *
     * @param secret the webhook's plaintext signing secret (CONTRACT.md §7 —
     *   wrapped [Sensitive] since this SDK has that type). Its raw UTF-8 bytes
     *   are the HMAC key.
     * @param signatureHeader the raw `X-Axiam-Signature` header value
     *   (`t=<unix>,v1=<hex>[,v1=<hex>...]`). This is the ONLY source of the
     *   timestamp used in the MAC — [timestampHeader], if supplied, is
     *   cross-checked against it but never substituted for it.
     * @param body the raw request body bytes, untouched.
     * @param timestampHeader optional `X-Axiam-Timestamp` header value. When
     *   supplied it MUST equal the `t=` value parsed from [signatureHeader];
     *   a mismatch is treated as a malformed header (CONTRACT.md §13.3 rule 2).
     * @param eventHeader optional `X-Axiam-Event` header value, echoed back on
     *   [WebhookEvent.eventType] on success — not covered by the MAC.
     * @param deliveryHeader optional `X-Axiam-Delivery` header value, echoed
     *   back on [WebhookEvent.deliveryId] on success — not covered by the
     *   MAC. Callers should dedup retried deliveries on this id (CONTRACT.md
     *   §13.3 rule 7): a retry replays a validly-signed body within the
     *   freshness window.
     * @param tolerance the two-sided freshness window; a `t` further than
     *   this from [now] in EITHER direction is rejected. Defaults to
     *   [DEFAULT_TOLERANCE] (300 seconds).
     * @param now the "current time" to check freshness against — an
     *   injection seam for deterministic tests; defaults to [Instant.now].
     */
    fun verify(
        secret: Sensitive<String>,
        signatureHeader: String,
        body: ByteArray,
        timestampHeader: String? = null,
        eventHeader: String? = null,
        deliveryHeader: String? = null,
        tolerance: Duration = DEFAULT_TOLERANCE,
        now: Instant = Instant.now(),
    ): WebhookVerifyResult {
        val parsed = parseSignatureHeader(signatureHeader)
            ?: return WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader)
        val (timestamp, candidateMacs) = parsed

        // §13.3 rule 2: X-Axiam-Timestamp is redundant with `t=` — only the
        // latter is covered by the MAC. When both are supplied they MUST agree.
        if (timestampHeader != null && timestampHeader.trim() != timestamp.toString()) {
            return WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader)
        }

        // §13.3 rule 4: recompute the MAC and compare EVERY supplied `v1`
        // candidate using a constant-time comparison over the DECODED bytes.
        // A hex-decode failure fails closed (counts as "no match"), never throws.
        val expectedMac = hmacSha256(secret.expose(), signedPayload(timestamp, body))
        val signatureValid = candidateMacs.any { hex ->
            val decoded = decodeHexOrNull(hex)
            decoded != null && decoded.size == expectedMac.size && MessageDigest.isEqual(decoded, expectedMac)
        }
        if (!signatureValid) {
            return WebhookVerifyResult.Failure(WebhookVerifyError.SignatureMismatch)
        }

        // §13.3 rule 5: freshness is two-sided — a future-dated `t` is
        // rejected exactly like a stale one (clock-skew abuse).
        val ageSec = now.epochSecond - timestamp
        val toleranceSec = tolerance.seconds
        if (ageSec > toleranceSec) {
            return WebhookVerifyResult.Failure(WebhookVerifyError.StaleTimestamp)
        }
        if (ageSec < -toleranceSec) {
            return WebhookVerifyResult.Failure(WebhookVerifyError.FutureTimestamp)
        }

        return WebhookVerifyResult.Success(
            WebhookEvent(
                eventType = eventHeader,
                deliveryId = deliveryHeader,
                timestamp = Instant.ofEpochSecond(timestamp),
                body = body,
            ),
        )
    }

    /** `"<timestamp>.<raw_body>"` as ASCII/UTF-8 bytes — exactly what the server signs. */
    private fun signedPayload(timestamp: Long, body: ByteArray): ByteArray =
        "$timestamp.".toByteArray(Charsets.US_ASCII) + body

    private fun hmacSha256(secret: String, message: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), HMAC_ALGORITHM))
        return mac.doFinal(message)
    }

    /**
     * Parses `t=<value>,v1=<value>[,v1=<value>...]` (CONTRACT.md §13.3 rule 3):
     * unknown keys/schemes are ignored for forward compatibility, but this
     * returns `null` (malformed) unless there is EXACTLY one `t` (a valid
     * non-negative integer) and AT LEAST one `v1` — a header with no `v1` is a
     * failure, never treated as "nothing to check, so allow it".
     */
    private fun parseSignatureHeader(header: String): Pair<Long, List<String>>? {
        var timestamp: Long? = null
        var timestampCount = 0
        val v1Candidates = mutableListOf<String>()

        for (rawPart in header.split(',')) {
            val part = rawPart.trim()
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            if (eq <= 0) continue
            val key = part.substring(0, eq).trim()
            val value = part.substring(eq + 1).trim()
            when (key) {
                "t" -> {
                    timestampCount++
                    timestamp = value.toLongOrNull()
                }
                "v1" -> if (value.isNotEmpty()) v1Candidates.add(value)
            }
        }

        if (timestampCount != 1) return null
        val t = timestamp ?: return null
        if (v1Candidates.isEmpty()) return null
        return t to v1Candidates
    }

    private fun decodeHexOrNull(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
