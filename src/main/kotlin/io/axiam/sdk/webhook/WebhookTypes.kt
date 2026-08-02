package io.axiam.sdk.webhook

import java.time.Instant
import java.util.Arrays

/**
 * A successfully-verified webhook delivery (CONTRACT.md §13.2).
 *
 * [eventType] and [deliveryId] come from the `X-Axiam-Event` /
 * `X-Axiam-Delivery` headers respectively — NEITHER is covered by the HMAC,
 * so they are informational only, echoed back for convenience; only
 * [timestamp] (from the signed `t=` field) and [body] are what the signature
 * actually attests to. [deliveryId] is the at-least-once dedup key: a retried
 * delivery replays a validly-signed body inside the freshness window, so a
 * receiver that must not double-process an event should keep a short-lived
 * seen-set of delivery ids (CONTRACT.md §13.3 rule 7).
 *
 * A plain `class` (not `data class`): [ByteArray]'s structural equality
 * requires [Arrays.equals]/`contentEquals`, which a synthesized data-class
 * `equals`/`hashCode` would get wrong (array reference identity instead).
 *
 * @property eventType  the `X-Axiam-Event` header value, or `null` if not supplied
 * @property deliveryId the `X-Axiam-Delivery` header value, or `null` if not supplied
 * @property timestamp  the signed `t=` timestamp, as an [Instant]
 * @property body       the exact raw request body bytes that were verified
 */
class WebhookEvent(
    val eventType: String?,
    val deliveryId: String?,
    val timestamp: Instant,
    val body: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WebhookEvent) return false
        return eventType == other.eventType &&
            deliveryId == other.deliveryId &&
            timestamp == other.timestamp &&
            body.contentEquals(other.body)
    }

    override fun hashCode(): Int =
        Arrays.hashCode(intArrayOf(eventType.hashCode(), deliveryId.hashCode(), timestamp.hashCode(), body.contentHashCode()))

    override fun toString(): String =
        "WebhookEvent(eventType=$eventType, deliveryId=$deliveryId, timestamp=$timestamp, body=<${body.size} bytes>)"
}

/**
 * Outcome of [AxiamWebhooks.verify] (CONTRACT.md §13.3 rule 6): a typed
 * sealed result rather than a thrown exception, so a caller's `when` is
 * exhaustive and no failure path can accidentally surface the expected
 * signature or the secret in a message/stack trace.
 */
sealed class WebhookVerifyResult {

    /** The signature verified and the timestamp was within tolerance. */
    data class Success(val event: WebhookEvent) : WebhookVerifyResult()

    /** Verification failed; see [WebhookVerifyError] for the reason taxonomy. */
    data class Failure(val error: WebhookVerifyError) : WebhookVerifyResult()
}

/**
 * Why [AxiamWebhooks.verify] rejected a delivery (CONTRACT.md §13.3). Every
 * [message] is a fixed, generic string — never the computed/expected MAC, the
 * secret, or any other secret material (CONTRACT.md §13.3 rule 6).
 */
sealed class WebhookVerifyError(val message: String) {

    /**
     * `X-Axiam-Signature` could not be parsed: it did not contain exactly one
     * `t=` (or `t` was not a valid integer), it contained no `v1=` entry at
     * all, or a supplied `X-Axiam-Timestamp` header disagreed with `t=`.
     */
    object MalformedHeader : WebhookVerifyError(
        "webhook signature header is malformed: expected exactly one numeric \"t=\" and at least one \"v1=\"",
    )

    /** None of the supplied `v1` values matched the recomputed HMAC-SHA256. */
    object SignatureMismatch : WebhookVerifyError("webhook signature does not match the expected value")

    /** `t=` is older than the freshness tolerance allows. */
    object StaleTimestamp : WebhookVerifyError("webhook timestamp is older than the freshness tolerance")

    /** `t=` is further in the future than the freshness tolerance allows. */
    object FutureTimestamp : WebhookVerifyError("webhook timestamp is further in the future than the freshness tolerance")

    override fun toString(): String = message
}
