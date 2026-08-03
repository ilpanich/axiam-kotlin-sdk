package io.axiam.sdk.webhook

import io.axiam.sdk.Sensitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * T-145 — [AxiamWebhooks.verify] coverage (CONTRACT.md §13.4's required test
 * list, plus the cross-SDK pin vector).
 */
class AxiamWebhooksTest {

    private val secret = "whsec_test_0123456789abcdef"
    private val body = """{"event":"user.created","id":"01"}""".toByteArray(Charsets.UTF_8)
    private val fixedNow = Instant.ofEpochSecond(1_785_700_000L)

    /** Computes `v1` exactly as the server does — the SDK-under-test's algorithm is never reused here. */
    private fun referenceHmacHex(secret: String, timestamp: Long, body: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val signed = "$timestamp.".toByteArray(Charsets.US_ASCII) + body
        val digest = mac.doFinal(signed)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) sb.append(String.format("%02x", b))
        return sb.toString()
    }

    private fun header(timestamp: Long, hex: String): String = "t=$timestamp,v1=$hex"

    // ---- 1. Valid-and-fresh -------------------------------------------------

    @Test
    fun `valid signature and fresh timestamp is accepted`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            eventHeader = "user.created",
            deliveryHeader = "delivery-1",
            now = fixedNow,
        )
        require(result is WebhookVerifyResult.Success)
        assertEquals("user.created", result.event.eventType)
        assertEquals("delivery-1", result.event.deliveryId)
        assertEquals(Instant.ofEpochSecond(ts), result.event.timestamp)
        assertTrue(result.event.body.contentEquals(body))
    }

    // ---- 2. Tampered body -----------------------------------------------------

    @Test
    fun `a single flipped body byte is rejected`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val tampered = body.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()

        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = tampered,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.SignatureMismatch), result)
    }

    // ---- 3. Wrong secret --------------------------------------------------------

    @Test
    fun `a wrong secret is rejected`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of("whsec_completely_different_secret"),
            signatureHeader = header(ts, v1),
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.SignatureMismatch), result)
    }

    // ---- 4. Stale timestamp -------------------------------------------------------

    @Test
    fun `a timestamp older than the tolerance is rejected`() {
        val ts = fixedNow.epochSecond - 301
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.StaleTimestamp), result)
    }

    @Test
    fun `a timestamp exactly at the tolerance boundary is accepted`() {
        val ts = fixedNow.epochSecond - 300
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            now = fixedNow,
        )
        assertTrue(result is WebhookVerifyResult.Success)
    }

    // ---- 5. Future timestamp beyond tolerance --------------------------------------

    @Test
    fun `a timestamp further in the future than the tolerance is rejected`() {
        val ts = fixedNow.epochSecond + 301
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.FutureTimestamp), result)
    }

    @Test
    fun `a custom tolerance is honoured`() {
        val ts = fixedNow.epochSecond - 30
        val v1 = referenceHmacHex(secret, ts, body)
        val rejected = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            tolerance = Duration.ofSeconds(10),
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.StaleTimestamp), rejected)

        val accepted = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            tolerance = Duration.ofSeconds(60),
            now = fixedNow,
        )
        assertTrue(accepted is WebhookVerifyResult.Success)
    }

    // ---- 6. Malformed header ---------------------------------------------------------

    @Test
    fun `a header with no v1 is rejected`() {
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=${fixedNow.epochSecond}",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `a non-numeric t is rejected`() {
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=not-a-number,v1=deadbeef",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `an empty header is rejected`() {
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `a header with no t is rejected`() {
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "v1=deadbeef",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `a header with two conflicting t entries is rejected`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=$ts,t=${ts + 1},v1=$v1",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `an X-Axiam-Timestamp header that disagrees with t= is rejected`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            timestampHeader = (ts + 5).toString(),
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `an X-Axiam-Timestamp header that agrees with t= is accepted`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, v1),
            body = body,
            timestampHeader = ts.toString(),
            now = fixedNow,
        )
        assertTrue(result is WebhookVerifyResult.Success)
    }

    @Test
    fun `a non-hex v1 value fails closed rather than throwing`() {
        val ts = fixedNow.epochSecond
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=$ts,v1=not-hex-at-all",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.SignatureMismatch), result)
    }

    @Test
    fun `unknown scheme keys are ignored for forward compatibility`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=$ts,v2=some-future-scheme,v1=$v1",
            body = body,
            now = fixedNow,
        )
        assertTrue(result is WebhookVerifyResult.Success)
    }

    @Test
    fun `a second v1 candidate is checked when the first does not match (key rotation)`() {
        val ts = fixedNow.epochSecond
        val v1 = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=$ts,v1=0000000000000000000000000000000000000000000000000000000000000000,v1=$v1",
            body = body,
            now = fixedNow,
        )
        assertTrue(result is WebhookVerifyResult.Success)
    }

    // ---- 7. Cross-SDK pin vector -------------------------------------------------------

    @Test
    fun `the shared cross-SDK fixture vector verifies`() {
        val ts = 1_785_700_000L
        val fixtureBody = """{"event":"user.created","id":"01JQ0000000000000000000000"}""".toByteArray(Charsets.UTF_8)
        val fixtureSecret = "whsec_test_0123456789abcdef"
        val v1 = referenceHmacHex(fixtureSecret, ts, fixtureBody)

        val accepted = AxiamWebhooks.verify(
            secret = Sensitive.of(fixtureSecret),
            signatureHeader = header(ts, v1),
            body = fixtureBody,
            now = Instant.ofEpochSecond(ts),
        )
        assertTrue(accepted is WebhookVerifyResult.Success)

        val tamperedBody = fixtureBody.copyOf().also { it[5] = (it[5].toInt() xor 0x20).toByte() }
        val rejected = AxiamWebhooks.verify(
            secret = Sensitive.of(fixtureSecret),
            signatureHeader = header(ts, v1),
            body = tamperedBody,
            now = Instant.ofEpochSecond(ts),
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.SignatureMismatch), rejected)
    }

    // ---- misc: never leak secret/expected MAC in an error ---------------------------

    @Test
    fun `error messages never contain the secret or the computed MAC`() {
        val ts = fixedNow.epochSecond
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, "0000000000000000000000000000000000000000000000000000000000000000"),
            body = body,
            now = fixedNow,
        )
        require(result is WebhookVerifyResult.Failure)
        assertFalse(result.error.message.contains(secret))
        val expected = referenceHmacHex(secret, ts, body)
        assertFalse(result.error.message.contains(expected))
    }

    // ---- WebhookEvent value semantics (§12.6.4) --------------------------------------
    //
    // WebhookEvent holds a ByteArray, which is exactly where a data-class-shaped
    // type goes wrong: the compiler-generated equals/hashCode would compare the
    // array by REFERENCE, so two events carrying identical bytes would compare
    // unequal and behave unpredictably in a set or as a map key. These are
    // hand-written for that reason, and were the largest untested surface left
    // in this package.

    private fun event(
        eventType: String? = "user.created",
        deliveryId: String? = "d-1",
        timestamp: Instant = fixedNow,
        body: ByteArray = "payload".toByteArray(Charsets.UTF_8),
    ) = WebhookEvent(eventType, deliveryId, timestamp, body)

    @Test
    fun `WebhookEvent equality compares the body by content, not by reference`() {
        val a = event(body = "same".toByteArray(Charsets.UTF_8))
        val b = event(body = "same".toByteArray(Charsets.UTF_8))

        assertTrue(a == b, "distinct arrays with equal content must compare equal")
        assertEquals(a.hashCode(), b.hashCode(), "equal values must share a hash code")
    }

    @Test
    fun `WebhookEvent is reflexive and rejects a foreign type`() {
        val a = event()
        assertTrue(a == a)
        assertFalse(a.equals("not an event"))
        assertFalse(a.equals(null))
    }

    @Test
    fun `WebhookEvent inequality is driven by every field`() {
        val base = event()
        assertFalse(base == event(eventType = "user.deleted"))
        assertFalse(base == event(deliveryId = "d-2"))
        assertFalse(base == event(timestamp = fixedNow.plusSeconds(1)))
        assertFalse(base == event(body = "different".toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun `WebhookEvent toString reports the body size rather than the body`() {
        val secretish = "super-secret-payload".toByteArray(Charsets.UTF_8)
        val rendered = event(body = secretish).toString()

        assertTrue(rendered.contains("user.created"))
        assertTrue(rendered.contains("<${secretish.size} bytes>"))
        assertFalse(
            rendered.contains("super-secret-payload"),
            "a delivery body may carry sensitive data and must not be rendered into a log line",
        )
    }

    @Test
    fun `WebhookVerifyError renders as its message`() {
        // The error is surfaced to integrators via toString in logs; pin that it
        // stays the human-readable message and never the enum-ish default.
        assertEquals(
            WebhookVerifyError.MalformedHeader.message,
            WebhookVerifyError.MalformedHeader.toString(),
        )
        assertEquals(
            WebhookVerifyError.FutureTimestamp.message,
            WebhookVerifyError.FutureTimestamp.toString(),
        )
    }

    // ---- header parsing: the remaining fail-closed branches --------------------------

    @Test
    fun `a header carrying two t values is refused rather than picking one`() {
        val ts = fixedNow.epochSecond
        val mac = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=$ts,t=$ts,v1=$mac",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `a non-numeric t is refused`() {
        val mac = referenceHmacHex(secret, fixedNow.epochSecond, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=not-a-number,v1=$mac",
            body = body,
            now = fixedNow,
        )
        assertEquals(WebhookVerifyResult.Failure(WebhookVerifyError.MalformedHeader), result)
    }

    @Test
    fun `an odd-length v1 is refused rather than decoded short`() {
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = "t=${fixedNow.epochSecond},v1=abc",
            body = body,
            now = fixedNow,
        )
        require(result is WebhookVerifyResult.Failure)
        assertTrue(
            result.error == WebhookVerifyError.MalformedHeader ||
                result.error == WebhookVerifyError.SignatureMismatch,
        )
    }

    @Test
    fun `verify falls back to the system clock when no now is supplied`() {
        // Exercises the default-argument path: a timestamp of "right now" must
        // verify without the test injecting a clock.
        val ts = Instant.now().epochSecond
        val mac = referenceHmacHex(secret, ts, body)
        val result = AxiamWebhooks.verify(
            secret = Sensitive.of(secret),
            signatureHeader = header(ts, mac),
            body = body,
        )
        assertTrue(result is WebhookVerifyResult.Success)
    }
}

