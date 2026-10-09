package io.axiam.sdk

import org.junit.jupiter.api.Assertions.assertTrue

/**
 * Redaction assertions shared by the contract 1.58 suites.
 *
 * A failing assertion reports an OFFSET and a fixed label — never the secret,
 * a fragment of it, or the rendering it was found in: a redaction test that
 * printed what it caught would itself be the cleartext log it exists to
 * prevent.
 */
object Redaction {

    /** A fresh run-time secret: no credential literal appears in a test. */
    fun secret(prefix: String = "s"): String =
        prefix + java.util.UUID.randomUUID().toString().replace("-", "") +
            java.util.UUID.randomUUID().toString().replace("-", "").take(11)

    /**
     * Asserts that no 8-character substring of [secret] appears in [haystack].
     *
     * @param haystack the rendering under test
     * @param secret the value that must not appear
     * @param label a fixed description of the rendering, for the failure message
     */
    fun assertNoFragment(haystack: String, secret: String, label: String) {
        if (secret.length < 8) {
            assertTrue(!haystack.contains(secret), "$label: the secret appears in a rendering")
            return
        }
        for (i in 0..secret.length - 8) {
            assertTrue(
                !haystack.contains(secret.substring(i, i + 8)),
                "$label: an 8-character fragment of the secret (offset $i) appears in a rendering",
            )
        }
    }
}
