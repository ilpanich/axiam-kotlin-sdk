package io.axiam.sdk.webauthn

import io.axiam.sdk.Sensitive
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.util.UUID

/**
 * A started ceremony: the server's options plus the token binding a response to
 * them (CONTRACT.md §24.1).
 *
 * @property challenge the server's options, exactly as they arrived — a
 *   `{"publicKey": {…}}` object carrying base64url buffers. Hand it to the
 *   authenticator **unchanged** (§24.0), or use [requestJson] for the string a
 *   platform API takes.
 * @property stateToken binds the authenticator's answer to this challenge. A
 *   bearer credential for the length of the ceremony — one that leaks inside
 *   that window is a ceremony an attacker can try to complete — so it is
 *   [Sensitive] (§24.5). It is **opaque**: this SDK never decodes it, and
 *   neither should a caller.
 */
data class WebauthnChallenge(
    val challenge: JsonObject,
    val stateToken: Sensitive<String>,
) {
    /**
     * The challenge in the JSON form every platform authenticator API takes
     * (§24.6a rule 1).
     *
     * This is the string an Android app passes to
     * `CreatePublicKeyCredentialRequest` or `GetPublicKeyCredentialOption`, and
     * the value a browser passes to
     * `PublicKeyCredential.parseCreationOptionsFromJSON()`. It is the inner
     * options object: the `publicKey` wrapper belongs to the DOM's
     * `CredentialCreationOptions`, and the platform JSON APIs do not want it.
     *
     * Pure local computation, no I/O. Nothing is defaulted, dropped or
     * reordered on the way through (§24.0).
     */
    val requestJson: String
        get() = Json.encodeToString(JsonObject.serializer(), challenge["publicKey"] as? JsonObject ?: challenge)
}

/**
 * A credential the user just enrolled — the `201` body of `register/finish`
 * (CONTRACT.md §24.1).
 *
 * @property id             this credential's AXIAM id, for a later delete
 * @property credentialId   the authenticator's own base64url credential id
 * @property name           the label it was stored under
 * @property credentialType `"passkey"` or `"security_key"`, as the server classified it
 * @property createdAt      RFC 3339 timestamp
 * @property lastUsedAt     RFC 3339 timestamp, or `null` for a credential never used
 */
data class WebauthnCredential(
    val id: UUID,
    val credentialId: String,
    val name: String,
    val credentialType: String,
    val createdAt: String,
    val lastUsedAt: String? = null,
)

/**
 * A completed authentication ceremony (CONTRACT.md §24.3).
 *
 * The tokens are also adopted by the client that produced this value — the
 * server sets the `axiam_access` / `axiam_refresh` / `axiam_csrf` cookie triple
 * alongside them — so a caller who only wants to be signed in can ignore every
 * property here.
 *
 * @property accessToken the new access token (§24.5)
 * @property refreshToken the new refresh token (§24.5)
 * @property sessionId the session this ceremony established
 * @property expiresIn the access token's lifetime in seconds
 */
data class WebauthnLoginResult(
    val accessToken: Sensitive<String>,
    val refreshToken: Sensitive<String>,
    val sessionId: UUID,
    val expiresIn: Long,
)

/**
 * The workspace a usernameless ceremony runs in (CONTRACT.md §24.1).
 *
 * `discoverable/start` is the one WebAuthn endpoint that carries the workspace
 * explicitly, because a usernameless ceremony has no prior step to have minted
 * a token that names it. Unlike the five `/oauth2/...` operations of §12.1
 * rule 2 it **accepts slugs**, so a slug-only client can run it.
 *
 * Pass `null` to `webauthnDiscoverableStart` to have it filled from the
 * client's own configured identity, which is what almost every caller wants.
 */
data class WebauthnWorkspace(
    val orgId: UUID? = null,
    val orgSlug: String? = null,
    val tenantId: UUID? = null,
    val tenantSlug: String? = null,
)

/**
 * A ceremony failure a caller can say something useful about (CONTRACT.md
 * §24.6b rule 5).
 *
 * This SDK ships no linked-API helper — the JVM has no authenticator and
 * §24.6b rule 2 forbids emulating one — but the classification is still
 * required of it, because an Android app catching a `CreateCredentialException`
 * has the same five outcomes and the same reason to want one vocabulary for
 * them. [classify] takes either the platform's error name or the throwable
 * itself.
 *
 * @property message user-facing copy, safe to show. The [CANCELLED] string
 *   deliberately does not accuse anyone of cancelling: the same classification
 *   covers a silent timeout, and the spec will not say which happened.
 */
enum class WebauthnFailure(val message: String) {

    /**
     * Covers **both** an explicit refusal and a silent timeout.
     *
     * The WebAuthn spec deliberately refuses to distinguish them, because
     * telling a website which one happened leaks whether an authenticator was
     * present. It must not be recovered by timing the call.
     */
    CANCELLED("The request was cancelled or timed out. You can try again."),

    /**
     * The authenticator already holds a credential for this account and refused
     * to silently mint a second — the exclusion list working, not a failure.
     * The only classification whose remedy is "use a different device".
     */
    ALREADY_REGISTERED(
        "This device is already registered on your account. Try a different device, " +
            "or remove the existing one first.",
    ),

    /** An explicitly aborted ceremony. */
    TIMEOUT("The request timed out before it completed. Please try again."),

    /** This device or browser cannot run the ceremony. */
    UNSUPPORTED(
        "This browser or device cannot be used for passkeys. Try a different browser, " +
            "or use another sign-in method.",
    ),

    /** Everything else. */
    UNKNOWN("Something went wrong. Please try again."),
    ;

    companion object {
        private val BY_NAME: Map<String, WebauthnFailure> = mapOf(
            "notallowederror" to CANCELLED,
            "canceled" to CANCELLED,
            "cancelled" to CANCELLED,
            "invalidstateerror" to ALREADY_REGISTERED,
            "aborterror" to TIMEOUT,
            "timeout" to TIMEOUT,
            "notsupportederror" to UNSUPPORTED,
            "securityerror" to UNSUPPORTED,
        )

        /**
         * Map a platform ceremony error name to its canonical classification.
         *
         * Every platform reports a ceremony failure as one opaque type whose
         * only machine-readable part is a name, so a handset can relay just
         * that name and a JVM service can turn it into the same five outcomes a
         * browser would see. Anything unrecognised is [UNKNOWN] rather than a
         * throw — a classifier that can fail is one more thing for an error
         * handler to handle.
         */
        @JvmStatic
        fun classify(name: String?): WebauthnFailure =
            BY_NAME[name?.trim()?.lowercase()] ?: UNKNOWN

        /**
         * Map a caught platform exception to its canonical classification.
         *
         * Written for Android: Credential Manager reports every ceremony
         * failure as a `CreateCredentialException` /
         * `GetCredentialException` subclass whose DOM error name is the only
         * machine-readable part, and reaching that name would mean this
         * artifact linking `androidx.credentials`. It does not — the class's
         * own simple name is checked first (`CreatePublicKeyCredentialDomException`
         * and friends do not carry it, so this rarely hits), then the message,
         * which is where the DOM name actually appears.
         *
         * Never throws, and never rethrows: a classifier is called from a catch
         * block, which is the worst possible place for a second exception.
         */
        @JvmStatic
        fun classify(error: Throwable?): WebauthnFailure {
            if (error == null) return UNKNOWN
            val haystack = buildString {
                append(error::class.simpleName ?: "")
                append(' ')
                append(error.message ?: "")
            }.lowercase()
            // Longest names first: "notallowederror" must not be shadowed by a
            // shorter key that happens to be a substring of the same message.
            return BY_NAME.entries
                .sortedByDescending { it.key.length }
                .firstOrNull { haystack.contains(it.key) }
                ?.value
                ?: UNKNOWN
        }
    }
}
