package io.axiam.sdk.account

import io.axiam.sdk.Sensitive
import kotlinx.serialization.json.JsonObject
import java.util.UUID

/**
 * A TOTP factor offered but not yet active (CONTRACT.md §25.1).
 *
 * **Both halves are [Sensitive], and the second one is why.** The `otpauth://`
 * URI *contains* the secret: wrapping the bare secret and then logging the URI
 * leaks exactly the same bytes (§25.3).
 *
 * @property secretBase32 the shared TOTP secret. Anyone holding it can generate
 *   valid codes for this account indefinitely.
 * @property totpUri `otpauth://totp/…?secret=<secretBase32>` — the string an
 *   authenticator app scans out of a QR code.
 */
data class MfaEnrollment(
    val secretBase32: Sensitive<String>,
    val totpUri: Sensitive<String>,
)

/**
 * The OPAQUE policy for the account a reset token belongs to (CONTRACT.md
 * §25.1).
 *
 * @property opaque the tenant's §23 parameters when it has OPAQUE enabled, and
 *   `null` when it does not — in which case the plaintext path is allowed. The
 *   block is forwarded to the §23 helpers untouched: this SDK does not model,
 *   validate or re-encode it.
 */
data class PasswordResetContext(
    val opaque: JsonObject? = null,
)

/**
 * Arguments to `requestPasswordReset` (CONTRACT.md §25.1).
 *
 * The workspace fields are all optional: unset, they are filled from the
 * client's own configured identity, which is what almost every caller wants.
 *
 * @property email the address to send the reset mail to
 * @property orgSlug an organization override
 * @property tenantId a tenant override, in UUID form
 * @property tenantSlug a tenant override, in slug form
 */
data class PasswordResetRequest(
    val email: String,
    val orgSlug: String? = null,
    val tenantId: UUID? = null,
    val tenantSlug: String? = null,
)

/**
 * Arguments to `confirmPasswordReset` (CONTRACT.md §25.1).
 *
 * @property token the single-use token from the reset mail
 * @property newPassword the replacement password
 * @property tenantId the tenant the account belongs to. A **body** field: this
 *   is not an `/oauth2/...` endpoint, so §12.1 rule 2's query-parameter
 *   convention does not reach it.
 * @property opaque the §23 registration record, for a tenant whose
 *   `passwordResetContext` reported an OPAQUE policy. `null` on the plaintext
 *   path.
 */
data class PasswordResetConfirmation(
    val token: Sensitive<String>,
    val newPassword: Sensitive<String>,
    val tenantId: UUID,
    val opaque: JsonObject? = null,
)
