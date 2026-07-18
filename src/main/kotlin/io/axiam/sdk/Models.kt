package io.axiam.sdk

/**
 * Authenticated user identity, injected into the request context by the §10
 * guard and returned as part of a completed [LoginResult].
 *
 * @property userId   the authenticated user's id (the token `sub` claim)
 * @property tenantId the tenant the user authenticated into
 * @property roles    the user's roles within [tenantId] (derived from the token `scope` claim)
 */
data class AxiamUser(
    val userId: String,
    val tenantId: String,
    val roles: List<String>,
)

/**
 * Outcome of [AxiamClient.login]/[AxiamClient.verifyMfa] (CONTRACT.md §1).
 *
 * An MFA challenge is an expected outcome represented as a flag, never thrown:
 * callers MUST check [mfaRequired] before assuming a session was established.
 *
 * @property mfaRequired    `true` when the server returned an MFA challenge (HTTP 202)
 * @property challengeToken the sensitive MFA challenge token to pass to
 *                          [AxiamClient.verifyMfa]; present only when [mfaRequired]
 * @property user           the authenticated user; present only on a completed login
 */
data class LoginResult(
    val mfaRequired: Boolean,
    val challengeToken: Sensitive<String>? = null,
    val user: AxiamUser? = null,
)

/**
 * A single authorization check (CONTRACT.md §1). Argument order is always
 * `(action, resource[, scope])`.
 *
 * @property action     the action being checked
 * @property resourceId the resource the action is checked against
 * @property scope      an optional sub-resource scope qualifier, or `null`
 */
data class AccessCheck(
    val action: String,
    val resourceId: String,
    val scope: String? = null,
)

/**
 * The outcome of a single authorization check.
 *
 * @property allowed whether the checked action is permitted
 * @property reason  a human-readable deny reason, or `null`
 */
data class AccessResult(
    val allowed: Boolean,
    val reason: String? = null,
)
