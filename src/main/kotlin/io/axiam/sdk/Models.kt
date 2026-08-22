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
 * Outcome of [AxiamClient.login]/[AxiamClient.verifyMfa] (CONTRACT.md §1, §25.2).
 *
 * **Three outcomes, not two.** An MFA challenge is an expected outcome
 * represented as a flag, never thrown; so is the §25.2 rule 1 case where the
 * tenant requires MFA and the account has none. Callers MUST check both
 * [mfaRequired] and [mfaSetupRequired] before assuming a session was
 * established — a client that branches only on the first reports a successful
 * login that has no session the moment a tenant turns required MFA on.
 *
 * The two new properties default, so every call site written before contract
 * 1.28 still compiles and still reads `false`.
 *
 * @property mfaRequired    `true` when the server returned an MFA challenge (HTTP 202)
 * @property challengeToken the sensitive MFA challenge token to pass to
 *                          [AxiamClient.verifyMfa]; present only when [mfaRequired]
 * @property user           the authenticated user; present only on a completed login
 * @property mfaSetupRequired `true` when the tenant requires MFA and this
 *                          account has no factor yet (HTTP 403 carrying
 *                          `mfa_setup_required`). Not a failure: the server
 *                          handed back a token to finish enrolment with.
 * @property setupToken     the sensitive setup token to pass to
 *                          [AxiamClient.mfaSetupEnroll] and
 *                          [AxiamClient.mfaSetupConfirm]; present only when
 *                          [mfaSetupRequired]. There is no session yet — this
 *                          token IS the credential for those two calls.
 */
data class LoginResult(
    val mfaRequired: Boolean,
    val challengeToken: Sensitive<String>? = null,
    val user: AxiamUser? = null,
    val mfaSetupRequired: Boolean = false,
    val setupToken: Sensitive<String>? = null,
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
 * @property allowed whether the checked action is permitted. **This property
 *   alone carries the outcome** — [reasonCode] explains it and never
 *   contradicts it
 * @property reason  a human-readable deny reason, or `null`
 * @property reasonCode machine-readable decision reason (CONTRACT.md §11
 *   rule 9, B1 deny-override): [ReasonCode.ALLOWED], [ReasonCode.NO_GRANT] or
 *   [ReasonCode.DENIED_BY_RULE].
 *
 *   **The two refusals mean opposite things to the person on the other end.**
 *   `no_grant` says *ask an admin for access*; `denied_by_rule` says *an admin
 *   has already decided*. An application that cannot tell them apart sends
 *   users to raise tickets that will be refused — which is why the contract
 *   forbids collapsing them into a bare `false`.
 *
 *   `null` when the server omits the field: a newer SDK against an older
 *   server treats it as absent, never as an error. An unrecognised value is
 *   surfaced verbatim and never changes [allowed], which is why this is a
 *   `String` rather than an enum — a code the SDK has never heard of still
 *   reaches the caller intact
 */
data class AccessResult(
    val allowed: Boolean,
    val reason: String? = null,
    val reasonCode: String? = null,
)

/**
 * The three `reason_code` values CONTRACT.md §11 rule 9 defines.
 *
 * Constants rather than an `enum class`, so an unrecognised server value is
 * still a valid [AccessResult.reasonCode] and reaches the caller — an enum
 * would force the SDK to drop it or throw on it.
 */
object ReasonCode {
    /** An allow grant matched and no deny did. */
    const val ALLOWED: String = "allowed"

    /** Nothing matched — default deny. *Ask an admin for access.* */
    const val NO_GRANT: String = "no_grant"

    /**
     * An explicit deny rule matched and overrode any allow. *An admin has
     * already decided.*
     */
    const val DENIED_BY_RULE: String = "denied_by_rule"
}
