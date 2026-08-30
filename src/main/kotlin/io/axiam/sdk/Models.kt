package io.axiam.sdk

import java.util.UUID

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
 * @property organizationLevel `true` when the account that just signed in is an
 *                          **organization-level** principal (§5.2) — one whose
 *                          record lives in its organization's reserved tenant,
 *                          so its global grants apply in every tenant of that
 *                          organization, and which can act on a different one by
 *                          sending a different `X-Axiam-Tenant` on the next
 *                          request. An ordinary tenant principal is a principal
 *                          of exactly one tenant and gets a `403` for the same
 *                          header change, so check this *before* offering a
 *                          tenant switch rather than discovering the answer from
 *                          a failed request. `false` against a server older than
 *                          contract 1.31, and `false` on the two pending
 *                          outcomes, where no principal has been established yet.
 *                          Since contract 1.35 that reach can be narrowed per
 *                          assignment, so this flag alone no longer decides what
 *                          to offer: consult [PrincipalScope.reachableTenantIds]
 *                          as well (§5.2.3 rule 3).
 * @property scope          where this principal lives and how far its roles
 *                          reach (§5.2.2, §5.2.3). `null` on the two pending
 *                          outcomes and against a server older than contract
 *                          1.34, which reports none of it.
 */
data class LoginResult(
    val mfaRequired: Boolean,
    val challengeToken: Sensitive<String>? = null,
    val user: AxiamUser? = null,
    val mfaSetupRequired: Boolean = false,
    val setupToken: Sensitive<String>? = null,
    val organizationLevel: Boolean = false,
    val scope: PrincipalScope? = null,
)

/**
 * Where the signed-in principal lives, and how far its roles reach — CONTRACT.md
 * §5.2.2 and §5.2.3.
 *
 * Grouped into one type rather than spread across [LoginResult]'s properties
 * because they are read together and grow together: §5.2.2 added three of these
 * and §5.2.3 a fourth, and a class that gains a property per contract revision is
 * one whose shape churns every time.
 *
 * Every property is nullable, and absent has a specific meaning in each case
 * rather than "unknown". A server older than contract 1.34 sends none of them, in
 * which case the whole scope is `null`.
 *
 * @property actingTenantId     the tenant a request **acts on** — what the
 *                              `X-Axiam-Tenant` header names. `null` when the
 *                              server does not report it.
 * @property principalTenantId  the tenant this principal's record **lives in**.
 *                              The same value as [actingTenantId] for every
 *                              ordinary principal; the two diverge only once an
 *                              organization-level principal selects another
 *                              tenant to act on. This is where the account's own
 *                              credentials belong, and what a §23 registration
 *                              record for *this* account must be sealed against —
 *                              see [AxiamClient.opaqueEnrollmentForSelf]. The
 *                              login reader fills this from [actingTenantId] when
 *                              the server omits it, which is exactly right there:
 *                              a server that cannot switch the acting tenant
 *                              cannot make the two differ, so absent means
 *                              *equal*, not unknown.
 * @property principalTenantSlug slug of [principalTenantId] — `"organization"` for
 *                              an organization-level principal; `null` when the
 *                              server omits it.
 * @property orgId              the caller's organization as a UUID (§5.2.2 rule
 *                              3). Read this rather than resolving a slug through
 *                              `GET /api/v1/organizations`, which is
 *                              `super-admin`-only and returns only the caller's
 *                              own organization.
 * @property reachableTenantIds the tenants this caller's roles reach, when they
 *                              are narrowed (§5.2.3). `null` means
 *                              **unrestricted**, which is both the common case and
 *                              the only thing a server older than contract 1.35
 *                              can mean. A present list is a deliberately narrowed
 *                              organization-level account: confine any tenant
 *                              switch to it, because naming anything outside is
 *                              refused at the header. An empty list arrives as
 *                              `null` for the same reason — it would read as
 *                              "reaches nothing", the opposite of what an omitted
 *                              field means here.
 */
data class PrincipalScope(
    val actingTenantId: UUID? = null,
    val principalTenantId: UUID? = null,
    val principalTenantSlug: String? = null,
    val orgId: UUID? = null,
    val reachableTenantIds: List<UUID>? = null,
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
