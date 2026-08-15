package io.axiam.sdk.reactor

import java.util.Locale

/**
 * What the server does when an interceptor produces no usable reply
 * (CONTRACT.md §22.8).
 *
 * "No usable reply" is one closed set and every member takes the same path:
 * timeout, transport failure, budget exhausted before this reactor was reached,
 * the per-tenant in-flight cap breached, and *every* §22.4 rejection — including
 * a valid signature carrying a forbidden patch field.
 *
 * This is a property of the *registration*, enforced by the server. It is
 * mirrored here so a caller can read and render it, and so
 * [ReactorEvents.defaultFailurePolicyFor] can compose the per-event defaults the
 * same way the server does.
 *
 * @property wire the lowercase form the AXIAM API uses.
 */
public enum class FailurePolicy(public val wire: String) {

    /** Proceed as if the reactor had replied `allow`. */
    FAIL_OPEN("fail_open"),

    /** Deny the underlying operation, with an audited reason naming the failure. */
    FAIL_CLOSED("fail_closed"),
    ;

    public companion object {
        /**
         * Parses a wire form back into a policy.
         *
         * @param raw the wire string, e.g. `"fail_closed"`; may be `null`
         * @return the matching policy, or `null` when [raw] names none
         */
        public fun fromWire(raw: String?): FailurePolicy? {
            val normalized = raw?.trim()?.lowercase(Locale.ROOT) ?: return null
            return entries.firstOrNull { it.wire == normalized }
        }
    }
}

/**
 * One hookable event: its name, what a reactor may change, and what happens when
 * the reactor does not answer (CONTRACT.md §22.5).
 *
 * Mirrors the server's `ReactorEventSpec` in
 * `crates/axiam-core/src/models/reactor.rs`, which is the single source of
 * truth. The live copy is served at `GET /api/v1/reactors/events`; this one is
 * here so a wire contract does not require a network call to be understood.
 *
 * @property name wire name, and the second half of the routing key
 *   (`<tenant_id>.<event>`).
 * @property interceptable whether an interceptor may register for this event at
 *   all; `false` means listen-only.
 * @property mutable whether an interceptor's reply may carry a `patch`.
 * @property mutableFields the complete allow-list: exact field names, or an
 *   entry ending in `.` denoting a namespace prefix (see [patchFieldAllowed]).
 * @property defaultFailurePolicy the policy a registration inherits when it
 *   names none.
 * @property description one line, as the admin UI shows it.
 */
public data class ReactorEventSpec(
    val name: String,
    val interceptable: Boolean,
    val mutable: Boolean,
    val mutableFields: List<String>,
    val defaultFailurePolicy: FailurePolicy,
    val description: String,
) {

    /**
     * Whether [field] may appear in a `patch` for this event.
     *
     * **The namespace-prefix rule.** An allow-list entry ending in `.` is a
     * namespace prefix, and it matches a field that starts with the entry *and
     * has at least one character after the dot*. So `ext.` admits
     * `ext.department` and `ext.a.b.c`, and refuses `ext.` itself (it names the
     * namespace, not a claim), `ext`, `extra`, `external_id` and
     * `evil.ext.department`.
     *
     * Everything else follows from that one rule: `token.pre_issue` cannot reach
     * `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `scp`, `azp`,
     * `act` or `client_id`, because none of them begins with `ext.`. A hook that
     * can rewrite `sub` is a hook that can mint a token for anyone, and a
     * *correctly signed* reply setting `sub` is refused exactly as a forged one
     * is.
     *
     * This is a read-only predicate. It exists so a reactor author can check a
     * key *before* writing the handler — it is **never** used to filter a
     * handler's patch down to the allowed subset, which §22.4 rule 1 forbids.
     *
     * @param field the patch key to test
     * @return `true` when the server would accept [field] in a patch for this event
     */
    public fun patchFieldAllowed(field: String): Boolean {
        if (!mutable) return false
        return mutableFields.any { allowed ->
            if (allowed.endsWith(".")) {
                field.length > allowed.length && field.startsWith(allowed)
            } else {
                field == allowed
            }
        }
    }
}

/**
 * The v1 reactor event registry (CONTRACT.md §22.5) — five interceptable events,
 * their mutable-field allow-lists, and their default failure policies.
 *
 * The live copy is served at `GET /api/v1/reactors/events` and is the one an
 * admin UI SHOULD read. This constant list is the same data, restated because a
 * wire contract that requires a network call to be understood is not a contract.
 *
 * **§22.7 hot-path exclusion.** `authz.check`, `authz.check_batch` and
 * `token.introspect` are not hookable and are absent from [REGISTRY] and from
 * every constant below. That absence is asserted by a test, not documented by a
 * comment. This SDK also offers no client-side interceptor, middleware hook or
 * callback presenting itself as the reactor equivalent for those operations. An
 * application that needs external input on an authorization decision writes a
 * **deny grant**, which the engine evaluates in the hot path at hot-path cost.
 */
public object ReactorEvents {

    /** Before an access token is minted. Mutable: the `ext.` claim namespace. */
    public const val TOKEN_PRE_ISSUE: String = "token.pre_issue"

    /**
     * After credentials verify, before a session is issued. Veto, or
     * `require_mfa` step-up.
     *
     * Covers *every* interactive sign-in — password authentication, SAML ACS and
     * the OIDC callback. MFA completion and the WebAuthn `authenticate/finish`
     * ceremony are not separate firings: both continue a login that was already
     * gated at its first step.
     *
     * The federated paths have no step-up branch, so a `require_mfa` answer on a
     * SAML or OIDC sign-in is **refused** (the sign-in fails) rather than
     * silently dropped. A reactor that needs step-up there must answer `deny` and
     * drive enrolment out of band.
     */
    public const val LOGIN_POST_AUTH: String = "login.post_auth"

    /** Before a user row is written. Mutable: `username`, `email`, `metadata.`. */
    public const val USER_PRE_CREATE: String = "user.pre_create"

    /** Before a user row is updated. Mutable: `username`, `email`, `metadata.`. */
    public const val USER_PRE_UPDATE: String = "user.pre_update"

    /** Before a role or permission is assigned (four-eyes workflows). Veto only. */
    public const val GRANT_PRE_ASSIGN: String = "grant.pre_assign"

    /**
     * Every hookable event in v1, in registry order.
     *
     * Note what is *not* here: see the §22.7 note on this object.
     */
    public val REGISTRY: List<ReactorEventSpec> = listOf(
        ReactorEventSpec(
            name = TOKEN_PRE_ISSUE,
            interceptable = true,
            mutable = true,
            mutableFields = listOf("ext."),
            defaultFailurePolicy = FailurePolicy.FAIL_OPEN,
            description = "Enrich or veto token issuance. May add claims under `ext.` only.",
        ),
        ReactorEventSpec(
            name = LOGIN_POST_AUTH,
            interceptable = true,
            mutable = false,
            mutableFields = emptyList(),
            defaultFailurePolicy = FailurePolicy.FAIL_CLOSED,
            description = "After credentials verify, before session issuance: veto or require step-up MFA.",
        ),
        ReactorEventSpec(
            name = USER_PRE_CREATE,
            interceptable = true,
            mutable = true,
            mutableFields = listOf("username", "email", "metadata."),
            defaultFailurePolicy = FailurePolicy.FAIL_CLOSED,
            description = "Validate or normalize a new user's profile fields.",
        ),
        ReactorEventSpec(
            name = USER_PRE_UPDATE,
            interceptable = true,
            mutable = true,
            mutableFields = listOf("username", "email", "metadata."),
            defaultFailurePolicy = FailurePolicy.FAIL_CLOSED,
            description = "Validate or normalize a profile update.",
        ),
        ReactorEventSpec(
            name = GRANT_PRE_ASSIGN,
            interceptable = true,
            mutable = false,
            mutableFields = emptyList(),
            defaultFailurePolicy = FailurePolicy.FAIL_CLOSED,
            description = "Veto a role or permission assignment (four-eyes workflows). Veto-only.",
        ),
    )

    /**
     * Looks an event up by wire name.
     *
     * @param name the event name, e.g. `token.pre_issue`; may be `null`
     * @return the spec, or `null` when [name] is not in the registry. An event
     *   outside the registry dispatches to nothing and resolves to `allow`
     *   server-side, which is what makes §22.7's hot-path exclusion structural
     *   rather than advisory.
     */
    public fun spec(name: String?): ReactorEventSpec? = REGISTRY.firstOrNull { it.name == name }

    /**
     * The `failure_policy` a registration should get when it names none: the
     * **strictest** default among the events it subscribes to (CONTRACT.md
     * §22.8).
     *
     * A reactor registered for both `token.pre_issue` (open) and
     * `login.post_auth` (closed) can veto a login, so it inherits `fail_closed` —
     * in either array order. Taking the first event's default would let the order
     * of a JSON array decide whether an unreachable fraud check passes.
     *
     * Unknown names are ignored here rather than defaulted: the server refuses
     * them at registration, and guessing a policy for an event that cannot exist
     * would only hide that refusal.
     *
     * @param events the registration's event names
     * @return [FailurePolicy.FAIL_CLOSED] when any named event defaults closed,
     *   [FailurePolicy.FAIL_OPEN] only when all of them default open
     */
    public fun defaultFailurePolicyFor(events: Collection<String>): FailurePolicy =
        if (events.any { spec(it)?.defaultFailurePolicy == FailurePolicy.FAIL_CLOSED }) {
            FailurePolicy.FAIL_CLOSED
        } else {
            FailurePolicy.FAIL_OPEN
        }
}
