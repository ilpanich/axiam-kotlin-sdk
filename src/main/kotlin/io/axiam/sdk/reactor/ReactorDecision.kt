package io.axiam.sdk.reactor

/**
 * What a handler decided about one event (CONTRACT.md §22.4).
 *
 * A **sealed** hierarchy of three answers. Three of §22.4's rules are encoded
 * here structurally rather than by documentation, because each is a rule an
 * implementation gets wrong by being permissive:
 *
 * 1. **`allow` and `patch` are mutually exclusive.** There is no way to attach a
 *    patch to [Allow] — a mutation is a [Mutate], which serializes
 *    `decision: "mutate"`. A patch on an `allow` is a reply whose author and
 *    whose reader disagree about what will happen; the server refuses it rather
 *    than resolving it.
 * 2. **An empty mutation is malformed.** [Mutate] refuses to be constructed with
 *    an empty patch, so it cannot be put on the wire and rejected as
 *    `malformed_mutation` at the far end.
 * 3. **`require_mfa` rides on `allow`.** It is a flag on [Allow], not a fourth
 *    decision, and it is valid on `login.post_auth` only.
 *
 * What is *not* encoded here is patch filtering. A patch containing a forbidden
 * key is sent unfiltered and rejected by the server (§22.4 rule 1): dropping the
 * bad key would leave the reactor author believing a field was set when it was
 * silently discarded.
 *
 * @property wire the lowercase `decision` value this answer serializes as.
 */
public sealed class ReactorDecision(public val wire: String) {

    /**
     * Proceed unchanged.
     *
     * @property requireMfa when `true`, proceed only after step-up
     *   authentication. Valid on `login.post_auth` **only**; the server rejects
     *   it on any other event as `require_mfa_not_supported`, before it even
     *   looks at the decision. Serialized only when `true` — a reply carrying
     *   `"require_mfa": false` produces different canonical bytes and therefore
     *   a different MAC.
     */
    public data class Allow(val requireMfa: Boolean = false) : ReactorDecision("allow")

    /**
     * Refuse the underlying operation.
     *
     * @property reason audited on the server. A deny with no reason still denies
     *   — the reason is for the audit trail, not for the decision, and the
     *   server substitutes `"denied by reactor"` when it is absent. `null` omits
     *   the field from the signed bytes.
     */
    public data class Deny(val reason: String? = null) : ReactorDecision("deny")

    /**
     * Proceed, applying [patch]. Valid on a mutable event only; the server
     * rejects it as `not_mutable` on a veto-only one.
     *
     * @property patch a flat, non-empty map of string to string. There is no
     *   nested or typed patch in v1. Sent **unfiltered**: one forbidden key
     *   rejects the whole patch, including the fields that would have been fine.
     */
    public data class Mutate(val patch: Map<String, String>) : ReactorDecision("mutate") {
        init {
            require(patch.isNotEmpty()) {
                "a mutate decision needs a non-empty patch (CONTRACT.md §22.4: an empty patch " +
                    "is rejected as malformed_mutation); return ReactorDecision.allow() to change nothing"
            }
        }
    }

    public companion object {

        /** Proceed unchanged. */
        public fun allow(): ReactorDecision = Allow(requireMfa = false)

        /**
         * Proceed, but only after step-up authentication (`login.post_auth`
         * only).
         *
         * Step-up is **sticky** across the chain: once any reactor demands it, no
         * later reactor can clear it.
         */
        public fun allowRequiringStepUp(): ReactorDecision = Allow(requireMfa = true)

        /**
         * Refuse, with an audited reason.
         *
         * @param reason why, for the audit trail; may be `null`
         */
        public fun deny(reason: String? = null): ReactorDecision = Deny(reason)

        /**
         * Proceed with a mutation.
         *
         * @param patch a non-empty flat map of field name to string value
         * @throws IllegalArgumentException when [patch] is empty
         */
        public fun mutate(patch: Map<String, String>): ReactorDecision = Mutate(patch)
    }
}
