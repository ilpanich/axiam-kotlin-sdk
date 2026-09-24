package io.axiam.sdk.management

/**
 * What reconciling a [ManagementManifest] would do (CONTRACT.md §27.6).
 *
 * Produced by `manifest().plan(...)`, which issues **reads and nothing else**
 * — so it is safe to run against production to find out what an apply would do.
 *
 * @property actions every step, including the ones that would change nothing
 */
data class ManagementPlan(val actions: List<PlannedAction>) {

    /** The subset of [actions] that would actually write. */
    val changes: List<PlannedAction> get() = actions.filter { it.change != Change.NO_CHANGE }

    /** `true` when the tenant already matches the manifest. */
    val isConverged: Boolean get() = changes.isEmpty()

    /** What a step would do to the thing it names. */
    enum class Change {
        /** The entity does not exist and would be created. */
        CREATE,

        /** The entity exists but differs, and would be updated in place. */
        UPDATE,

        /** The entity already matches. Reported, so a converged plan is still legible. */
        NO_CHANGE,
    }

    /** What kind of thing a step is about. */
    enum class Target {
        /** A resource in the hierarchy. */
        RESOURCE,

        /** A scope beneath a resource. */
        SCOPE,

        /** A permission. */
        PERMISSION,

        /** A role. */
        ROLE,

        /** A permission granted to a role. */
        ROLE_GRANT,

        /** A group. */
        GROUP,

        /** A role held by a group. */
        GROUP_ROLE,

        /** A user. */
        USER,

        /** A role held directly by a user. */
        USER_ROLE,

        /** A user's membership of a group. */
        GROUP_MEMBER,

        /** A service account (CONTRACT.md §27.6.1 item 3, contract 1.51). */
        SERVICE_ACCOUNT,

        /** A role held directly by a service account. */
        SERVICE_ACCOUNT_ROLE,
    }

    /**
     * One step of a plan.
     *
     * @property change what would happen
     * @property target what kind of thing it is about
     * @property key the manifest-local key of the entry it came from
     * @property summary a one-line description, for printing a plan to a human
     */
    data class PlannedAction(
        val change: Change,
        val target: Target,
        val key: String,
        val summary: String,
    )
}

/**
 * What reconciling a [ManagementManifest] actually did (CONTRACT.md §27.6).
 *
 * §27.6 rule 7: `apply` stops at the **first** failure and does **not** roll
 * back. Everything before the failure stands; everything after it is reported
 * as [Status.NOT_ATTEMPTED]. That is deliberate — an automatic rollback would
 * be a second unreviewed batch of writes issued at exactly the moment the
 * tenant is in a state nobody has looked at.
 *
 * @property steps every step, in the order it was attempted
 */
data class ApplyReport(val steps: List<AppliedStep>) {

    /** The failing step, if there was one — [Status.FAILED] or [Status.BINDING_UPDATE_FAILED]. */
    val failure: AppliedStep?
        get() = steps.firstOrNull {
            it.outcome.status == Status.FAILED || it.outcome.status == Status.BINDING_UPDATE_FAILED
        }

    /** `true` when every step ran without failing. */
    val isComplete: Boolean get() = failure == null

    /** How many steps actually wrote something. */
    val changedCount: Int
        get() = steps.count {
            it.outcome.status == Status.CREATED || it.outcome.status == Status.UPDATED ||
                it.outcome.status == Status.CREATED_SERVICE_ACCOUNT
        }

    /**
     * The [Target.SERVICE_ACCOUNT] steps that created an account, paired with
     * the server's one-time response — `client_secret` included (§27.5
     * rule 5, §27.6.1 item 3, contract 1.51).
     *
     * Present even when a LATER step of the same `apply` failed: `create` is
     * the only moment the plaintext secret exists, and `apply` never rotates
     * to reconcile, so dropping it here would mean the caller's only chance
     * to read it was lost to an unrelated failure three steps later.
     */
    fun createdServiceAccounts():
        Sequence<Pair<ManagementPlan.PlannedAction, io.axiam.sdk.management.models.ServiceAccountCreatedResponse>> =
        steps.asSequence().mapNotNull { step ->
            val created = step.outcome.createdServiceAccount
            if (created != null) step.action to created else null
        }

    /** What became of one step. */
    enum class Status {
        /** The entity did not exist and was created. */
        CREATED,

        /**
         * A [Target.SERVICE_ACCOUNT] step that created an account — see
         * [ApplyReport.createdServiceAccounts]. A [Status.CREATED] cousin, kept
         * distinct because it carries the one-time secret rather than nothing.
         */
        CREATED_SERVICE_ACCOUNT,

        /** The entity existed, differed, and was updated in place. */
        UPDATED,

        /** The entity already matched; nothing was sent. */
        UNCHANGED,

        /** The step was attempted and the server refused it. */
        FAILED,

        /**
         * A role-binding `Update` — unassign then assign (§27.6.1 item 2) —
         * whose assign half failed. The unassign already happened, so the
         * previous binding was re-assigned (see [StepOutcome.restoreSucceeded]):
         * this is NOT the same as [FAILED], which never removed anything the
         * step meant to restore.
         */
        BINDING_UPDATE_FAILED,

        /** An earlier step failed, so this one was never sent (§27.6 rule 7). */
        NOT_ATTEMPTED,
    }

    /**
     * What became of one step, and why.
     *
     * @property status what happened
     * @property message the server's explanation, present on [Status.FAILED]
     *   and [Status.BINDING_UPDATE_FAILED]
     * @property restoreSucceeded on [Status.BINDING_UPDATE_FAILED] only:
     *   whether re-assigning the previous binding (after the new assign
     *   failed) itself succeeded. `null` for every other status.
     * @property createdServiceAccount on [Status.CREATED_SERVICE_ACCOUNT]
     *   only: the server's one-time response, secret included. `null` for
     *   every other status.
     */
    data class StepOutcome(
        val status: Status,
        val message: String? = null,
        val restoreSucceeded: Boolean? = null,
        val createdServiceAccount: io.axiam.sdk.management.models.ServiceAccountCreatedResponse? = null,
    )

    /**
     * One planned step, paired with what became of it.
     *
     * @property action the step as it was planned
     * @property outcome what happened when it ran
     */
    data class AppliedStep(val action: ManagementPlan.PlannedAction, val outcome: StepOutcome)
}
