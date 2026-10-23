package io.axiam.sdk.management

import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.FieldError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.models.AddMemberRequest
import io.axiam.sdk.management.models.AssignRoleToGroupRequest
import io.axiam.sdk.management.models.AssignRoleToServiceAccountRequest
import io.axiam.sdk.management.models.AssignRoleToUserRequest
import io.axiam.sdk.management.models.CreateGroupRequest
import io.axiam.sdk.management.models.CreateNetworkReplyProfileRequest
import io.axiam.sdk.management.models.CreateNetworkSegmentRequest
import io.axiam.sdk.management.models.CreatePermissionRequest
import io.axiam.sdk.management.models.CreateResourceRequest
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateScopeRequest
import io.axiam.sdk.management.models.CreateServiceAccountRequest
import io.axiam.sdk.management.models.CreateUserRequest
import io.axiam.sdk.management.models.Group
import io.axiam.sdk.management.models.GrantPermissionRequest
import io.axiam.sdk.management.models.NetworkPolicyResponse
import io.axiam.sdk.management.models.NetworkReplyProfile
import io.axiam.sdk.management.models.NetworkReplyProfileInput
import io.axiam.sdk.management.models.NetworkSegmentResponse
import io.axiam.sdk.management.models.Permission
import io.axiam.sdk.management.models.PermissionEffect
import io.axiam.sdk.management.models.ReplaceNetworkPolicyRequest
import io.axiam.sdk.management.models.RadiusServiceType
import io.axiam.sdk.management.models.RadiusTerminationAction
import io.axiam.sdk.management.models.ReplaceNetworkReplyProfileRequest
import io.axiam.sdk.management.models.ReplaceNetworkSegmentRequest
import io.axiam.sdk.management.models.Resource
import io.axiam.sdk.management.models.Role
import io.axiam.sdk.management.models.ServiceAccountResponse
import io.axiam.sdk.management.models.UpdateGroup
import io.axiam.sdk.management.models.UpdatePermissionRequest
import io.axiam.sdk.management.models.UpdateResourceRequest
import io.axiam.sdk.management.models.UpdateRole
import io.axiam.sdk.management.models.UpdateServiceAccount
import io.axiam.sdk.management.models.UpdateUserRequest
import io.axiam.sdk.management.models.UserResponse
import java.util.UUID

/**
 * The CONTRACT.md §27.6 declarative layer: describe the tenant you want, then
 * reconcile toward it. §27.6.1 (contract 1.51) adds resource `metadata`,
 * resource-scoped role bindings with `inherit`, and service accounts; §27.6.2
 * (contract 1.62) adds the `network` namespace — the tenant's cap, segments and
 * reply profiles — whose writes are version-conditional and never retried.
 *
 * Two operations, and the difference between them is the whole design.
 * [plan] issues reads and nothing else, so it can be run against production to
 * find out what an [apply] would do. [apply] performs the writes, stops at the
 * first failure, and does not roll back.
 *
 * A view over the management API, not a connection: constructing one performs
 * no I/O (§27.2 rule 1).
 */
class ManifestApi internal constructor(private val api: ManagementApi) {

    /** What the server holds today for one role-side subject binding. */
    private data class ExistingBinding(
        val resourceId: UUID?,
        val inherit: Boolean,
        val tenantScope: List<UUID>?,
    )

    /** Which of the three subject kinds a binding step is about. */
    private enum class SubjectKind { GROUP, USER, SERVICE_ACCOUNT }

    /** Everything the reconciler read, in one snapshot. */
    private class Snapshot {
        var resources: List<Resource> = emptyList()
        var permissions: List<Permission> = emptyList()
        var roles: List<Role> = emptyList()
        var groups: List<Group> = emptyList()
        var users: List<UserResponse> = emptyList()
        var serviceAccounts: List<ServiceAccountResponse> = emptyList()
        val scopes = mutableMapOf<UUID, List<io.axiam.sdk.management.models.Scope>>()
        val roleGrants = mutableMapOf<UUID, List<UUID>>()
        val roleGroupBindings = mutableMapOf<UUID, Map<UUID, ExistingBinding>>()
        val roleUserBindings = mutableMapOf<UUID, Map<UUID, ExistingBinding>>()
        val roleServiceAccountBindings = mutableMapOf<UUID, Map<UUID, ExistingBinding>>()
        val groupMembers = mutableMapOf<UUID, List<UUID>>()
        var networkPolicy: NetworkPolicyResponse? = null
        var networkSegments: List<NetworkSegmentResponse> = emptyList()
        var networkProfiles: List<NetworkReplyProfile> = emptyList()
    }

    /** Manifest keys resolved to the server identifiers they name. */
    private class Resolved {
        val resources = mutableMapOf<String, UUID>()
        val scopes = mutableMapOf<String, UUID>()
        val permissions = mutableMapOf<String, UUID>()
        val roles = mutableMapOf<String, UUID>()
        val groups = mutableMapOf<String, UUID>()
        val users = mutableMapOf<String, UUID>()
        val serviceAccounts = mutableMapOf<String, UUID>()

        /** §27.6.2 item 4: a segment's id, from the read or from the write that made it. */
        val networkSegmentIds = mutableMapOf<String, UUID>()

        /**
         * §27.6.2 item 4: a segment's `version` — the read's, replaced by the
         * response of this `apply`'s own write of the segment, because a profile's
         * `segment_version` must be the one the segment write moved it to.
         */
        val networkSegmentVersions = mutableMapOf<String, Long>()
    }

    /** What a step will actually do, kept separate from how it is described. */
    private enum class Kind {
        NOOP,
        CREATE_RESOURCE, UPDATE_RESOURCE, CREATE_SCOPE,
        CREATE_PERMISSION, UPDATE_PERMISSION,
        CREATE_ROLE, UPDATE_ROLE, GRANT_PERMISSION,
        CREATE_GROUP, UPDATE_GROUP, BIND_GROUP_ROLE,
        CREATE_USER, UPDATE_USER, BIND_USER_ROLE, ADD_GROUP_MEMBER,
        CREATE_SERVICE_ACCOUNT, UPDATE_SERVICE_ACCOUNT, BIND_SERVICE_ACCOUNT_ROLE,
        UPDATE_NETWORK_POLICY,
        CREATE_NETWORK_SEGMENT, UPDATE_NETWORK_SEGMENT,
        CREATE_NETWORK_PROFILE, UPDATE_NETWORK_PROFILE,
    }

    /** One executable step, carrying manifest keys rather than identifiers. */
    private data class Step(
        val action: ManagementPlan.PlannedAction,
        val kind: Kind,
        val key: String,
        val spec: Any? = null,
        val related: String? = null,
    )

    /** The payload of a `BIND_*_ROLE` step: the desired binding, plus what to restore on failure. */
    private data class BindingOp(
        val subjectKey: String,
        val binding: ManagementManifest.RoleBinding,
        val isUpdate: Boolean,
        val existing: ExistingBinding?,
    )

    /** The payload of a segment step: the spec, and the read an `Update` replaces. */
    private data class SegmentOp(
        val spec: ManagementManifest.NetworkSegmentSpec,
        val read: NetworkSegmentResponse?,
    )

    /** The payload of a profile step: the spec, and the read an `Update` replaces. */
    private data class ProfileOp(
        val spec: ManagementManifest.NetworkProfileSpec,
        val segmentKey: String,
        val read: NetworkReplyProfile?,
    )

    /** The payload of the policy step: the cap stated, and the policy as read. */
    private data class PolicyOp(
        val spec: ManagementManifest.NetworkPolicySpec,
        val read: NetworkPolicyResponse,
    )

    /**
     * The payload of an `UPDATE_RESOURCE` step: which field(s) actually
     * drifted, tracked separately so the request sent is truly sparse — a
     * resource whose `metadata` alone drifted must not also carry
     * `resource_type`, or a byte-for-byte-unchanged type would be resent on
     * every metadata edit for no reason (§27.6.1 item 1).
     */
    private data class ResourceUpdateOp(
        val spec: ManagementManifest.ResourceSpec,
        val resourceTypeDrifted: Boolean,
        val metadataDrifted: Boolean,
    )

    /**
     * Reports what reconciling [manifest] would change, writing nothing.
     *
     * Every request this issues is a read (§27.6 rule 1), and the plan is
     * stable: running it twice against an unchanged tenant produces the same
     * actions in the same order.
     *
     * @param manifest the tenant description to compare against
     * @return the plan, including the steps that would change nothing
     * @throws NetworkError if the manifest is unreconcilable, including an
     *   ambiguous service-account name (§27.6.1 item 3)
     */
    suspend fun plan(manifest: ManagementManifest): ManagementPlan {
        ManifestValidation.validate(manifest)
        val steps = derive(manifest, read(manifest), Resolved())
        return ManagementPlan(steps.map { it.action })
    }

    /**
     * Reconciles the tenant toward [manifest].
     *
     * Stops at the first failure and does **not** roll back (§27.6 rule 7):
     * everything before the failure stands, and everything after it is reported
     * as [ApplyReport.Status.NOT_ATTEMPTED]. An automatic rollback would be a
     * second unreviewed batch of writes issued at exactly the moment the tenant
     * is in a state nobody has looked at.
     *
     * @param manifest the tenant description to converge on
     * @return what every step did
     * @throws NetworkError if the manifest is unreconcilable, or would create a
     *   user with no password
     */
    suspend fun apply(manifest: ManagementManifest): ApplyReport {
        ManifestValidation.validate(manifest)
        val resolved = Resolved()
        val steps = derive(manifest, read(manifest), resolved)
        requirePasswords(steps)
        return execute(steps, resolved)
    }

    /** The page size a plan's reads use; large enough that most tenants take one round. */
    private val planPage = PageRequest.of(200)

    private suspend fun read(manifest: ManagementManifest): Snapshot {
        val snapshot = Snapshot()
        snapshot.resources = api.resources().listAll(planPage)
        snapshot.permissions = api.permissions().listAll(planPage)
        snapshot.roles = api.roles().listAll(planPage)
        snapshot.groups = api.groups().listAll(planPage)
        snapshot.users = api.users().listAll(planPage)
        // §27.6.1 item 3, matching the reference: read only when the manifest
        // actually names a service account. A manifest with none makes no new
        // request beyond what §27.6 already reads for resources/permissions/
        // roles/groups/users.
        if (manifest.serviceAccounts.isNotEmpty()) {
            snapshot.serviceAccounts = api.serviceAccounts().listAll(planPage)
        }

        // Only the resources, roles and groups the manifest could match: a
        // tenant with a thousand resources should not cost a thousand scope
        // reads to plan five.
        val wantedResources = manifest.resources.map { it.name }.toSet()
        for (resource in snapshot.resources) {
            if (resource.name in wantedResources) {
                snapshot.scopes[resource.id] = api.scopes().list(resource.id)
            }
        }
        val wantedRoles = manifest.roles.map { it.name }.toSet()
        for (role in snapshot.roles) {
            if (role.name !in wantedRoles) continue
            snapshot.roleGrants[role.id] = api.roles().listPermissions(role.id).map { it.permission.id }
            snapshot.roleUserBindings[role.id] = api.roles().listUsers(role.id).associate {
                it.user.id to ExistingBinding(it.resourceId, it.inherit, it.tenantScope)
            }
            snapshot.roleGroupBindings[role.id] = api.roles().listGroups(role.id).associate {
                it.group.id to ExistingBinding(it.resourceId, it.inherit, it.tenantScope)
            }
            // Only when the manifest actually names a service account —
            // matching the top-level list read's own guard above, and for
            // the same reason: a manifest with none makes no new request.
            if (manifest.serviceAccounts.isNotEmpty()) {
                snapshot.roleServiceAccountBindings[role.id] = api.roles().listServiceAccounts(role.id).associate {
                    it.serviceAccount.id to ExistingBinding(it.resourceId, it.inherit, it.tenantScope)
                }
            }
        }
        val wantedGroups = manifest.groups.map { it.name }.toSet()
        for (group in snapshot.groups) {
            if (group.name in wantedGroups) {
                snapshot.groupMembers[group.id] =
                    api.groups().listMembersAll(group.id, planPage).map { it.id }
            }
        }
        readNetwork(manifest, snapshot)
        return snapshot
    }

    /**
     * §27.6.2 item 3: `get_policy`, `list_segments` and `list_profiles`, each
     * walked to exhaustion, and only for what the manifest states — a manifest
     * with no `network` section makes no new request, so it plans exactly as it
     * did before contract 1.62. GETs only (§27.6 rule 1).
     */
    private suspend fun readNetwork(manifest: ManagementManifest, snapshot: Snapshot) {
        val network = manifest.network
        if (network.isEmpty) return
        if (network.policy != null) snapshot.networkPolicy = api.network().getPolicy()
        if (network.segments.isNotEmpty()) {
            snapshot.networkSegments = api.network().listSegmentsAll(null, planPage)
        }
        if (network.profiles.isNotEmpty()) {
            snapshot.networkProfiles = api.network().listProfilesAll(planPage)
        }
    }

    private fun derive(
        manifest: ManagementManifest,
        snap: Snapshot,
        res: Resolved,
    ): List<Step> {
        val out = mutableListOf<Step>()
        val specs = manifest.resources.associateBy { it.key }

        for (key in ManifestValidation.topologicalOrder(manifest)) {
            val spec = specs.getValue(key)
            val parentPending = spec.parent != null && spec.parent !in res.resources
            val parentId = spec.parent?.let { res.resources[it] }
            // A child whose parent is itself pending cannot already exist, so
            // matching it against a root of the same name would be wrong.
            val existing = if (parentPending) null else snap.resources.firstOrNull {
                it.name == spec.name && it.parentId == parentId
            }
            val summary = "resource '${spec.name}' (${spec.resourceType})"
            if (existing != null) {
                res.resources[key] = existing.id
                // §27.6.1 item 1: drift is JSON equality of the WHOLE object,
                // never a merge; an UNSTATED metadata (null) is silent no
                // matter what the server holds.
                val metadataDrifted = spec.metadata != null && spec.metadata != existing.metadata
                val resourceTypeDrifted = existing.resourceType != spec.resourceType
                val drifted = resourceTypeDrifted || metadataDrifted
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.RESOURCE, key, summary,
                    if (drifted) Kind.UPDATE_RESOURCE else Kind.NOOP,
                    if (drifted) ResourceUpdateOp(spec, resourceTypeDrifted, metadataDrifted) else spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.RESOURCE, key, summary,
                    Kind.CREATE_RESOURCE, spec,
                )
            }
        }

        for (spec in manifest.resources) {
            val resourceId = res.resources[spec.key]
            val current = resourceId?.let { snap.scopes[it] }.orEmpty()
            for (scope in spec.scopes) {
                val summary = "scope '${scope.name}' under resource '${spec.name}'"
                val found = current.firstOrNull { it.name == scope.name }
                if (found != null) {
                    res.scopes[scope.key] = found.id
                    out += step(
                        ManagementPlan.Change.NO_CHANGE, ManagementPlan.Target.SCOPE, scope.key,
                        summary, Kind.NOOP, scope, spec.key,
                    )
                } else {
                    out += step(
                        ManagementPlan.Change.CREATE, ManagementPlan.Target.SCOPE, scope.key,
                        summary, Kind.CREATE_SCOPE, scope, spec.key,
                    )
                }
            }
        }

        for (spec in manifest.permissions) {
            val summary = "permission '${spec.action}'"
            val found = snap.permissions.firstOrNull { it.action == spec.action }
            if (found != null) {
                res.permissions[spec.key] = found.id
                val drifted = found.description != spec.description
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.PERMISSION, spec.key, summary,
                    if (drifted) Kind.UPDATE_PERMISSION else Kind.NOOP, spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.PERMISSION, spec.key,
                    summary, Kind.CREATE_PERMISSION, spec,
                )
            }
        }

        for (spec in manifest.roles) {
            val summary = "role '${spec.name}'"
            val found = snap.roles.firstOrNull { it.name == spec.name }
            if (found != null) {
                res.roles[spec.key] = found.id
                val drifted = found.description != spec.description || found.isGlobal != spec.global
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.ROLE, spec.key, summary,
                    if (drifted) Kind.UPDATE_ROLE else Kind.NOOP, spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.ROLE, spec.key, summary,
                    Kind.CREATE_ROLE, spec,
                )
            }
        }

        for (role in manifest.roles) {
            val granted = res.roles[role.key]?.let { snap.roleGrants[it] }.orEmpty()
            for (grant in role.grants) {
                val summary = "grant '${grant.permission}' to role '${role.name}'"
                val permissionId = res.permissions[grant.permission]
                val already = permissionId != null && permissionId in granted
                out += step(
                    if (already) ManagementPlan.Change.NO_CHANGE else ManagementPlan.Change.CREATE,
                    ManagementPlan.Target.ROLE_GRANT, role.key, summary,
                    if (already) Kind.NOOP else Kind.GRANT_PERMISSION, grant, role.key,
                )
            }
        }

        for (spec in manifest.groups) {
            val summary = "group '${spec.name}'"
            val found = snap.groups.firstOrNull { it.name == spec.name }
            if (found != null) {
                res.groups[spec.key] = found.id
                val drifted = found.description != spec.description
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.GROUP, spec.key, summary,
                    if (drifted) Kind.UPDATE_GROUP else Kind.NOOP, spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.GROUP, spec.key, summary,
                    Kind.CREATE_GROUP, spec,
                )
            }
        }

        for (group in manifest.groups) {
            bindingSteps(
                out, SubjectKind.GROUP, group.key, group.roles,
                subjectId = res.groups[group.key], subjectName = group.name,
                res = res, existingFor = { roleId, subjectId -> snap.roleGroupBindings[roleId]?.get(subjectId) },
                target = ManagementPlan.Target.GROUP_ROLE,
            )
        }

        for (spec in manifest.users) {
            val summary = "user '${spec.username}'"
            val found = snap.users.firstOrNull { it.username == spec.username }
            if (found != null) {
                res.users[spec.key] = found.id
                val drifted = found.email != spec.email
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.USER, spec.key, summary,
                    if (drifted) Kind.UPDATE_USER else Kind.NOOP, spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.USER, spec.key, summary,
                    Kind.CREATE_USER, spec,
                )
            }
        }

        for (user in manifest.users) {
            bindingSteps(
                out, SubjectKind.USER, user.key, user.roles,
                subjectId = res.users[user.key], subjectName = user.username,
                res = res, existingFor = { roleId, subjectId -> snap.roleUserBindings[roleId]?.get(subjectId) },
                target = ManagementPlan.Target.USER_ROLE,
            )
        }

        for (user in manifest.users) {
            for (groupKey in user.groups) {
                val summary = "user '${user.username}' in group '$groupKey'"
                val groupId = res.groups[groupKey]
                val userId = res.users[user.key]
                val already = groupId != null && userId != null &&
                    userId in snap.groupMembers[groupId].orEmpty()
                out += step(
                    if (already) ManagementPlan.Change.NO_CHANGE else ManagementPlan.Change.CREATE,
                    ManagementPlan.Target.GROUP_MEMBER, user.key, summary,
                    if (already) Kind.NOOP else Kind.ADD_GROUP_MEMBER, groupKey, user.key,
                )
            }
        }

        // §27.6 rule 5: service accounts and their bindings come next.
        deriveServiceAccounts(out, manifest, snap, res)

        // §27.6 rule 5 (contract 1.62): the `network` namespace is appended last, so
        // that a manifest without one plans exactly as it did before 1.62.
        deriveNetwork(out, manifest, snap, res)

        return out
    }

    /**
     * §27.6.2: the policy, then the segments, then the profiles — and the
     * profiles in the segments' order, so that `plan` is stable (rule 8).
     *
     * Every stated member is compared with the value **as the read returns it**
     * (item 3): for a profile that is the effective, clamped one, so a stated
     * `session_timeout_secs` above the cap is an `Update` here and the server's
     * refusal at `apply`; no hidden or stored value is compared. A segment's
     * `kind`, `site` and `name` are the key and never drift (§36.3 rule 4).
     */
    private fun deriveNetwork(
        out: MutableList<Step>,
        manifest: ManagementManifest,
        snap: Snapshot,
        res: Resolved,
    ) {
        val network = manifest.network

        network.policy?.let { spec ->
            val read = snap.networkPolicy ?: error("the policy was not read")
            val drifted = spec.sessionTimeoutMaxSecs != read.sessionTimeoutMaxSecs
            out += step(
                if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                ManagementPlan.Target.NETWORK_POLICY, NETWORK_POLICY_KEY,
                "network policy (Session-Timeout cap ${spec.sessionTimeoutMaxSecs}s)",
                if (drifted) Kind.UPDATE_NETWORK_POLICY else Kind.NOOP, PolicyOp(spec, read),
            )
        }

        for (spec in network.segments) {
            val summary = "network segment '${spec.site}/${spec.kind.wire}/${spec.name}'"
            val found = snap.networkSegments.firstOrNull {
                it.siteKey == spec.site && it.kind == spec.kind && it.name == spec.name
            }
            if (found == null) {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.NETWORK_SEGMENT, spec.key, summary,
                    Kind.CREATE_NETWORK_SEGMENT, SegmentOp(spec, null),
                )
                continue
            }
            res.networkSegmentIds[spec.key] = found.id
            res.networkSegmentVersions[spec.key] = found.version
            val drifted = found.vlanId != spec.vlanId ||
                !spec.rank.matches(found.rank) ||
                (spec.filterIds != null && spec.filterIds.toSet() != found.filterIds.toSet()) ||
                (spec.enabled != null && spec.enabled != found.enabled)
            out += step(
                if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                ManagementPlan.Target.NETWORK_SEGMENT, spec.key, summary,
                if (drifted) Kind.UPDATE_NETWORK_SEGMENT else Kind.NOOP, SegmentOp(spec, found),
            )
        }

        val bySegment = network.profiles.associateBy { it.segment }
        for (segment in network.segments) {
            val spec = bySegment[segment.key] ?: continue
            val summary = "network profile of segment '${segment.site}/${segment.kind.wire}/${segment.name}'"
            val segmentId = res.networkSegmentIds[segment.key]
            val found = segmentId?.let { id -> snap.networkProfiles.firstOrNull { it.segmentId == id } }
            if (found == null) {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.NETWORK_PROFILE, segment.key, summary,
                    Kind.CREATE_NETWORK_PROFILE, ProfileOp(spec, segment.key, null),
                )
                continue
            }
            val drifted = found.sessionTimeoutSecs != spec.sessionTimeoutSecs ||
                (spec.terminationAction != null && spec.terminationAction != found.terminationAction) ||
                !spec.idleTimeoutSecs.matches(found.idleTimeoutSecs) ||
                !spec.filterId.matches(found.filterId) ||
                !spec.serviceType.matches(found.serviceType)
            // §27.6.2 item 4 (contract 1.62 (ab), §34.6): an Update would carry the read's value for a
            // member the manifest does not state, and a value this SDK does not know is never sent.
            // Refused here, before any write, rather than half-way through an apply.
            if (drifted) {
                if (spec.terminationAction == null && found.terminationAction == RadiusTerminationAction.UNKNOWN) {
                    throw unknownCarried(summary, "termination_action", found.terminationActionRaw)
                }
                if (spec.serviceType === JsonNullable.Absent && found.serviceType == RadiusServiceType.UNKNOWN) {
                    throw unknownCarried(summary, "service_type", found.serviceTypeRaw)
                }
            }
            out += step(
                if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                ManagementPlan.Target.NETWORK_PROFILE, segment.key, summary,
                if (drifted) Kind.UPDATE_NETWORK_PROFILE else Kind.NOOP, ProfileOp(spec, segment.key, found),
            )
        }
    }

    /**
     * The local refusal of §27.6.2 item 4: a [ValidationError] (as 1.1.0's apply-time refusal
     * was; still a [NetworkError] by subtype, §27.4 rule 7) naming the member in its
     * [FieldError]. The value is quoted where the decoded type kept it ([raw], C163-10, contract
     * 1.64); an SDK that did not keep it says the value is unknown.
     */
    private fun unknownCarried(summary: String, member: String, raw: String?): ValidationError {
        val value = if (raw != null) {
            // JSON-escaped and quoted: the text is the server's, and a quote or a newline in it
            // must not reach the message or the log verbatim (C164-21).
            "$member " + kotlinx.serialization.json.JsonPrimitive(raw.take(MAX_QUOTED_VALUE))
        } else "a $member (the value is unknown)"
        val msg = "$summary: the server returned $value this SDK does not know, the manifest does not " +
            "state $member, and the profile would be updated; an unknown value is never sent " +
            "(§34.2 P12.2). Nothing was sent: state $member in the manifest (§27.6.2 item 4)."
        return ValidationError(msg, listOf(FieldError(member, msg)))
    }

    /**
     * Whether a stated optional member agrees with the read: unstated
     * ([JsonNullable.Absent]) is silent and always agrees; "none"
     * ([JsonNullable.Null]) agrees with a read that has none.
     */
    private fun <T> JsonNullable<T>.matches(read: T?): Boolean =
        this === JsonNullable.Absent ||
            (this === JsonNullable.Null && read == null) ||
            (this is JsonNullable.Value && value == read)

    /** The member's value in a body built from [read]: stated, none, or carried from the read. */
    private fun <T> JsonNullable<T>.orRead(read: T?): T? = when (this) {
        JsonNullable.Absent -> read
        JsonNullable.Null -> null
        is JsonNullable.Value -> value
    }

    /**
     * §27.6.1 item 3. Reconciled by NAME: the server does not keep it unique
     * (only `client_id` is indexed), so a manifest naming a name that matches
     * more than one existing account is refused here — before any write —
     * rather than picking one arbitrarily.
     */
    private fun deriveServiceAccounts(
        out: MutableList<Step>,
        manifest: ManagementManifest,
        snap: Snapshot,
        res: Resolved,
    ) {
        for (spec in manifest.serviceAccounts) {
            val summary = "service account '${spec.name}'"
            val matches = snap.serviceAccounts.filter { it.name == spec.name }
            if (matches.size > 1) {
                throw NetworkError(
                    "manifest names service account '${spec.name}' (key '${spec.key}'), which is " +
                        "ambiguous: ${matches.size} existing accounts share that name, and the " +
                        "server does not keep names unique (only client_id is indexed). Nothing " +
                        "was sent (§27.6 rule 1) — rename the account or disambiguate by hand.",
                )
            }
            val found = matches.firstOrNull()
            if (found != null) {
                res.serviceAccounts[spec.key] = found.id
                // §27.6.1 item 3: description is the ONLY field an Update
                // reconciles. name is the reconciliation key and status is
                // left alone (apply never suspends/reactivates an account).
                val drifted = spec.description != null && spec.description != found.description
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.SERVICE_ACCOUNT, spec.key, summary,
                    if (drifted) Kind.UPDATE_SERVICE_ACCOUNT else Kind.NOOP, spec,
                )
            } else {
                out += step(
                    ManagementPlan.Change.CREATE, ManagementPlan.Target.SERVICE_ACCOUNT, spec.key,
                    summary, Kind.CREATE_SERVICE_ACCOUNT, spec,
                )
            }
        }

        for (sa in manifest.serviceAccounts) {
            bindingSteps(
                out, SubjectKind.SERVICE_ACCOUNT, sa.key, sa.roles,
                subjectId = res.serviceAccounts[sa.key], subjectName = sa.name,
                res = res,
                existingFor = { roleId, subjectId -> snap.roleServiceAccountBindings[roleId]?.get(subjectId) },
                target = ManagementPlan.Target.SERVICE_ACCOUNT_ROLE,
            )
        }
    }

    /**
     * Shared role-binding reconciliation for groups, users and service
     * accounts alike (§27.6.1 item 2): the natural key is (subject, role) —
     * `NoChange` for the same resource and `inherit`, an `Update` (unassign
     * then assign) otherwise. A binding whose role is itself pending
     * (not-yet-created) or whose subject is pending can never already exist,
     * so it is always a `Create`.
     */
    private fun bindingSteps(
        out: MutableList<Step>,
        kind: SubjectKind,
        subjectKey: String,
        roleBindings: List<ManagementManifest.RoleBinding>,
        subjectId: UUID?,
        subjectName: String,
        res: Resolved,
        existingFor: (roleId: UUID, subjectId: UUID) -> ExistingBinding?,
        target: ManagementPlan.Target,
    ) {
        for (binding in roleBindings) {
            val roleId = res.roles[binding.role]
            val summary = "role '${binding.role}' on ${kind.name.lowercase()} '$subjectName'"
            val desiredResourceId = (binding as? ManagementManifest.RoleBinding.Scoped)
                ?.resource?.let { res.resources[it] }
            val desiredInherit = (binding as? ManagementManifest.RoleBinding.Scoped)?.inherit ?: true

            val existing = if (roleId != null && subjectId != null) existingFor(roleId, subjectId) else null
            val change: ManagementPlan.Change
            val stepKind: Kind
            val op: BindingOp
            if (existing == null) {
                change = ManagementPlan.Change.CREATE
                stepKind = bindKindFor(kind)
                op = BindingOp(subjectKey, binding, isUpdate = false, existing = null)
            } else if (existing.resourceId == desiredResourceId && existing.inherit == desiredInherit) {
                change = ManagementPlan.Change.NO_CHANGE
                stepKind = Kind.NOOP
                op = BindingOp(subjectKey, binding, isUpdate = false, existing = existing)
            } else {
                change = ManagementPlan.Change.UPDATE
                stepKind = bindKindFor(kind)
                op = BindingOp(subjectKey, binding, isUpdate = true, existing = existing)
            }
            out += step(change, target, subjectKey, summary, stepKind, op, related = binding.role)
        }
    }

    private fun bindKindFor(kind: SubjectKind): Kind = when (kind) {
        SubjectKind.GROUP -> Kind.BIND_GROUP_ROLE
        SubjectKind.USER -> Kind.BIND_USER_ROLE
        SubjectKind.SERVICE_ACCOUNT -> Kind.BIND_SERVICE_ACCOUNT_ROLE
    }

    private fun step(
        change: ManagementPlan.Change,
        target: ManagementPlan.Target,
        key: String,
        summary: String,
        kind: Kind,
        spec: Any?,
        related: String? = null,
    ): Step = Step(ManagementPlan.PlannedAction(change, target, key, summary), kind, key, spec, related)

    /**
     * Refuses, before any request, when a user must be created with no password.
     *
     * §27.6 rule 1: discovering this halfway through an apply leaves the tenant
     * part-reconciled, and the fix — supply the password — is one a caller
     * could have been told about before anything was written.
     */
    private fun requirePasswords(steps: List<Step>) {
        val missing = steps
            .filter { it.kind == Kind.CREATE_USER }
            .filter { (it.spec as ManagementManifest.UserSpec).initialPassword == null }
            .map { it.key }
        if (missing.isNotEmpty()) {
            throw NetworkError(
                "manifest would create ${missing.size} user(s) with no initialPassword: " +
                    "$missing. A user cannot be created without one, and this is refused " +
                    "before any request rather than part-way through an apply (§27.6 rule 1).",
            )
        }
    }

    private suspend fun execute(steps: List<Step>, res: Resolved): ApplyReport {
        val applied = mutableListOf<ApplyReport.AppliedStep>()
        var stopped = false
        for (s in steps) {
            if (stopped) {
                applied += ApplyReport.AppliedStep(
                    s.action, ApplyReport.StepOutcome(ApplyReport.Status.NOT_ATTEMPTED),
                )
                continue
            }
            if (s.kind == Kind.NOOP) {
                applied += ApplyReport.AppliedStep(
                    s.action, ApplyReport.StepOutcome(ApplyReport.Status.UNCHANGED),
                )
                continue
            }
            if (isBindKind(s.kind)) {
                val outcome = runBinding(kindOf(s.kind), s, res)
                applied += ApplyReport.AppliedStep(s.action, outcome)
                if (outcome.status == ApplyReport.Status.FAILED ||
                    outcome.status == ApplyReport.Status.BINDING_UPDATE_FAILED
                ) {
                    stopped = true
                }
                continue
            }
            try {
                val outcome = run(s, res)
                applied += ApplyReport.AppliedStep(s.action, outcome)
            } catch (e: RuntimeException) {
                applied += ApplyReport.AppliedStep(
                    s.action,
                    // §27.6.2 item 5: a 409's `reason_code` is exposed as data, so the
                    // caller branches on it and never on the message.
                    ApplyReport.StepOutcome(
                        ApplyReport.Status.FAILED, e.message, reasonCode = (e as? ConflictError)?.reasonCode,
                    ),
                )
                stopped = true
            }
        }
        return ApplyReport(applied)
    }

    private fun isBindKind(kind: Kind): Boolean =
        kind == Kind.BIND_GROUP_ROLE || kind == Kind.BIND_USER_ROLE || kind == Kind.BIND_SERVICE_ACCOUNT_ROLE

    private fun kindOf(kind: Kind): SubjectKind = when (kind) {
        Kind.BIND_GROUP_ROLE -> SubjectKind.GROUP
        Kind.BIND_USER_ROLE -> SubjectKind.USER
        Kind.BIND_SERVICE_ACCOUNT_ROLE -> SubjectKind.SERVICE_ACCOUNT
        else -> error("kindOf called on a non-binding Kind: $kind")
    }

    /**
     * Runs one role-binding step (§27.6.1 item 2): a plain `CREATE` assigns
     * once; an `UPDATE` unassigns the previous binding then assigns the new
     * one, carrying the previous binding's `tenant_scope` across — and, if
     * the assign half fails, re-assigns the previous binding and reports
     * [ApplyReport.Status.BINDING_UPDATE_FAILED] with whether THAT restore
     * succeeded.
     */
    private suspend fun runBinding(kind: SubjectKind, s: Step, res: Resolved): ApplyReport.StepOutcome {
        val op = s.spec as BindingOp
        val roleId = res.roles.getValue(s.related!!)
        val subjectId = subjectIdFor(kind, op.subjectKey, res)
        val desiredResourceId = (op.binding as? ManagementManifest.RoleBinding.Scoped)
            ?.resource?.let { res.resources[it] }
        val desiredInherit = (op.binding as? ManagementManifest.RoleBinding.Scoped)?.inherit ?: true

        if (!op.isUpdate) {
            return try {
                assignFor(kind, roleId, subjectId, desiredResourceId, desiredInherit, tenantScope = null)
                ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            } catch (e: RuntimeException) {
                ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.message)
            }
        }

        val existing = op.existing!!
        try {
            unassignFor(kind, roleId, subjectId, existing.resourceId)
        } catch (e: RuntimeException) {
            return ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.message)
        }
        return try {
            assignFor(kind, roleId, subjectId, desiredResourceId, desiredInherit, existing.tenantScope)
            ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
        } catch (e: RuntimeException) {
            // The unassign already happened: restore the previous binding
            // exactly (its own resource, inherit and tenant_scope) rather
            // than leave the subject with NEITHER binding.
            val restore = runCatching {
                assignFor(kind, roleId, subjectId, existing.resourceId, existing.inherit, existing.tenantScope)
            }
            ApplyReport.StepOutcome(
                ApplyReport.Status.BINDING_UPDATE_FAILED,
                message = e.message,
                restoreSucceeded = restore.isSuccess,
            )
        }
    }

    private fun subjectIdFor(kind: SubjectKind, key: String, res: Resolved): UUID = when (kind) {
        SubjectKind.GROUP -> res.groups.getValue(key)
        SubjectKind.USER -> res.users.getValue(key)
        SubjectKind.SERVICE_ACCOUNT -> res.serviceAccounts.getValue(key)
    }

    private suspend fun assignFor(
        kind: SubjectKind,
        roleId: UUID,
        subjectId: UUID,
        resourceId: UUID?,
        inherit: Boolean,
        tenantScope: List<UUID>?,
    ) {
        // §27.13 S-10 rule 1: `inherit` reaches the wire only when `false`.
        val wireInherit = if (inherit) null else false
        when (kind) {
            SubjectKind.GROUP -> api.roles().assignToGroup(
                roleId,
                AssignRoleToGroupRequest(
                    groupId = subjectId, resourceId = resourceId,
                    inherit = wireInherit, tenantScope = tenantScope,
                ),
            )
            SubjectKind.USER -> api.roles().assignToUser(
                roleId,
                AssignRoleToUserRequest(
                    userId = subjectId, resourceId = resourceId,
                    inherit = wireInherit, tenantScope = tenantScope,
                ),
            )
            SubjectKind.SERVICE_ACCOUNT -> api.roles().assignToServiceAccount(
                roleId,
                AssignRoleToServiceAccountRequest(
                    serviceAccountId = subjectId, resourceId = resourceId,
                    inherit = wireInherit, tenantScope = tenantScope,
                ),
            )
        }
    }

    private suspend fun unassignFor(kind: SubjectKind, roleId: UUID, subjectId: UUID, resourceId: UUID?) {
        val resourceParam = resourceId?.toString()
        when (kind) {
            SubjectKind.GROUP -> api.roles().unassignFromGroup(roleId, subjectId, resourceParam)
            SubjectKind.USER -> api.roles().unassignFromUser(roleId, subjectId, resourceParam)
            SubjectKind.SERVICE_ACCOUNT -> api.roles().unassignFromServiceAccount(roleId, subjectId, resourceParam)
        }
    }

    private suspend fun run(s: Step, res: Resolved): ApplyReport.StepOutcome {
        when (s.kind) {
            Kind.CREATE_RESOURCE -> {
                val spec = s.spec as ManagementManifest.ResourceSpec
                val created = api.resources().create(
                    CreateResourceRequest(
                        name = spec.name,
                        parentId = spec.parent?.let { res.resources[it] },
                        resourceType = spec.resourceType,
                        metadata = spec.metadata,
                    ),
                )
                res.resources[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_RESOURCE -> {
                val op = s.spec as ResourceUpdateOp
                api.resources().update(
                    res.resources.getValue(s.key),
                    UpdateResourceRequest(
                        resourceType = if (op.resourceTypeDrifted) op.spec.resourceType else null,
                        metadata = if (op.metadataDrifted) op.spec.metadata else null,
                    ),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.CREATE_SCOPE -> {
                val spec = s.spec as ManagementManifest.ScopeSpec
                val created = api.scopes().create(
                    res.resources.getValue(s.related!!),
                    CreateScopeRequest(description = spec.description, name = spec.name),
                )
                res.scopes[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.CREATE_PERMISSION -> {
                val spec = s.spec as ManagementManifest.PermissionSpec
                val created = api.permissions().create(
                    CreatePermissionRequest(action = spec.action, description = spec.description),
                )
                res.permissions[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_PERMISSION -> {
                val spec = s.spec as ManagementManifest.PermissionSpec
                api.permissions().update(
                    res.permissions.getValue(s.key),
                    UpdatePermissionRequest(description = spec.description),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.CREATE_ROLE -> {
                val spec = s.spec as ManagementManifest.RoleSpec
                val created = api.roles().create(
                    CreateRoleRequest(
                        description = spec.description,
                        isGlobal = spec.global,
                        name = spec.name,
                    ),
                )
                res.roles[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_ROLE -> {
                val spec = s.spec as ManagementManifest.RoleSpec
                api.roles().update(
                    res.roles.getValue(s.key),
                    UpdateRole(description = spec.description, isGlobal = spec.global),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.GRANT_PERMISSION -> {
                val grant = s.spec as ManagementManifest.GrantSpec
                val scopeIds = grant.scopes.mapNotNull { res.scopes[it] }
                api.roles().grantPermission(
                    res.roles.getValue(s.related!!),
                    GrantPermissionRequest(
                        effect = grant.effect?.let {
                            if (it == "deny") PermissionEffect.DENY else PermissionEffect.ALLOW
                        },
                        permissionId = res.permissions.getValue(grant.permission),
                        scopeIds = scopeIds.ifEmpty { null },
                    ),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.CREATE_GROUP -> {
                val spec = s.spec as ManagementManifest.GroupSpec
                val created = api.groups().create(
                    CreateGroupRequest(description = spec.description, name = spec.name),
                )
                res.groups[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_GROUP -> {
                val spec = s.spec as ManagementManifest.GroupSpec
                api.groups().update(
                    res.groups.getValue(s.key),
                    UpdateGroup(description = spec.description),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.CREATE_USER -> {
                val spec = s.spec as ManagementManifest.UserSpec
                val created = api.users().create(
                    CreateUserRequest(
                        email = spec.email,
                        password = spec.initialPassword!!,
                        username = spec.username,
                    ),
                )
                res.users[s.key] = created.id
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_USER -> {
                val spec = s.spec as ManagementManifest.UserSpec
                api.users().update(res.users.getValue(s.key), UpdateUserRequest(email = spec.email))
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.ADD_GROUP_MEMBER -> {
                api.groups().addMember(
                    res.groups.getValue(s.spec as String),
                    AddMemberRequest(userId = res.users.getValue(s.related!!)),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.CREATE_SERVICE_ACCOUNT -> {
                val spec = s.spec as ManagementManifest.ServiceAccountSpec
                val created = api.serviceAccounts().create(
                    CreateServiceAccountRequest(description = spec.description, name = spec.name),
                )
                res.serviceAccounts[s.key] = created.id
                // §27.5 rule 5: the one-time secret rides on the OUTCOME, not
                // only on a value the caller would need this exact call to
                // capture — see ApplyReport.createdServiceAccounts().
                return ApplyReport.StepOutcome(
                    ApplyReport.Status.CREATED_SERVICE_ACCOUNT,
                    createdServiceAccount = created,
                )
            }
            Kind.UPDATE_SERVICE_ACCOUNT -> {
                val spec = s.spec as ManagementManifest.ServiceAccountSpec
                api.serviceAccounts().update(
                    res.serviceAccounts.getValue(s.key),
                    UpdateServiceAccount(description = spec.description),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.UPDATE_NETWORK_POLICY -> {
                val op = s.spec as PolicyOp
                // The version `plan` read, exactly (§27.6.2 item 4); no retry, no re-read.
                api.network().replacePolicy(
                    ReplaceNetworkPolicyRequest(
                        sessionTimeoutMaxSecs = op.spec.sessionTimeoutMaxSecs,
                        version = op.read.version,
                    ),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.CREATE_NETWORK_SEGMENT -> {
                val spec = (s.spec as SegmentOp).spec
                val created = api.network().createSegment(
                    CreateNetworkSegmentRequest(
                        enabled = spec.enabled,
                        // In the order the manifest states (item 3).
                        filterIds = spec.filterIds,
                        kind = spec.kind,
                        name = spec.name,
                        rank = spec.rank.orRead(null),
                        siteKey = spec.site,
                        vlanId = spec.vlanId,
                    ),
                )
                // A new segment's id, and the version of THIS write's response, are what
                // its profile is created against (item 4).
                res.networkSegmentIds[spec.key] = created.id
                res.networkSegmentVersions[spec.key] = created.version
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_NETWORK_SEGMENT -> {
                val op = s.spec as SegmentOp
                val read = op.read!!
                val replaced = api.network().replaceSegment(
                    read.id,
                    // Full body, built from the read: the stated members replace the read's,
                    // every unstated one is carried, a stated `null` is left out. No `kind`,
                    // `site_key` or `name`: they do not change (§36.2).
                    ReplaceNetworkSegmentRequest(
                        enabled = op.spec.enabled ?: read.enabled,
                        filterIds = op.spec.filterIds ?: read.filterIds,
                        rank = op.spec.rank.orRead(read.rank),
                        version = read.version,
                        vlanId = op.spec.vlanId,
                    ),
                )
                res.networkSegmentVersions[op.spec.key] = replaced.version
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.CREATE_NETWORK_PROFILE -> {
                val op = s.spec as ProfileOp
                val spec = op.spec
                api.network().createProfile(
                    CreateNetworkReplyProfileRequest(
                        profile = NetworkReplyProfileInput(
                            filterId = spec.filterId.orRead(null),
                            idleTimeoutSecs = spec.idleTimeoutSecs.orRead(null),
                            serviceType = spec.serviceType.orRead(null),
                            sessionTimeoutSecs = spec.sessionTimeoutSecs,
                            terminationAction = spec.terminationAction,
                        ),
                        segmentId = res.networkSegmentIds.getValue(op.segmentKey),
                        segmentVersion = res.networkSegmentVersions.getValue(op.segmentKey),
                    ),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.CREATED)
            }
            Kind.UPDATE_NETWORK_PROFILE -> {
                val op = s.spec as ProfileOp
                val spec = op.spec
                val read = op.read!!
                api.network().replaceProfile(
                    read.segmentId,
                    ReplaceNetworkReplyProfileRequest(
                        profile = NetworkReplyProfileInput(
                            dictionary = read.dictionary,
                            filterId = spec.filterId.orRead(read.filterId),
                            idleTimeoutSecs = spec.idleTimeoutSecs.orRead(read.idleTimeoutSecs),
                            serviceType = spec.serviceType.orRead(read.serviceType),
                            sessionTimeoutSecs = spec.sessionTimeoutSecs,
                            terminationAction = spec.terminationAction ?: read.terminationAction,
                        ),
                        // The segment's version as this apply left it (item 4), not the one plan read.
                        segmentVersion = res.networkSegmentVersions.getValue(op.segmentKey),
                        version = read.version,
                    ),
                )
                return ApplyReport.StepOutcome(ApplyReport.Status.UPDATED)
            }
            Kind.BIND_GROUP_ROLE, Kind.BIND_USER_ROLE, Kind.BIND_SERVICE_ACCOUNT_ROLE, Kind.NOOP ->
                error("handled by execute() before reaching run()")
        }
    }

    private companion object {
        /** The key a plan action for the singleton `network.policy` carries (it has none of its own). */
        const val NETWORK_POLICY_KEY = "network.policy"

        /** Longest part of a server-sent value a refusal quotes: the text is the server's, not ours. */
        const val MAX_QUOTED_VALUE = 64
    }
}
