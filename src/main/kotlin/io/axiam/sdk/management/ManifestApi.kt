package io.axiam.sdk.management

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.management.models.AddMemberRequest
import io.axiam.sdk.management.models.AssignRoleToGroupRequest
import io.axiam.sdk.management.models.AssignRoleToUserRequest
import io.axiam.sdk.management.models.CreateGroupRequest
import io.axiam.sdk.management.models.CreatePermissionRequest
import io.axiam.sdk.management.models.CreateResourceRequest
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateScopeRequest
import io.axiam.sdk.management.models.CreateUserRequest
import io.axiam.sdk.management.models.Group
import io.axiam.sdk.management.models.GrantPermissionRequest
import io.axiam.sdk.management.models.Permission
import io.axiam.sdk.management.models.PermissionEffect
import io.axiam.sdk.management.models.Resource
import io.axiam.sdk.management.models.Role
import io.axiam.sdk.management.models.Scope
import io.axiam.sdk.management.models.UpdateGroup
import io.axiam.sdk.management.models.UpdatePermissionRequest
import io.axiam.sdk.management.models.UpdateResourceRequest
import io.axiam.sdk.management.models.UpdateRole
import io.axiam.sdk.management.models.UpdateUserRequest
import io.axiam.sdk.management.models.UserResponse
import java.util.UUID

/**
 * The CONTRACT.md §27.6 declarative layer: describe the tenant you want, then
 * reconcile toward it.
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

    /** Everything the reconciler read, in one snapshot. */
    private class Snapshot {
        var resources: List<Resource> = emptyList()
        var permissions: List<Permission> = emptyList()
        var roles: List<Role> = emptyList()
        var groups: List<Group> = emptyList()
        var users: List<UserResponse> = emptyList()
        val scopes = mutableMapOf<UUID, List<Scope>>()
        val roleGrants = mutableMapOf<UUID, List<UUID>>()
        val roleUsers = mutableMapOf<UUID, List<UUID>>()
        val roleGroups = mutableMapOf<UUID, List<UUID>>()
        val groupMembers = mutableMapOf<UUID, List<UUID>>()
    }

    /** Manifest keys resolved to the server identifiers they name. */
    private class Resolved {
        val resources = mutableMapOf<String, UUID>()
        val scopes = mutableMapOf<String, UUID>()
        val permissions = mutableMapOf<String, UUID>()
        val roles = mutableMapOf<String, UUID>()
        val groups = mutableMapOf<String, UUID>()
        val users = mutableMapOf<String, UUID>()
    }

    /** What a step will actually do, kept separate from how it is described. */
    private enum class Kind {
        NOOP,
        CREATE_RESOURCE, UPDATE_RESOURCE, CREATE_SCOPE,
        CREATE_PERMISSION, UPDATE_PERMISSION,
        CREATE_ROLE, UPDATE_ROLE, GRANT_PERMISSION,
        CREATE_GROUP, UPDATE_GROUP, ASSIGN_ROLE_TO_GROUP,
        CREATE_USER, UPDATE_USER, ASSIGN_ROLE_TO_USER, ADD_GROUP_MEMBER,
    }

    /** One executable step, carrying manifest keys rather than identifiers. */
    private data class Step(
        val action: ManagementPlan.PlannedAction,
        val kind: Kind,
        val key: String,
        val spec: Any? = null,
        val related: String? = null,
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
     * @throws NetworkError if the manifest is unreconcilable
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
            snapshot.roleUsers[role.id] = api.roles().listUsers(role.id).map { it.user.id }
            snapshot.roleGroups[role.id] = api.roles().listGroups(role.id).map { it.group.id }
        }
        val wantedGroups = manifest.groups.map { it.name }.toSet()
        for (group in snapshot.groups) {
            if (group.name in wantedGroups) {
                snapshot.groupMembers[group.id] =
                    api.groups().listMembersAll(group.id, planPage).map { it.id }
            }
        }
        return snapshot
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
                val drifted = existing.resourceType != spec.resourceType
                out += step(
                    if (drifted) ManagementPlan.Change.UPDATE else ManagementPlan.Change.NO_CHANGE,
                    ManagementPlan.Target.RESOURCE, key, summary,
                    if (drifted) Kind.UPDATE_RESOURCE else Kind.NOOP, spec,
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
            for (roleKey in group.roles) {
                val summary = "role '$roleKey' on group '${group.name}'"
                val roleId = res.roles[roleKey]
                val groupId = res.groups[group.key]
                val already = roleId != null && groupId != null &&
                    groupId in snap.roleGroups[roleId].orEmpty()
                out += step(
                    if (already) ManagementPlan.Change.NO_CHANGE else ManagementPlan.Change.CREATE,
                    ManagementPlan.Target.GROUP_ROLE, group.key, summary,
                    if (already) Kind.NOOP else Kind.ASSIGN_ROLE_TO_GROUP, roleKey, group.key,
                )
            }
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
            for (roleKey in user.roles) {
                val summary = "role '$roleKey' on user '${user.username}'"
                val roleId = res.roles[roleKey]
                val userId = res.users[user.key]
                val already = roleId != null && userId != null &&
                    userId in snap.roleUsers[roleId].orEmpty()
                out += step(
                    if (already) ManagementPlan.Change.NO_CHANGE else ManagementPlan.Change.CREATE,
                    ManagementPlan.Target.USER_ROLE, user.key, summary,
                    if (already) Kind.NOOP else Kind.ASSIGN_ROLE_TO_USER, roleKey, user.key,
                )
            }
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
        return out
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
            try {
                run(s, res)
            } catch (e: RuntimeException) {
                applied += ApplyReport.AppliedStep(
                    s.action, ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.message),
                )
                stopped = true
                continue
            }
            val status = if (s.kind.name.startsWith("UPDATE")) {
                ApplyReport.Status.UPDATED
            } else {
                ApplyReport.Status.CREATED
            }
            applied += ApplyReport.AppliedStep(s.action, ApplyReport.StepOutcome(status))
        }
        return ApplyReport(applied)
    }

    private suspend fun run(s: Step, res: Resolved) {
        when (s.kind) {
            Kind.CREATE_RESOURCE -> {
                val spec = s.spec as ManagementManifest.ResourceSpec
                val created = api.resources().create(
                    CreateResourceRequest(
                        name = spec.name,
                        parentId = spec.parent?.let { res.resources[it] },
                        resourceType = spec.resourceType,
                    ),
                )
                res.resources[s.key] = created.id
            }
            Kind.UPDATE_RESOURCE -> {
                val spec = s.spec as ManagementManifest.ResourceSpec
                api.resources().update(
                    res.resources.getValue(s.key),
                    UpdateResourceRequest(resourceType = spec.resourceType),
                )
            }
            Kind.CREATE_SCOPE -> {
                val spec = s.spec as ManagementManifest.ScopeSpec
                val created = api.scopes().create(
                    res.resources.getValue(s.related!!),
                    CreateScopeRequest(description = spec.description, name = spec.name),
                )
                res.scopes[s.key] = created.id
            }
            Kind.CREATE_PERMISSION -> {
                val spec = s.spec as ManagementManifest.PermissionSpec
                val created = api.permissions().create(
                    CreatePermissionRequest(action = spec.action, description = spec.description),
                )
                res.permissions[s.key] = created.id
            }
            Kind.UPDATE_PERMISSION -> {
                val spec = s.spec as ManagementManifest.PermissionSpec
                api.permissions().update(
                    res.permissions.getValue(s.key),
                    UpdatePermissionRequest(description = spec.description),
                )
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
            }
            Kind.UPDATE_ROLE -> {
                val spec = s.spec as ManagementManifest.RoleSpec
                api.roles().update(
                    res.roles.getValue(s.key),
                    UpdateRole(description = spec.description, isGlobal = spec.global),
                )
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
            }
            Kind.CREATE_GROUP -> {
                val spec = s.spec as ManagementManifest.GroupSpec
                val created = api.groups().create(
                    CreateGroupRequest(description = spec.description, name = spec.name),
                )
                res.groups[s.key] = created.id
            }
            Kind.UPDATE_GROUP -> {
                val spec = s.spec as ManagementManifest.GroupSpec
                api.groups().update(
                    res.groups.getValue(s.key),
                    UpdateGroup(description = spec.description),
                )
            }
            Kind.ASSIGN_ROLE_TO_GROUP -> api.roles().assignToGroup(
                res.roles.getValue(s.spec as String),
                AssignRoleToGroupRequest(groupId = res.groups.getValue(s.related!!)),
            )
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
            }
            Kind.UPDATE_USER -> {
                val spec = s.spec as ManagementManifest.UserSpec
                api.users().update(res.users.getValue(s.key), UpdateUserRequest(email = spec.email))
            }
            Kind.ASSIGN_ROLE_TO_USER -> api.roles().assignToUser(
                res.roles.getValue(s.spec as String),
                AssignRoleToUserRequest(userId = res.users.getValue(s.related!!)),
            )
            Kind.ADD_GROUP_MEMBER -> api.groups().addMember(
                res.groups.getValue(s.spec as String),
                AddMemberRequest(userId = res.users.getValue(s.related!!)),
            )
            Kind.NOOP -> Unit // Never reached: execute() short-circuits a no-op before here.
        }
    }
}
