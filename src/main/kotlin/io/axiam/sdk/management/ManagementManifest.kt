package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import kotlinx.serialization.json.JsonElement

/**
 * A description of the tenant you want (CONTRACT.md §27.6, and §27.6.1 for the
 * `metadata` / two-shape-binding / `service_accounts` additions of contract
 * 1.51).
 *
 * A manifest states what should **exist**. It is not a diff and not a
 * migration: reconciling it against a tenant that already matches writes
 * nothing, and reconciling it twice is the same as reconciling it once.
 *
 * What it never does is delete. Something the manifest does not mention is
 * something the manifest has no opinion about, not something it wants gone
 * (§27.6 rule 4) — otherwise adopting a manifest for five roles would be a
 * request to remove every other role in the tenant.
 *
 * Keys (`docs`, `editor`, `alice`) are **manifest-local** and never reach the
 * server. They exist so one entry can name another before either has an
 * identifier, which is what lets a manifest be written before anything in it
 * exists.
 *
 * @property resources the resource tree, with its scopes
 * @property permissions the permissions that should exist
 * @property roles the roles, with the permissions they grant
 * @property groups the groups, with the roles they hold
 * @property users the users, with their roles and group memberships
 * @property serviceAccounts the service accounts, with the roles they hold
 *   (§27.6.1 item 3, contract 1.51)
 */
data class ManagementManifest(
    val resources: List<ResourceSpec> = emptyList(),
    val permissions: List<PermissionSpec> = emptyList(),
    val roles: List<RoleSpec> = emptyList(),
    val groups: List<GroupSpec> = emptyList(),
    val users: List<UserSpec> = emptyList(),
    val serviceAccounts: List<ServiceAccountSpec> = emptyList(),
) {

    /**
     * A role bound to a subject (a group, a user or a service account) — the
     * two shapes CONTRACT.md §27.6.1 item 2 defines (contract 1.51).
     *
     * [Plain] names a role with no resource: the assignment reaches wherever
     * the role does, and it is refused with 400 if the role is `global` and
     * `inherit` is stated `false` — a global role applies everywhere by
     * definition, so "stop at a resource" is meaningless for one. [Scoped]
     * names a resource and whether the assignment reaches that resource's
     * descendants ([Scoped.inherit], `true` — the default — unless stated
     * `false`).
     *
     * A closed `sealed interface` rather than one class with a nullable
     * `resource`, so a `when` naming both is exhaustive at compile time and a
     * third shape cannot be added by accident.
     */
    sealed interface RoleBinding {
        /** The [RoleSpec.key] this binding is about. */
        val role: String

        /** No resource: the assignment reaches wherever the role does. */
        data class Plain(override val role: String) : RoleBinding

        /**
         * Scoped to a resource.
         *
         * @property resource the [ResourceSpec.key] this binding is scoped to
         * @property inherit whether the assignment also reaches [resource]'s
         *   descendants (`true`, the default) or applies at [resource] only
         *   (`false`). Reaches the wire only when `false` (§27.13 S-10 rule 1)
         *   — an inheriting scoped binding sends no `inherit` key at all.
         */
        data class Scoped(
            override val role: String,
            val resource: String,
            val inherit: Boolean = true,
        ) : RoleBinding

        companion object {
            /** A binding with no resource — the plain shape. */
            fun of(role: String): RoleBinding = Plain(role)

            /** A binding scoped to [resource], reaching its descendants. */
            fun at(role: String, resource: String): RoleBinding = Scoped(role, resource, inherit = true)

            /** A binding scoped to [resource] ONLY — never its descendants. */
            fun atOnly(role: String, resource: String): RoleBinding = Scoped(role, resource, inherit = false)
        }
    }

    /**
     * One resource, and the scopes beneath it.
     *
     * @property key manifest-local identifier, referenced by [parent] and by grants
     * @property name the resource's name, as the server stores it
     * @property resourceType the resource's type
     * @property parent the [key] of this resource's parent, or null for a root
     * @property scopes the scopes that should exist under this resource
     * @property metadata what the resource's `metadata` should be, compared by
     *   equality of the WHOLE object — never a merge. `null` (the default,
     *   distinct from an explicit empty object) means unstated: the field is
     *   silent, whatever the server holds. A stated empty object matches what
     *   the server stores for a resource created with none (§27.6.1 item 1).
     */
    data class ResourceSpec(
        val key: String,
        val name: String,
        val resourceType: String,
        val parent: String? = null,
        val scopes: List<ScopeSpec> = emptyList(),
        val metadata: JsonElement? = null,
    )

    /**
     * One scope beneath a resource.
     *
     * @property key manifest-local identifier, referenced by a grant's scope list
     * @property name the scope's name
     * @property description what the scope is for
     */
    data class ScopeSpec(val key: String, val name: String, val description: String)

    /**
     * One permission.
     *
     * @property key manifest-local identifier, referenced by grants
     * @property action the action this permission allows, e.g. `document:read`
     * @property description what the permission is for
     */
    data class PermissionSpec(val key: String, val action: String, val description: String)

    /**
     * One grant of a permission to a role.
     *
     * @property permission the [PermissionSpec.key] being granted
     * @property effect `"allow"`, `"deny"`, or null for the server's default.
     *   AXIAM's RBAC is DENY-OVERRIDE: a deny beats every allow that reaches
     *   the same principal, at any depth of the resource hierarchy. It is not
     *   "the more specific rule wins".
     * @property scopes the [ScopeSpec.key] values this grant is narrowed to;
     *   empty grants across the whole resource
     */
    data class GrantSpec(
        val permission: String,
        val effect: String? = null,
        val scopes: List<String> = emptyList(),
    )

    /**
     * One role, and what it grants.
     *
     * @property key manifest-local identifier
     * @property name the role's name
     * @property description what the role is for
     * @property global whether the role applies across every resource
     * @property grants the permissions this role should hold
     */
    data class RoleSpec(
        val key: String,
        val name: String,
        val description: String,
        val global: Boolean = false,
        val grants: List<GrantSpec> = emptyList(),
    )

    /**
     * One group, and the roles it holds.
     *
     * @property key manifest-local identifier
     * @property name the group's name
     * @property description what the group is for
     * @property roles the roles this group should hold — a plain
     *   [RoleBinding.Plain] or a resource-scoped [RoleBinding.Scoped]
     *   (§27.6.1 item 2, contract 1.51)
     */
    data class GroupSpec(
        val key: String,
        val name: String,
        val description: String,
        val roles: List<RoleBinding> = emptyList(),
    )

    /**
     * One user, with their roles and group memberships.
     *
     * @property key manifest-local identifier
     * @property username the user's username
     * @property email the user's email address
     * @property initialPassword the password to CREATE the user with. Used only
     *   when the user does not exist: a manifest that mentions a password is
     *   not a request to reset one, so reconciling against an existing user
     *   never sends it (§27.6 rule 3).
     * @property roles the roles this user should hold directly — a plain
     *   [RoleBinding.Plain] or a resource-scoped [RoleBinding.Scoped]
     *   (§27.6.1 item 2, contract 1.51)
     * @property groups the [GroupSpec.key] values this user should belong to
     */
    data class UserSpec(
        val key: String,
        val username: String,
        val email: String,
        val initialPassword: Sensitive<String>? = null,
        val roles: List<RoleBinding> = emptyList(),
        val groups: List<String> = emptyList(),
    )

    /**
     * One service account, and the roles it holds (CONTRACT.md §27.6.1 item 3,
     * contract 1.51).
     *
     * Reconciled by [name] — the server does not keep it unique, only
     * `client_id` is indexed, so a manifest naming more than one existing
     * match fails `plan` before any write rather than picking one arbitrarily.
     * [description] is the only field an `Update` reconciles (`name` and
     * `status` are left alone). The one-time `client_secret` a `Create`
     * returns is carried on the apply report's outcome for that step, even
     * when a later step of the same apply fails — see
     * `ApplyReport.createdServiceAccounts()` — and `apply` never rotates one
     * to reconcile: an account whose secret nobody kept is a `NoChange` on
     * every later plan, not a standing invitation to mint a new one.
     *
     * @property key manifest-local identifier
     * @property name the account's name — the reconciliation key
     * @property description what the account is for; `null` is silent (§27.6
     *   rule 3), never a request to clear an existing one
     * @property roles the roles this account should hold — a plain
     *   [RoleBinding.Plain] or a resource-scoped [RoleBinding.Scoped]
     */
    data class ServiceAccountSpec(
        val key: String,
        val name: String,
        val description: String? = null,
        val roles: List<RoleBinding> = emptyList(),
    )

    companion object {
        /** A manifest that describes nothing, and therefore changes nothing. */
        fun empty(): ManagementManifest = ManagementManifest()

        /** Starts a [Builder]. */
        fun builder(): Builder = Builder()
    }

    /**
     * Builds a manifest, checking back-references as they are made.
     *
     * The record form accepts a grant naming a role that does not exist; this
     * does not. A forward reference the builder lets through becomes a null
     * dereference deep inside `apply`, **after** part of the tenant has already
     * been written — so every call that names an earlier key checks it, and
     * [build] reports every problem at once rather than the first (§27.6
     * rule 1).
     */
    class Builder internal constructor() {

        private val resources = mutableListOf<ResourceSpec>()
        private val scopes = mutableMapOf<String, MutableList<ScopeSpec>>()
        private val permissions = mutableListOf<PermissionSpec>()
        private val roles = mutableListOf<RoleSpec>()
        private val grants = mutableMapOf<String, MutableList<GrantSpec>>()
        private val groups = mutableListOf<GroupSpec>()
        private val groupRoles = mutableMapOf<String, MutableList<RoleBinding>>()
        private val users = mutableListOf<UserSpec>()
        private val userRoles = mutableMapOf<String, MutableList<RoleBinding>>()
        private val userGroups = mutableMapOf<String, MutableList<String>>()
        private val serviceAccounts = mutableListOf<ServiceAccountSpec>()
        private val serviceAccountRoles = mutableMapOf<String, MutableList<RoleBinding>>()
        private val problems = mutableListOf<String>()

        /**
         * Declares a root resource.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the resource's type
         * @param metadata what the resource's `metadata` should be; `null`
         *   (the default) leaves it unstated (§27.6.1 item 1)
         * @return this builder
         */
        fun resource(
            key: String,
            name: String,
            resourceType: String,
            metadata: JsonElement? = null,
        ): Builder = apply {
            resources += ResourceSpec(key, name, resourceType, metadata = metadata)
        }

        /**
         * Declares a resource beneath [parentKey].
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the resource's type
         * @param parentKey the [key] of an already-declared resource
         * @param metadata what the resource's `metadata` should be; `null`
         *   (the default) leaves it unstated (§27.6.1 item 1)
         * @return this builder
         */
        fun childResource(
            key: String,
            name: String,
            resourceType: String,
            parentKey: String,
            metadata: JsonElement? = null,
        ): Builder =
            apply {
                if (resources.none { it.key == parentKey }) {
                    problems += "childResource '$key' names parent '$parentKey', " +
                        "which no resource(...) call has declared yet"
                    return@apply
                }
                resources += ResourceSpec(key, name, resourceType, parentKey, metadata = metadata)
            }

        /**
         * Declares a scope beneath [resourceKey].
         *
         * @param resourceKey the [ResourceSpec.key] this scope belongs to
         * @param key manifest-local identifier
         * @param name the scope's name
         * @param description what the scope is for
         * @return this builder
         */
        fun scope(resourceKey: String, key: String, name: String, description: String): Builder =
            apply {
                if (resources.none { it.key == resourceKey }) {
                    problems += "scope '$key' names resource '$resourceKey', " +
                        "which no resource(...) call has declared yet"
                    return@apply
                }
                scopes.getOrPut(resourceKey) { mutableListOf() } += ScopeSpec(key, name, description)
            }

        /**
         * Declares a permission.
         *
         * @param key manifest-local identifier
         * @param action the action it allows
         * @param description what it is for
         * @return this builder
         */
        fun permission(key: String, action: String, description: String): Builder = apply {
            permissions += PermissionSpec(key, action, description)
        }

        /**
         * Declares a role.
         *
         * @param key manifest-local identifier
         * @param name the role's name
         * @param description what it is for
         * @return this builder
         */
        fun role(key: String, name: String, description: String): Builder = apply {
            roles += RoleSpec(key, name, description, global = false)
        }

        /**
         * Declares a role that applies across every resource.
         *
         * @param key manifest-local identifier
         * @param name the role's name
         * @param description what it is for
         * @return this builder
         */
        fun globalRole(key: String, name: String, description: String): Builder = apply {
            roles += RoleSpec(key, name, description, global = true)
        }

        /**
         * Grants a permission to the role named by [roleKey].
         *
         * @param roleKey the role receiving the grant
         * @param permissionKey the permission being granted
         * @param effect `"allow"`, `"deny"`, or null for the server's default
         * @param scopeKeys the scopes this grant is narrowed to; pass none to
         *   grant across the whole resource
         * @return this builder
         */
        fun grant(
            roleKey: String,
            permissionKey: String,
            effect: String? = null,
            vararg scopeKeys: String,
        ): Builder = apply {
            if (roles.none { it.key == roleKey }) {
                problems += "grant of '$permissionKey' names role '$roleKey', " +
                    "which no role(...) call has declared yet"
                return@apply
            }
            grants.getOrPut(roleKey) { mutableListOf() } +=
                GrantSpec(permissionKey, effect, scopeKeys.toList())
        }

        /**
         * Declares a group, optionally holding roles with NO resource (the
         * plain shape). For a resource-scoped binding, declare the group here
         * with no roles and call [bindGroupRole].
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description what it is for
         * @param roleKeys the roles this group should hold, with no resource
         * @return this builder
         */
        fun group(key: String, name: String, description: String, vararg roleKeys: String): Builder =
            apply {
                groups += GroupSpec(key, name, description)
                if (roleKeys.isNotEmpty()) {
                    groupRoles.getOrPut(key) { mutableListOf() } += roleKeys.map { RoleBinding.of(it) }
                }
            }

        /**
         * Binds [binding] (§27.6.1 item 2 — plain or resource-scoped) to the
         * group named by [groupKey], in addition to whatever [group] already
         * declared.
         *
         * @param groupKey the group receiving the binding
         * @param binding the role binding — [RoleBinding.of], [RoleBinding.at]
         *   or [RoleBinding.atOnly]
         * @return this builder
         */
        fun bindGroupRole(groupKey: String, binding: RoleBinding): Builder = apply {
            if (groups.none { it.key == groupKey }) {
                problems += "bindGroupRole names group '$groupKey', " +
                    "which no group(...) call has declared yet"
                return@apply
            }
            groupRoles.getOrPut(groupKey) { mutableListOf() } += binding
        }

        /**
         * Declares a user.
         *
         * @param key manifest-local identifier
         * @param username the user's username
         * @param email the user's email address
         * @param initialPassword the password to CREATE the user with; never
         *   sent for a user that already exists
         * @return this builder
         */
        fun user(
            key: String,
            username: String,
            email: String,
            initialPassword: Sensitive<String>? = null,
        ): Builder = apply {
            users += UserSpec(key, username, email, initialPassword)
        }

        /**
         * Assigns the role named by [roleKey] to the user named by [userKey],
         * with no resource (the plain shape).
         *
         * @param userKey the user receiving the role
         * @param roleKey the role being assigned
         * @return this builder
         */
        fun assignRole(userKey: String, roleKey: String): Builder = assignRole(userKey, RoleBinding.of(roleKey))

        /**
         * Binds [binding] (§27.6.1 item 2 — plain or resource-scoped) to the
         * user named by [userKey].
         *
         * @param userKey the user receiving the binding
         * @param binding the role binding — [RoleBinding.of], [RoleBinding.at]
         *   or [RoleBinding.atOnly]
         * @return this builder
         */
        fun assignRole(userKey: String, binding: RoleBinding): Builder = apply {
            if (users.none { it.key == userKey }) {
                problems += "assignRole names user '$userKey', " +
                    "which no user(...) call has declared yet"
                return@apply
            }
            userRoles.getOrPut(userKey) { mutableListOf() } += binding
        }

        /**
         * Puts the user named by [userKey] into the group named by [groupKey].
         *
         * @param userKey the user joining the group
         * @param groupKey the group being joined
         * @return this builder
         */
        fun addToGroup(userKey: String, groupKey: String): Builder = apply {
            if (users.none { it.key == userKey }) {
                problems += "addToGroup names user '$userKey', " +
                    "which no user(...) call has declared yet"
                return@apply
            }
            userGroups.getOrPut(userKey) { mutableListOf() } += groupKey
        }

        /**
         * Declares a service account (CONTRACT.md §27.6.1 item 3, contract
         * 1.51). Reconciled by [name].
         *
         * @param key manifest-local identifier
         * @param name the account's name — the reconciliation key
         * @param description what it is for; `null` (the default) leaves it
         *   unstated
         * @return this builder
         */
        fun serviceAccount(key: String, name: String, description: String? = null): Builder = apply {
            serviceAccounts += ServiceAccountSpec(key, name, description)
        }

        /**
         * Binds [binding] (§27.6.1 item 2 — plain or resource-scoped) to the
         * service account named by [serviceAccountKey].
         *
         * @param serviceAccountKey the account receiving the binding
         * @param binding the role binding — [RoleBinding.of], [RoleBinding.at]
         *   or [RoleBinding.atOnly]
         * @return this builder
         */
        fun bindServiceAccountRole(serviceAccountKey: String, binding: RoleBinding): Builder = apply {
            if (serviceAccounts.none { it.key == serviceAccountKey }) {
                problems += "bindServiceAccountRole names service account '$serviceAccountKey', " +
                    "which no serviceAccount(...) call has declared yet"
                return@apply
            }
            serviceAccountRoles.getOrPut(serviceAccountKey) { mutableListOf() } += binding
        }

        /**
         * Assembles the manifest, or throws if any back-reference is dangling.
         *
         * @return the assembled manifest
         * @throws NetworkError if any call named a key that was never declared
         */
        fun build(): ManagementManifest {
            if (problems.isNotEmpty()) {
                throw NetworkError(
                    "this manifest cannot be built:\n  - " + problems.joinToString("\n  - ") +
                        "\n\nEvery problem is listed rather than only the first: fixing them one " +
                        "build at a time is the slowest possible way to learn about six of them.",
                )
            }
            return ManagementManifest(
                resources = resources.map { it.copy(scopes = scopes[it.key].orEmpty()) },
                permissions = permissions.toList(),
                roles = roles.map { it.copy(grants = grants[it.key].orEmpty()) },
                groups = groups.map { it.copy(roles = groupRoles[it.key].orEmpty()) },
                users = users.map {
                    it.copy(
                        roles = userRoles[it.key].orEmpty(),
                        groups = userGroups[it.key].orEmpty(),
                    )
                },
                serviceAccounts = serviceAccounts.map { it.copy(roles = serviceAccountRoles[it.key].orEmpty()) },
            )
        }
    }
}
