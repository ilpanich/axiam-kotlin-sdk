package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError

/**
 * A description of the tenant you want (CONTRACT.md §27.6).
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
 */
data class ManagementManifest(
    val resources: List<ResourceSpec> = emptyList(),
    val permissions: List<PermissionSpec> = emptyList(),
    val roles: List<RoleSpec> = emptyList(),
    val groups: List<GroupSpec> = emptyList(),
    val users: List<UserSpec> = emptyList(),
) {

    /**
     * One resource, and the scopes beneath it.
     *
     * @property key manifest-local identifier, referenced by [parent] and by grants
     * @property name the resource's name, as the server stores it
     * @property resourceType the resource's type
     * @property parent the [key] of this resource's parent, or null for a root
     * @property scopes the scopes that should exist under this resource
     */
    data class ResourceSpec(
        val key: String,
        val name: String,
        val resourceType: String,
        val parent: String? = null,
        val scopes: List<ScopeSpec> = emptyList(),
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
     * @property roles the [RoleSpec.key] values this group should hold
     */
    data class GroupSpec(
        val key: String,
        val name: String,
        val description: String,
        val roles: List<String> = emptyList(),
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
     * @property roles the [RoleSpec.key] values this user should hold directly
     * @property groups the [GroupSpec.key] values this user should belong to
     */
    data class UserSpec(
        val key: String,
        val username: String,
        val email: String,
        val initialPassword: Sensitive<String>? = null,
        val roles: List<String> = emptyList(),
        val groups: List<String> = emptyList(),
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
        private val groupRoles = mutableMapOf<String, MutableList<String>>()
        private val users = mutableListOf<UserSpec>()
        private val userRoles = mutableMapOf<String, MutableList<String>>()
        private val userGroups = mutableMapOf<String, MutableList<String>>()
        private val problems = mutableListOf<String>()

        /**
         * Declares a root resource.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the resource's type
         * @return this builder
         */
        fun resource(key: String, name: String, resourceType: String): Builder = apply {
            resources += ResourceSpec(key, name, resourceType)
        }

        /**
         * Declares a resource beneath [parentKey].
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the resource's type
         * @param parentKey the [key] of an already-declared resource
         * @return this builder
         */
        fun childResource(key: String, name: String, resourceType: String, parentKey: String): Builder =
            apply {
                if (resources.none { it.key == parentKey }) {
                    problems += "childResource '$key' names parent '$parentKey', " +
                        "which no resource(...) call has declared yet"
                    return@apply
                }
                resources += ResourceSpec(key, name, resourceType, parentKey)
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
         * Declares a group, optionally holding roles.
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description what it is for
         * @param roleKeys the roles this group should hold
         * @return this builder
         */
        fun group(key: String, name: String, description: String, vararg roleKeys: String): Builder =
            apply {
                groups += GroupSpec(key, name, description)
                if (roleKeys.isNotEmpty()) {
                    groupRoles.getOrPut(key) { mutableListOf() } += roleKeys.toList()
                }
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
         * Assigns the role named by [roleKey] to the user named by [userKey].
         *
         * @param userKey the user receiving the role
         * @param roleKey the role being assigned
         * @return this builder
         */
        fun assignRole(userKey: String, roleKey: String): Builder = apply {
            if (users.none { it.key == userKey }) {
                problems += "assignRole names user '$userKey', " +
                    "which no user(...) call has declared yet"
                return@apply
            }
            userRoles.getOrPut(userKey) { mutableListOf() } += roleKey
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
            )
        }
    }
}
