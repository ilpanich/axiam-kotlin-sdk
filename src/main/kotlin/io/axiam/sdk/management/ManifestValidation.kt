package io.axiam.sdk.management

import io.axiam.sdk.errors.NetworkError

/**
 * Checks a [ManagementManifest] before a single request goes out
 * (CONTRACT.md §27.6 rule 1).
 *
 * Everything here is answerable from the manifest alone, so it is answered
 * from the manifest alone: a dangling reference or a cycle discovered halfway
 * through an apply leaves the tenant part-reconciled, and the fix is one the
 * caller could have been told about before anything was written.
 */
internal object ManifestValidation {

    /**
     * Reports every problem at once, or nothing.
     *
     * Every problem rather than the first: fixing them one run at a time is
     * the slowest possible way to learn about six of them.
     */
    fun validate(manifest: ManagementManifest) {
        val problems = mutableListOf<String>()
        val resourceKeys = manifest.resources.map { it.key }.toSet()
        val scopeKeys = manifest.resources.flatMap { r -> r.scopes.map { it.key } }.toSet()
        val permissionKeys = manifest.permissions.map { it.key }.toSet()
        val roleKeys = manifest.roles.map { it.key }.toSet()
        val groupKeys = manifest.groups.map { it.key }.toSet()

        duplicates(manifest.resources.map { it.key }, "resource", problems)
        duplicates(manifest.permissions.map { it.key }, "permission", problems)
        duplicates(manifest.roles.map { it.key }, "role", problems)
        duplicates(manifest.groups.map { it.key }, "group", problems)
        duplicates(manifest.users.map { it.key }, "user", problems)

        for (resource in manifest.resources) {
            val parent = resource.parent
            if (parent != null && parent !in resourceKeys) {
                problems += "resource '${resource.key}' names parent '$parent', which no " +
                    "resource declares"
            }
        }
        for (role in manifest.roles) {
            for (grant in role.grants) {
                if (grant.permission !in permissionKeys) {
                    problems += "role '${role.key}' grants '${grant.permission}', which no " +
                        "permission declares"
                }
                for (scope in grant.scopes) {
                    if (scope !in scopeKeys) {
                        problems += "role '${role.key}' narrows a grant to scope '$scope', " +
                            "which no resource declares"
                    }
                }
                val effect = grant.effect
                if (effect != null && effect != "allow" && effect != "deny") {
                    problems += "role '${role.key}' grants '${grant.permission}' with effect " +
                        "'$effect'; only 'allow' and 'deny' exist"
                }
            }
        }
        for (group in manifest.groups) {
            for (role in group.roles) {
                if (role !in roleKeys) {
                    problems += "group '${group.key}' holds role '$role', which no role declares"
                }
            }
        }
        for (user in manifest.users) {
            for (role in user.roles) {
                if (role !in roleKeys) {
                    problems += "user '${user.key}' holds role '$role', which no role declares"
                }
            }
            for (group in user.groups) {
                if (group !in groupKeys) {
                    problems += "user '${user.key}' joins group '$group', which no group declares"
                }
            }
        }

        cycle(manifest)?.let { problems += it }

        if (problems.isNotEmpty()) {
            throw NetworkError(
                "this manifest cannot be reconciled:\n  - " + problems.joinToString("\n  - ") +
                    "\n\nNothing was sent: §27.6 rule 1 refuses a manifest before the first " +
                    "request rather than part-way through an apply.",
            )
        }
    }

    private fun duplicates(keys: List<String>, what: String, problems: MutableList<String>) {
        keys.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.sorted().forEach {
            problems += "$what key '$it' is declared more than once; keys must be unique"
        }
    }

    /**
     * Names a resource cycle, or null.
     *
     * A cycle is not merely invalid, it is unreconcilable: neither resource can
     * be created before the other, and a reconciler that did not check would
     * loop rather than fail.
     */
    private fun cycle(manifest: ManagementManifest): String? {
        val parents = manifest.resources.associate { it.key to it.parent }
        for (start in parents.keys.sorted()) {
            var seen = mutableSetOf(start)
            var at = parents[start]
            while (at != null) {
                if (!seen.add(at)) {
                    return "resource '$start' is its own ancestor via '$at'; a parent cycle " +
                        "can never be created in any order"
                }
                at = parents[at]
            }
        }
        return null
    }

    /**
     * Resource keys ordered so a parent always precedes its children.
     *
     * §27.6 rule 2: ordering is DERIVED, not declared. A manifest that lists a
     * child first is not wrong, it is just a manifest — the reconciler is what
     * knows a parent has to exist first.
     */
    fun topologicalOrder(manifest: ManagementManifest): List<String> {
        val parents = manifest.resources.associate { it.key to it.parent }
        val ordered = mutableListOf<String>()
        val placed = mutableSetOf<String>()

        fun place(key: String) {
            if (key in placed) return
            parents[key]?.let { if (it in parents) place(it) }
            if (placed.add(key)) ordered += key
        }
        manifest.resources.forEach { place(it.key) }
        return ordered
    }
}
