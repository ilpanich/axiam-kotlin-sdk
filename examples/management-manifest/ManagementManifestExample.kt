package io.axiam.sdk.examples.managementmanifest

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.management.ManagementManifest
import kotlinx.coroutines.runBlocking

/**
 * The CONTRACT.md §27.6 declarative layer: describe the tenant you want, see
 * what would change, then apply it.
 *
 * A manifest states what should exist. It is not a diff and not a migration:
 * running it against a tenant that already matches writes nothing, and running
 * it twice is the same as running it once. What it never does is delete —
 * something the manifest does not mention is something the manifest has no
 * opinion about, not something it wants gone (§27.6 rule 4).
 *
 * Run: `AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
 * ./gradlew runManagementManifestExample --args="--apply"`
 */
object ManagementManifestExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val apply = args.firstOrNull() == "--apply"
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        val tenant = env("AXIAM_TENANT", "acme")
        val admin = env("AXIAM_ADMIN", "admin@example.com")
        val password = env("AXIAM_ADMIN_PASSWORD", "changeme")

        // The builder checks back-references as they are made: a grant naming a
        // role no role(...) call has declared is refused at build(), before any
        // request. Ordering between KINDS is derived (resources before scopes,
        // permissions before grants), so this reads top-down but need not.
        val manifest = ManagementManifest.builder()
            .resource("docs", "documents", "collection")
            .scope("docs", "draft", "draft", "Unpublished work")
            .childResource("archive", "archive", "collection", "docs")
            .permission("read", "document:read", "Read a document")
            .permission("purge", "document:purge", "Permanently delete a document")
            .role("editor", "Editor", "Edits documents")
            // A grant narrowed to a scope applies only within it.
            .grant("editor", "read", null, "draft")
            // AXIAM's RBAC is DENY-OVERRIDE: this refusal beats every allow that
            // reaches the same principal, at any depth of the resource
            // hierarchy. It is not "the more specific rule wins".
            .grant("editor", "purge", "deny")
            .group("staff", "Staff", "Everyone in the company", "editor")
            .user("alice", "alice", "alice@example.test", Sensitive.of("correct-horse-battery"))
            .assignRole("alice", "editor")
            .addToGroup("alice", "staff")
            .build()

        AxiamClient.builder(baseUrl, tenant).orgSlug(tenant).build().use { client ->
            client.login(admin, password)

            // plan() issues reads and nothing else — it cannot change the
            // tenant, so it is safe to run against production to find out what
            // an apply would do.
            val plan = client.management().manifest().plan(manifest)
            println(
                if (plan.isConverged) {
                    "tenant already matches the manifest; nothing to do"
                } else {
                    "${plan.changes.size} change(s) pending:"
                },
            )
            for (action in plan.changes) {
                println("  ${action.change} ${action.target}  ${action.summary}")
            }

            if (!apply) {
                println("(re-run with --apply to execute)")
                return@use
            }

            // apply() stops at the FIRST failure and does not roll back (§27.6
            // rule 7). Everything before the failure stands; everything after it
            // is reported as never attempted. That is deliberate: an automatic
            // rollback would be a second unreviewed batch of writes issued at
            // exactly the moment the tenant is in an unknown state.
            val report = client.management().manifest().apply(manifest)
            for (step in report.steps) {
                println("  %-13s %s".format(step.outcome.status, step.action.summary))
            }
            report.failure?.let {
                println("stopped at: ${it.action.summary} -- ${it.outcome.message}")
            }
            println(
                if (report.isComplete) {
                    "applied ${report.changedCount} change(s)"
                } else {
                    "INCOMPLETE: fix the failure above and re-run; what succeeded stands"
                },
            )
        }
    }

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
