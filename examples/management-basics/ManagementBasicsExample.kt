package io.axiam.sdk.examples.managementbasics

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.PageRequest
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateUserRequest
import io.axiam.sdk.management.models.UpdateUserRequest
import kotlinx.coroutines.runBlocking
import java.util.UUID

/**
 * Walks the CONTRACT.md §27 management surface: namespace handles, paging,
 * sparse updates, one-time secrets, and the three error classifications.
 *
 * Every call goes through `client.management()`, which is a view over the same
 * session the rest of the SDK uses — there is no second client to build, no
 * second login, and no second set of TLS settings to get wrong.
 *
 * Run: `AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
 * ./gradlew runManagementBasicsExample`
 */
object ManagementBasicsExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        val tenant = env("AXIAM_TENANT", "acme")
        val admin = env("AXIAM_ADMIN", "admin@example.com")
        val password = env("AXIAM_ADMIN_PASSWORD", "changeme")

        AxiamClient.builder(baseUrl, tenant).orgSlug(tenant).build().use { client ->
            client.login(admin, password)

            // §27.2: a handle is a view, not a connection. Acquiring one is free
            // and performs no I/O, so holding onto it buys nothing.
            println("org    : ${client.resolvedOrgId()}")
            println("tenant : ${client.resolvedTenantId()}")

            // ----------------------------------------------------------
            // §27.4 rule 4 — paging
            // ----------------------------------------------------------

            // total is the size of the WHOLE set, not of this page. Treating
            // items.size as the total is the bug this type exists to stop.
            val firstPage = client.management().users().list(PageRequest.of(25))
            println("users  : ${firstPage.items.size} of ${firstPage.total}")

            // listAll walks to exhaustion. It stops on an empty page even if the
            // server's total disagrees, so a miscounting server costs one wasted
            // request rather than an unbounded loop.
            println("roles  : ${client.management().roles().listAll().size}")

            // ----------------------------------------------------------
            // §27.4 rule 5 — sparse update vs replacement
            // ----------------------------------------------------------

            firstPage.items.firstOrNull()?.let { user ->
                // A sparse body sends ONLY the properties you name. Everything
                // you leave out is absent from the JSON entirely — not sent as
                // null, which the server would read as "clear this field".
                // Kotlin needs no builder for this: the defaults are the API.
                client.management().users()
                    .update(user.id, UpdateUserRequest(email = "renamed@example.test"))
            }

            // A replacement body has no defaults: its constructor takes every
            // property, so forgetting one is a compile error rather than a
            // silent overwrite with null.
            val created = client.management().roles()
                .create(CreateRoleRequest("Edits documents", isGlobal = false, name = "Editor"))
            println("created: ${created.id}")

            // ----------------------------------------------------------
            // §27.4 rule 7 — the three classifications
            // ----------------------------------------------------------

            // Each inherits the parent §2 already gave its status, so code that
            // already catches AuthzError or NetworkError keeps working, and
            // code that wants the distinction can ask for it.
            try {
                client.management().users().get(UUID.randomUUID())
            } catch (e: NotFoundError) {
                println("404 -> NotFoundError (an AuthzError): ${e.message}")
            }

            try {
                client.management().roles()
                    .create(CreateRoleRequest("Edits documents", isGlobal = false, name = "Editor"))
            } catch (e: ConflictError) {
                // Also an AuthzError: §2 already mapped 409 there, and the
                // sub-type keeps that mapping rather than moving the status.
                println("409 -> ConflictError: ${e.message}")
            }

            try {
                client.management().users().create(
                    CreateUserRequest(
                        email = "not-an-email",
                        password = Sensitive.of("correct-horse-battery"),
                        username = "someone",
                    ),
                )
            } catch (e: ValidationError) {
                // A ValidationError carries the server's per-field detail when
                // it sent any, so the caller can point at the offending input.
                println("400 -> ValidationError on: ${e.fields.map { it.field }}")
            }

            // §27.4 rule 8: only GETs are retried. A create that times out is
            // reported, never repeated — one retried POST is two roles.
        }
    }

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
