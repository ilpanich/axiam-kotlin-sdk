package io.axiam.sdk.examples.managementbasics

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.PageRequest
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateUserRequest
import io.axiam.sdk.management.models.TenantKind
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
            // §27.4 rule 4 — search rides on the page request
            // ----------------------------------------------------------

            // The term goes where offset and limit already live, rather than
            // becoming a third argument on each of the twenty list methods.
            // That is what makes listAll carry it across the whole walk: a walk
            // that filtered page one and not page two would hand back the
            // matches followed by the unfiltered tail.
            //
            // The SERVER filters, before offset/limit, so total counts MATCHES.
            // Filtering the list here in Kotlin would give you neither that nor
            // a page count that belongs to the set it labels.
            val matches = client.management().users().list(PageRequest.matching(25, "ada"))
            println("matches: ${matches.total} users match \"ada\"")

            // Blank is the same request as unset: no search key at all. A box
            // that fires on every keystroke sends one of these the moment it is
            // cleared, and "rows containing the empty string" is a different
            // question from "all rows".
            val cleared = client.management().users().list(PageRequest.matching(25, "   "))
            println("cleared: ${cleared.total} (everything again)")

            // The server caps the term's length. This SDK does not copy that
            // cap: a truncation the server would not have made is a silently
            // different query, with nothing to say so.

            // ----------------------------------------------------------
            // §27.11 — open enums, and nulls that are not zero
            // ----------------------------------------------------------

            // kotlinx.serialization's own enum serializer THROWS on a value
            // outside the constants, which fails the whole response — taking
            // down every tenant on the page over one field of one of them,
            // including the ones you were after. The generated serializer
            // decodes it to UNKNOWN instead (§27.11 rule 1), so a `when` over
            // these constants needs an UNKNOWN branch.
            for (tenant in client.management().tenants().list(PageRequest.of(5)).items) {
                when (tenant.kind) {
                    // A row written before organization scope existed. Read it
                    // as standard — that is what it is.
                    null -> println("tenant : ${tenant.slug} (no kind recorded)")
                    TenantKind.UNKNOWN -> println(
                        "tenant : ${tenant.slug} (a kind this SDK does not know — " +
                            "leave it out of any update)",
                    )
                    else -> println("tenant : ${tenant.slug} ${tenant.kind}")
                }
            }

            // Certificate.boundServiceAccountId is resolved by list() and is
            // null on get(). Null there means "this read does not carry it",
            // not "there is nothing bound" — the SDK spends no second request
            // filling it in behind you. MtlsTrustAnchorResponse.trustedAnchors
            // reads the same way: null means NOTHING WAS RELOADED, not that the
            // listener trusts zero CAs.
            client.management().certificates().list(PageRequest.of(5)).items
                .filter { it.boundServiceAccountId != null }
                .forEach { println("cert   : ${it.id} authenticates ${it.boundServiceAccountId}") }

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
