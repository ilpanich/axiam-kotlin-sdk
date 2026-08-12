package io.axiam.sdk.examples.umaresourceserver

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.ktor.AxiamAuthentication
import io.axiam.sdk.ktor.UmaChallenger
import io.axiam.sdk.ktor.requireAccess
import io.axiam.sdk.oidc.LoginClientCredentialsParams
import io.axiam.sdk.oidc.ResourceSet
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking

/**
 * UMA 2.0 (CONTRACT.md §20) — the **resource-server** half of the pair.
 *
 * The situation: this service holds invoices that belong to *users*, not to
 * itself. When someone asks for one, the useful answer is not just "no" — it is
 * "not with what you're carrying, and here is where to go and get better". That
 * actionable refusal is what UMA adds over plain RBAC.
 *
 * What this shows, in order:
 *
 *  1. Mint a **PAT** — a client-credentials token carrying `uma_protection`.
 *     §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
 *     `client_id` that minted it, so a user token cannot stand in.
 *  2. **Register** the resource this service guards. The returned id *is* the
 *     AXIAM resource id — there is no parallel resource store to keep in sync.
 *  3. Install [AxiamAuthentication] with a [UmaChallenger], so a denial from
 *     [requireAccess] carries `WWW-Authenticate: UMA` with a fresh ticket.
 *
 * Its counterpart is [io.axiam.sdk.examples.umaclient.UmaClientExample], which
 * consumes that header.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_OIDC_CLIENT_ID=... AXIAM_OIDC_CLIENT_SECRET=... \
 *   ./gradlew runUmaResourceServerExample
 * ```
 */
object UmaResourceServerExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        val tenantSlug = env("AXIAM_TENANT_SLUG", "acme")
        val port = env("AXIAM_PORT", "8081").toInt()

        val client = AxiamClient.builder(baseUrl, tenantSlug)
            .oidcClientId(env("AXIAM_OIDC_CLIENT_ID", "invoices-resource-server"))
            .oidcClientSecret(env("AXIAM_OIDC_CLIENT_SECRET", "resource-server-secret"))
            .build()

        // ---- 1. The PAT ----
        //
        // §20.2 rule 1: a client-credentials token carrying `uma_protection`.
        // Not a user token, and not this client's ambient session — the SDK
        // will not substitute either, and the Protection API would refuse them.
        val session = client.loginClientCredentials(
            LoginClientCredentialsParams(scope = "uma_protection"),
        )
        val pat = session.accessToken

        // ---- 2. Registration ----
        //
        // Registering the same name twice creates two resources, so a real
        // service registers once at provisioning time and stores the id, or
        // reconciles by listing. Inline here because it is the step that shows
        // the returned id is the AXIAM resource id.
        val registered = client.umaRegisterResource(
            pat,
            ResourceSet(
                name = "invoice-7",
                type = "invoice",
                // The declared scopes are the allow-list the permission
                // endpoint validates a ticket request against. A resource
                // registered with none can never appear in a ticket.
                resourceScopes = listOf("invoices:read", "invoices:approve"),
            ),
        )

        // ---- 3. The challenger ----
        //
        // `asUri` names where the caller should redeem the ticket. Read it from
        // the discovery document rather than assembling it by hand — a
        // deployment is free to move its endpoints, which is why §12.3 rule 6
        // forbids hardcoding them.
        val configuration = client.oidcDiscover()
        val challenger = UmaChallenger("invoices", configuration.issuer, pat, client)

        println("registered invoice-7 as ${registered.id}")
        println("try:  curl -i http://127.0.0.1:$port/invoices/${registered.id}")

        embeddedServer(Netty, port = port) {
            // The load-bearing line is `umaChallenge`. Without it this is an
            // ordinary §11 guard and a denial is a bare 403; with it, the
            // denial carries a ticket and the caller can act on it.
            install(AxiamAuthentication) {
                this.client = client
                this.umaChallenge = challenger
            }
            routing {
                get("/invoices/{invoiceId}") {
                    // Reached only when the engine allowed it — including
                    // honouring any deny rule, which UMA does not bypass: the
                    // ticket minted on a refusal asks for the same action this
                    // check just evaluated, so the same grants and denies apply
                    // to whatever RPT comes back.
                    val invoiceId = call.parameters["invoiceId"] ?: ""
                    val user = call.requireAccess("invoices:read", invoiceId) ?: return@get
                    call.respondText("""{"id":"$invoiceId","total":"42.00","reader":"${user.userId}"}""")
                }
            }
        }.start(wait = true)
    }

    private fun env(key: String, fallback: String): String =
        System.getenv(key)?.takeIf { it.isNotBlank() } ?: fallback
}
