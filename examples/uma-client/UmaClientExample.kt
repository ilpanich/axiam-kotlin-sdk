package io.axiam.sdk.examples.umaclient

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.oidc.UmaExchangeTicketParams
import io.axiam.sdk.oidc.umaParseChallenge
import kotlinx.coroutines.runBlocking
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * UMA 2.0 (CONTRACT.md §20) — the **client** half of the pair.
 *
 * Run [io.axiam.sdk.examples.umaresourceserver.UmaResourceServerExample] first;
 * this program talks to it.
 *
 * The flow, which is the whole reason UMA exists:
 *
 *  1. Ask for the invoice with the user's ordinary token. The resource server
 *     refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket and
 *     an authorization server.
 *  2. **Parse** the challenge. Note what happens next, and what does not:
 *     parsing performs no exchange (§20.3). The `as_uri` in that header is a
 *     host the *server we just failed against* chose; auto-redeeming would send
 *     the user's token wherever a 403 pointed.
 *  3. Decide to trust it, then **exchange** the ticket for an RPT.
 *  4. Retry with the RPT.
 *
 * Step 3 is a decision, not a formality — this example makes it explicitly, by
 * comparing the nominated `as_uri` against the issuer this client already
 * trusts, and refusing when they differ.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_INVOICE_ID=... ./gradlew runUmaClientExample
 * ```
 */
object UmaClientExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val resourceServer = env("AXIAM_RESOURCE_SERVER", "http://127.0.0.1:8081")
        // The resource server printed this id when it registered.
        val invoiceId = env("AXIAM_INVOICE_ID", "00000000-0000-0000-0000-000000000000")
        // The requesting party's own token — what this program would normally
        // send and, in step 3, the `claim_token` that names *who* is asking.
        val userToken = env("AXIAM_USER_TOKEN", "the-requesting-partys-access-token")

        val http = HttpClient.newHttpClient()
        val url = URI.create("$resourceServer/invoices/$invoiceId")

        // The exchange is a token-endpoint grant, so this client is confidential.
        val client = AxiamClient.builder(
            env("AXIAM_BASE_URL", "https://localhost:8443"),
            env("AXIAM_TENANT_SLUG", "acme"),
        )
            .oidcClientId(env("AXIAM_OIDC_CLIENT_ID", "invoices-client"))
            .oidcClientSecret(env("AXIAM_OIDC_CLIENT_SECRET", "client-secret"))
            .build()

        client.use {
            // ---- 1. The refusal ----
            val refused = http.send(get(url, userToken), HttpResponse.BodyHandlers.ofString())
            println("first attempt: ${refused.statusCode()}")

            val header = refused.headers().firstValue("WWW-Authenticate").orElse(null)
            if (header == null) {
                // A resource server that refuses without a challenge is telling
                // you it has nothing to offer — there is no ticket to redeem,
                // and retrying the same request would be pointless.
                println("no WWW-Authenticate header: this refusal is not actionable.")
                return@use
            }

            // ---- 2. Parse, and only parse ----
            val challenge = umaParseChallenge(header)
            val ticket = challenge?.ticket
            if (ticket == null) {
                println("the challenge names no ticket; nothing to redeem.")
                return@use
            }

            // Nothing from the challenge is echoed, and there are two separate
            // reasons for that.
            //
            // The ticket, because §20.6 says so: its 60-second life does not
            // make it harmless — for those 60 seconds it IS the credential that
            // converts into an RPT, so a header in a log line is a live
            // credential in a log line.
            //
            // The realm and as_uri, because they are strings a *remote* server
            // chose. They are not secrets, but echoing attacker-controlled text
            // into a terminal or a log file is its own small hazard (escape
            // sequences, log forging), and an example is the last place to
            // teach the habit. What matters here is the shape of the challenge,
            // not its contents.
            println("challenge parsed: as_uri present=${challenge.asUri != null}, ticket present=true")

            // ---- 3. The trust decision ----
            //
            // This is the step §20.3 exists to keep in the caller's hands. The
            // SDK parsed the header and stopped; deciding whether to send the
            // user's token to the host it names is this program's call, and it
            // is a real one — a compromised or merely misconfigured resource
            // server could nominate anything here.
            val configuration = client.oidcDiscover()
            val nominated = challenge.asUri
            if (nominated != null && nominated.trimEnd('/') != configuration.issuer.trimEnd('/')) {
                // Neither side of the comparison is echoed. The nominated value
                // for the reasons above; our own issuer because it is reached
                // through a client constructed with a client secret, and an
                // example that prints values derived from that object is
                // teaching a habit that is fine here and wrong three refactors
                // later. The decision and its outcome are what a reader needs;
                // the values are two lines away in a debugger.
                println("refusing to redeem: the challenge nominates an authorization server")
                println("that is not the issuer this client already trusts.")
                println("this is the auto-exchange §20.3 forbids, and why it forbids it.")
                return@use
            }
            println("as_uri matches the issuer we already trust; redeeming.")

            // ---- 4. Exchange, then retry ----
            //
            // One request. A ticket is spent whether or not this succeeds
            // (§20.2 rule 6), so on failure the next step is a *new* ticket —
            // which means going back to step 1, not resending this one.
            val rpt = try {
                client.umaExchangeTicket(
                    UmaExchangeTicketParams(
                        ticket = ticket,
                        claimToken = Sensitive.of(userToken),
                        configuration = configuration,
                    ),
                )
            } catch (error: Exception) {
                println("exchange failed: ${error.javaClass.simpleName}")
                println("the ticket is spent either way — request a new one by retrying.")
                return@use
            }
            println("got an RPT, valid for ${rpt.expiresIn}s")

            val allowed = http.send(
                get(url, rpt.accessToken.expose()),
                HttpResponse.BodyHandlers.ofString(),
            )
            println("second attempt: ${allowed.statusCode()}")
        }
    }

    /**
     * Issues a bearer-authenticated GET against the resource server. Plain
     * `java.net.http` rather than the SDK client: the resource server is this
     * program's own peer, not the AXIAM deployment.
     */
    private fun get(url: URI, token: String): HttpRequest =
        HttpRequest.newBuilder(url).header("Authorization", "Bearer $token").build()

    private fun env(key: String, fallback: String): String =
        System.getenv(key)?.takeIf { it.isNotBlank() } ?: fallback
}
