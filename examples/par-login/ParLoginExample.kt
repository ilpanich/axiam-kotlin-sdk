package io.axiam.sdk.examples.parlogin

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.oidc.AuthorizationRequest
import io.axiam.sdk.oidc.OidcBeginParams
import io.axiam.sdk.oidc.OidcConfiguration
import io.axiam.sdk.oidc.OidcExchangeParams
import io.axiam.sdk.oidc.OidcParParams
import io.axiam.sdk.oidc.PushedAuthorizationRequest
import kotlinx.coroutines.runBlocking

/**
 * CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
 *
 * PAR moves the authorization request off the browser. Instead of putting
 * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
 * agent carries, the client POSTs them straight to AXIAM over an authenticated
 * back channel and puts an opaque `request_uri` in the redirect. What travels
 * through the browser is then a random string that cannot be edited into
 * meaning something else.
 *
 * **A FAPI 2.0 client has no choice**: `profile: "fapi2"` refuses a
 * registration that does not set `require_par`, so such a client cannot
 * authorize any other way (§21.1).
 *
 * Run: `AXIAM_BASE_URL=… AXIAM_TENANT_ID=… AXIAM_CLIENT_ID=… AXIAM_CLIENT_SECRET=…
 * ./gradlew runParLoginExample`
 */
object ParLoginExample {

    private const val REDIRECT_URI = "https://app.example.com/callback"

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com")
        val tenantId = env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")

        AxiamClient.builder(baseUrl, tenantId)
            .oidcClientId(env("AXIAM_CLIENT_ID", "app"))
            .oidcClientSecret(env("AXIAM_CLIENT_SECRET", "s3cret"))
            .build()
            .use { client ->
                val config = client.oidcDiscover()

                // §26 is optional, so a server may advertise no endpoint at
                // all. The SDK refuses client-side rather than concatenating a
                // URL onto the issuer and POSTing a fully-formed authorization
                // request at a 404 (§12.7.2 rule 1).
                if (config.pushed_authorization_request_endpoint == null) {
                    println(
                        "this server does not support RFC 9126 — " +
                            "fall back to the plain oidcBegin redirect",
                    )
                    return@runBlocking
                }

                pushAndRedirect(client, config)
            }
    }

    private suspend fun pushAndRedirect(client: AxiamClient, config: OidcConfiguration) {
        // oidcBegin still runs first, and still owns state/nonce/PKCE. §26.2
        // rule 1 forbids a second generator: two sources for any of those are
        // two things that can disagree.
        val begun: AuthorizationRequest =
            client.oidcBegin(OidcBeginParams(config, REDIRECT_URI, scope = "openid profile"))

        val pushed: PushedAuthorizationRequest = try {
            client.oidcPar(OidcParParams(begun, REDIRECT_URI, config, scope = "openid profile"))
        } catch (e: OAuthProtocolError) {
            println("the server rejected the push: ${e.error}")
            return
        } catch (e: AuthError) {
            println("no PAR endpoint: ${e.message}")
            return
        }
        // Note there is no retry here, and there must not be. This is a POST
        // that creates server state, so it falls outside §16.2's read-only
        // eligibility. The safe recovery is a fresh push, which costs one round
        // trip and cannot double-consume anything (§26.2 rule 4).

        // The URL carries EXACTLY client_id and request_uri. The server refuses
        // a request that mixes a request_uri with inline authorization
        // parameters rather than merging them — an attacker supplies the inline
        // value they want and lets the pushed copy satisfy whichever check
        // reads the other one. Re-adding scope "for compatibility" restores the
        // attack (§26.2 rule 2).
        println("redirect the browser to: ${pushed.url}")
        println("the handle expires in ${pushed.expiresIn}s")

        // Persist these three exactly as a non-PAR login would — the redirect
        // being opaque changes nothing about the callback's obligations.
        rememberForTheCallback(pushed.state, pushed.nonce, pushed.codeVerifier)

        completeTheCallback(client, config, pushed)
    }

    private suspend fun completeTheCallback(
        client: AxiamClient,
        config: OidcConfiguration,
        pushed: PushedAuthorizationRequest,
    ) {
        if (pushed.state != stateFromTheCallbackQuery()) {
            // state is not a secret (§12.3 rule 2), but this comparison is the
            // CSRF guard, so a real application makes it constant-time.
            println("state mismatch — drop this callback on the floor")
            return
        }

        // The exchange is the ordinary §12 one. The request_uri is spent by
        // now: it is single-use, and a second redirect through it fails.
        val tokens = client.oidcExchange(
            OidcExchangeParams(
                code = codeFromTheCallbackQuery(),
                codeVerifier = pushed.codeVerifier,
                redirectUri = REDIRECT_URI,
                nonce = pushed.nonce,
                configuration = config,
            ),
        )
        println("signed in, id token subject: ${tokens.idClaims?.sub ?: "(none)"}")
    }

    // ------------------------------------------------------------------

    private fun rememberForTheCallback(state: String, nonce: String, codeVerifier: Sensitive<String>) {
        // A real application puts these in its own HTTP session, or in an
        // io.axiam.sdk.oidc.OidcStateStore. The SDK stores nothing itself
        // (§12.3 rule 1).
        println("  stashed state/nonce/verifier for the callback")
    }

    private fun codeFromTheCallbackQuery(): String = env("AXIAM_AUTH_CODE", "the-code-from-the-redirect")

    private fun stateFromTheCallbackQuery(): String = env("AXIAM_STATE", "the-state-from-the-redirect")

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
