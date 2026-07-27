package io.axiam.sdk.examples.oidclogin

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.oidc.IntrospectParams
import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcBeginParams
import io.axiam.sdk.oidc.OidcExchangeParams
import io.axiam.sdk.oidc.OidcStateEntry
import io.axiam.sdk.oidc.RevokeParams
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates "Login with AXIAM" — the OIDC/SSO relying-party helpers
 * (CONTRACT.md §12) — driving the authorization-code + PKCE flow directly on
 * [AxiamClient], framework-free (importing ONLY public SDK entry points,
 * never `io.axiam.sdk.internal.*`). For a Ktor route-based version of the
 * same flow, wire [io.axiam.sdk.ktor.axiamOidcLogin] into your own routing
 * instead of following the steps below by hand.
 *
 * The nine operations, and where each appears below:
 *  1. [AxiamClient.oidcDiscover]              — fetch the discovery document.
 *  2. [AxiamClient.oidcBegin]                 — build the redirect URL (no network I/O).
 *  3. [AxiamClient.oidcExchange]               — trade the callback code for a validated token set.
 *  4. [AxiamClient.oidcRefresh]                — not exercised here; see its doc comment.
 *  5. [AxiamClient.loginClientCredentials]     — the machine-to-machine alternative (`AXIAM_M2M=1`).
 *  6. [AxiamClient.introspect]                 — inspect the access token this flow just minted.
 *  7. [AxiamClient.revoke]                     — clean up at the end of the demo.
 *  8. [AxiamClient.ssoStart] / 9. [AxiamClient.ssoComplete] — the separate upstream-IdP federation
 *     pair; not exercised here (see CONTRACT.md §12.1 note 7 — no ID token reaches the SDK on
 *     that path).
 *
 * **The caller owns all login state** (CONTRACT.md §12.3 rule 1): `oidcBegin`
 * returns `state`, `nonce`, and a `Sensitive`-wrapped `codeVerifier`, and the
 * SDK stores none of them. This example uses a [MemoryOidcStateStore] — the
 * same optional reference store the Ktor glue uses internally — purely to
 * illustrate the pattern a real two-request (login redirect + callback) web
 * flow needs; a single-process CLI demo like this one could just as well
 * hold the three values in local variables across the `readLine()` prompt.
 *
 * This example is illustrative/compilable without a live AXIAM server. Running
 * it end-to-end needs a reachable AXIAM server at `AXIAM_BASE_URL` with an
 * OIDC client registered for `AXIAM_OIDC_CLIENT_ID` (+ `AXIAM_OIDC_CLIENT_SECRET`
 * for a confidential client) and `AXIAM_OIDC_REDIRECT_URI`.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_TENANT_ID=... \
 * AXIAM_OIDC_CLIENT_ID=... AXIAM_OIDC_CLIENT_SECRET=... AXIAM_OIDC_REDIRECT_URI=... \
 *   ./gradlew runOidcLoginExample
 * ```
 */
object OidcLoginExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        // A UUID tenantId is used here (not a slug) so oidcExchange/introspect/
        // revoke's mandatory ?tenant_id= query parameter (§12.3 rule 4) can
        // default from the client's own configuration without an explicit
        // per-call argument or a prior login().
        val tenantId = env("AXIAM_TENANT_ID", "22222222-2222-2222-2222-222222222222")
        val clientId = env("AXIAM_OIDC_CLIENT_ID", "my-app")
        val clientSecret = System.getenv("AXIAM_OIDC_CLIENT_SECRET") // optional: omit for a public client
        val redirectUri = env("AXIAM_OIDC_REDIRECT_URI", "http://127.0.0.1:8081/auth/callback")

        // §5: tenantId is a required, positional builder argument. §12.1: the
        // OIDC client_id (and, for a confidential client, client_secret) is
        // configured HERE at construction time — never a per-call argument —
        // because §12.4 rule 4 audience matching needs the SAME value the
        // authorization request used. TLS is always strict (§6).
        val builder = AxiamClient.builder(baseUrl, tenantId).oidcClientId(clientId)
        if (!clientSecret.isNullOrBlank()) {
            builder.oidcClientSecret(clientSecret)
        }

        builder.build().use { client ->
            if (env("AXIAM_M2M", "0") == "1") {
                runClientCredentialsDemo(client)
                return@use
            }
            runAuthorizationCodeDemo(client, redirectUri)
        }
    }

    /** Steps 1-3, 6, 7: the interactive "Login with AXIAM" redirect flow. */
    private suspend fun runAuthorizationCodeDemo(client: AxiamClient, redirectUri: String) {
        // CONTRACT.md §12.3 rule 1: entirely OPTIONAL — oidcBegin/oidcExchange
        // never touch a store themselves. This one only exists so the "park
        // state, read it back after the redirect" pattern is visible here.
        val store = MemoryOidcStateStore()

        val configuration = client.oidcDiscover()
        val request = client.oidcBegin(
            OidcBeginParams(configuration = configuration, redirectUri = redirectUri, scope = "openid profile email"),
        )
        store.save(
            OidcStateEntry(
                state = request.state,
                nonce = request.nonce,
                codeVerifier = request.codeVerifier,
                redirectUri = redirectUri,
            ),
        )

        println("Open this URL in a browser and complete the login:")
        println(request.url)
        print("Paste the callback's \"state\" value: ")
        val callbackState = readlnOrNull().orEmpty().trim()
        print("Paste the callback's \"code\" value: ")
        val callbackCode = readlnOrNull().orEmpty().trim()

        // Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
        val entry = store.consume(callbackState)
        if (entry == null) {
            System.err.println("unknown, expired, or already-used login state")
            return
        }

        val tokens = try {
            client.oidcExchange(
                OidcExchangeParams(
                    code = callbackCode,
                    codeVerifier = entry.codeVerifier,
                    redirectUri = entry.redirectUri,
                    nonce = entry.nonce,
                ),
            )
        } catch (e: OAuthProtocolError) {
            System.err.println("token exchange rejected by AXIAM: ${e.error} (${e.errorDescription})")
            return
        } catch (e: AuthError) {
            // Covers every §12.4 ID-token validation failure — e.reason
            // carries the stable machine-readable code (invalid_alg,
            // unknown_kid, invalid_signature, invalid_issuer, invalid_audience,
            // token_expired, nonce_mismatch).
            System.err.println("id_token validation failed: ${e.message} (reason=${e.reason})")
            return
        }

        // tokens.accessToken/.refreshToken/.idToken are Sensitive — never
        // printed. tokens.idClaims is the ALREADY-VALIDATED (§12.4) claim set.
        println("Login succeeded — sub=${tokens.idClaims?.sub}, expiresIn=${tokens.expiresIn}s")

        val active = client.introspect(IntrospectParams(token = tokens.accessToken)).active
        println("introspect confirms the fresh access token is active=$active")

        client.revoke(RevokeParams(token = tokens.accessToken))
        println("revoked the access token (demo cleanup)")
    }

    /** Step 5: the machine-to-machine alternative — no browser, no ID token. */
    private suspend fun runClientCredentialsDemo(client: AxiamClient) {
        val tokens = try {
            client.loginClientCredentials()
        } catch (e: AuthError) {
            System.err.println("loginClientCredentials failed: ${e.message}")
            return
        }
        println("Service-account login succeeded — expiresIn=${tokens.expiresIn}s, idToken=${tokens.idToken}")
        client.revoke(RevokeParams(token = tokens.accessToken))
        println("revoked the access token (demo cleanup)")
    }

    private fun env(key: String, fallback: String): String {
        val v = System.getenv(key)
        return if (v.isNullOrBlank()) fallback else v
    }
}
