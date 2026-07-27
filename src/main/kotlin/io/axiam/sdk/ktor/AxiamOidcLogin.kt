package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcBeginParams
import io.axiam.sdk.oidc.OidcExchangeParams
import io.axiam.sdk.oidc.OidcStateEntry
import io.axiam.sdk.oidc.OidcStateStore
import io.axiam.sdk.oidc.OidcTokenSet
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * "Login with AXIAM" Ktor glue (CONTRACT.md §12) — installs the login-redirect
 * and callback routes on [this] [Route], following the SAME per-SDK
 * conventions as [AxiamAuthentication]: kept `compileOnly`-safe, exactly like
 * that plugin — the SDK core ([io.axiam.sdk.AxiamClient] and the
 * `io.axiam.sdk.oidc` package) compiles and passes tests with Ktor entirely
 * absent from a consumer's classpath; only a consumer who imports this file
 * needs the `ktor-server-core` dependency their own project adds.
 *
 * This function performs NO token extraction and sets NO cookie of its own:
 * `oidcExchange`'s result is delivered to the host application only through
 * [onSuccess], which is where the application establishes its OWN session
 * (sign a cookie, write a session row, ...) — this SDK deliberately does not
 * decide what "logged in" means for the host application.
 *
 * The [store] is what turns the two HTTP requests of a redirect flow into one
 * login: `oidcBegin` produces `state`/`nonce`/`codeVerifier` on the login
 * request, and only `state` survives the round trip through the IdP, so the
 * other two must be parked somewhere the callback request can reach (§12.3
 * rule 1 — the core §12 operations store nothing themselves).
 *
 * @param client the relying-party [AxiamClient] driving the flow (built with
 *   `oidcClientId`/`oidcClientSecret` configured)
 * @param redirectUri the relying party's redirect URI — the public URL of
 *   [callbackPath] — replayed verbatim on the token exchange (the server
 *   compares the two)
 * @param store where in-flight login state is parked between the login
 *   redirect and the callback; defaults to a fresh [MemoryOidcStateStore]
 *   (single-process only — a multi-instance deployment needs a shared store)
 * @param loginPath the route path that redirects the browser to the IdP
 * @param callbackPath the route path the IdP redirects back to
 * @param scope requested scope; `openid` is added automatically when absent
 *   (§12.1 rule 4)
 * @param successRedirect where to send the browser after a successful login;
 *   falls back to the `return_to` query parameter captured at login time,
 *   then to a `200` JSON summary. **The caller owns validating this
 *   destination** — neither this value nor `return_to` is checked for
 *   open-redirect safety here (documented caller responsibility, CONTRACT.md
 *   §12 T1 judgment call 19)
 * @param onSuccess called with the validated token set once the exchange
 *   succeeds — the hook where the host application establishes its OWN
 *   session (sign a cookie, write a session row, ...). Receives the consumed
 *   [OidcStateEntry] too, so `returnTo` and any other data captured at login
 *   time is available
 */
fun Route.axiamOidcLogin(
    client: AxiamClient,
    redirectUri: String,
    store: OidcStateStore = MemoryOidcStateStore(),
    loginPath: String = "/login",
    callbackPath: String = "/callback",
    scope: String? = null,
    successRedirect: String? = null,
    onSuccess: (suspend (OidcTokenSet, OidcStateEntry) -> Unit)? = null,
) {
    get(loginPath) {
        val returnTo = call.request.queryParameters["return_to"]
        val outcome = beginOidcLogin(client, store, redirectUri, scope, returnTo)
        respondOutcome(call, outcome)
    }
    get(callbackPath) {
        val query = call.request.queryParameters
        val outcome = completeOidcLogin(
            client = client,
            store = store,
            successRedirect = successRedirect,
            onSuccess = onSuccess,
            state = query["state"],
            code = query["code"],
            idpError = query["error"],
            idpErrorDescription = query["error_description"],
        )
        respondOutcome(call, outcome)
    }
}

/**
 * What a login/callback route should do next — one arm per response shape.
 * [axiamOidcLogin] translates this into the actual Ktor response so the two
 * routes cannot drift apart.
 */
internal sealed class OidcLoginOutcome {
    /** Send a `302` to [url]. */
    data class Redirect(val url: String) : OidcLoginOutcome()

    /** Reply `200` with a token-free JSON summary. */
    data class Success(val sub: String?, val expiresIn: Long) : OidcLoginOutcome()

    /** Reply [status] with the standardized `{ "error", "message" }` body. */
    data class Error(val status: HttpStatusCode, val error: String, val message: String) : OidcLoginOutcome()
}

/**
 * Step 1 — build the authorization request, park its state, and hand back the
 * redirect (CONTRACT.md §12.1 `oidcBegin`).
 *
 * Discovery is fetched through `oidcDiscover`, so its per-origin cache and
 * single-flight de-duplication apply (§12.3 rule 6) — a busy login route does
 * not hammer the discovery endpoint.
 */
internal suspend fun beginOidcLogin(
    client: AxiamClient,
    store: OidcStateStore,
    redirectUri: String,
    scope: String?,
    returnTo: String?,
): OidcLoginOutcome = try {
    val configuration = client.oidcDiscover()
    val request = client.oidcBegin(
        OidcBeginParams(configuration = configuration, redirectUri = redirectUri, scope = scope),
    )
    store.save(
        OidcStateEntry(
            state = request.state,
            nonce = request.nonce,
            codeVerifier = request.codeVerifier,
            redirectUri = redirectUri,
            returnTo = returnTo,
        ),
    )
    OidcLoginOutcome.Redirect(request.url)
} catch (_: Exception) {
    // A login route that cannot reach AXIAM must fail closed with 503 rather
    // than redirect the browser somewhere half-built.
    OidcLoginOutcome.Error(HttpStatusCode.ServiceUnavailable, "oidc_unavailable", "could not start the OIDC login flow")
}

/**
 * Step 2 — validate the callback, consume the stored state, exchange the
 * code, and hand back the post-login response (CONTRACT.md §12.1
 * `oidcExchange`).
 *
 * Failure mapping (a login-glue convention, not itself contract-specified —
 * CONTRACT.md §12 T1 judgment call 19): `400 invalid_request` for a malformed
 * callback; `401 authentication_failed` for an IdP error, an
 * unknown/expired/already-used login state, an ID-token failure, or an
 * `OAuth2` protocol error; `503 oidc_unavailable` for a network failure
 * reaching AXIAM.
 */
internal suspend fun completeOidcLogin(
    client: AxiamClient,
    store: OidcStateStore,
    successRedirect: String?,
    onSuccess: (suspend (OidcTokenSet, OidcStateEntry) -> Unit)?,
    state: String?,
    code: String?,
    idpError: String?,
    idpErrorDescription: String?,
): OidcLoginOutcome {
    if (!idpError.isNullOrEmpty()) {
        val message = if (idpErrorDescription.isNullOrEmpty()) idpError else "$idpError: $idpErrorDescription"
        return OidcLoginOutcome.Error(HttpStatusCode.Unauthorized, "authentication_failed", message)
    }
    if (state.isNullOrEmpty() || code.isNullOrEmpty()) {
        return OidcLoginOutcome.Error(
            HttpStatusCode.BadRequest,
            "invalid_request",
            "callback is missing the state or code query parameter",
        )
    }

    // Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
    // Unknown, already-consumed, and expired states are deliberately
    // indistinguishable to the caller.
    val entry = store.consume(state)
        ?: return OidcLoginOutcome.Error(
            HttpStatusCode.Unauthorized,
            "authentication_failed",
            "unknown, expired, or already-used login state",
        )

    val tokens = try {
        client.oidcExchange(
            OidcExchangeParams(
                code = code,
                codeVerifier = entry.codeVerifier,
                redirectUri = entry.redirectUri,
                nonce = entry.nonce,
            ),
        )
    } catch (_: NetworkError) {
        return OidcLoginOutcome.Error(HttpStatusCode.ServiceUnavailable, "oidc_unavailable", "the AXIAM token endpoint is unreachable")
    } catch (e: AuthError) {
        // Includes OAuthProtocolError and every §12.4 reason code: a login
        // that cannot be proven is a failed login.
        return OidcLoginOutcome.Error(HttpStatusCode.Unauthorized, "authentication_failed", e.message ?: "token exchange failed")
    }

    onSuccess?.invoke(tokens, entry)

    val destination = successRedirect ?: entry.returnTo
    if (!destination.isNullOrEmpty()) {
        return OidcLoginOutcome.Redirect(destination)
    }
    return OidcLoginOutcome.Success(sub = tokens.idClaims?.sub, expiresIn = tokens.expiresIn)
}

private suspend fun respondOutcome(call: ApplicationCall, outcome: OidcLoginOutcome) {
    when (outcome) {
        is OidcLoginOutcome.Redirect -> call.respondRedirect(outcome.url)
        is OidcLoginOutcome.Success -> {
            val body = buildJsonObject {
                put("authenticated", true)
                outcome.sub?.let { put("sub", it) }
                put("expires_in", outcome.expiresIn)
            }
            call.respondText(Json.encodeToString(JsonObject.serializer(), body), ContentType.Application.Json, HttpStatusCode.OK)
        }
        is OidcLoginOutcome.Error -> {
            val body = buildJsonObject {
                put("error", outcome.error)
                put("message", outcome.message)
            }
            call.respondText(Json.encodeToString(JsonObject.serializer(), body), ContentType.Application.Json, outcome.status)
        }
    }
}
