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
import io.ktor.http.HttpHeaders
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
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale

/**
 * "Login with AXIAM" Ktor glue (CONTRACT.md §12) — installs the login-redirect
 * and callback routes on [this] [Route], following the SAME per-SDK
 * conventions as [AxiamAuthentication]: kept `compileOnly`-safe, exactly like
 * that plugin — the SDK core ([io.axiam.sdk.AxiamClient] and the
 * `io.axiam.sdk.oidc` package) compiles and passes tests with Ktor entirely
 * absent from a consumer's classpath; only a consumer who imports this file
 * needs the `ktor-server-core` dependency their own project adds.
 *
 * This function performs NO token extraction and sets no SESSION cookie of its
 * own: `oidcExchange`'s result is delivered to the host application only
 * through [onSuccess] / [onSuccessWithCall], which is where the application
 * establishes its OWN session (sign a cookie, write a session row, ...) — this
 * SDK deliberately does not decide what "logged in" means for the host
 * application. The one cookie it does set is the short-lived browser-binding
 * cookie below.
 *
 * ### Browser binding (CONTRACT.md §12.8 rule 1; contract 1.68, C7)
 *
 * The login route sets a random 32-byte value as the `HttpOnly`, `Secure`,
 * `SameSite=Lax`, `Path=/` cookie `__Host-axiam_oidc_bind` (no `Domain`;
 * `Max-Age=600`) and stores its SHA-256 on the state entry. The callback
 * consumes the entry FIRST (so `state` stays single-use), then refuses with
 * the same `401` it gives an unknown state — no code exchange, no success
 * callback — unless the request presents a cookie whose digest matches
 * (constant-time compare). Without this, an attacker who began a login and
 * stopped before the callback could have a victim's browser load
 * `callback?state=…&code=…` and complete the attacker's login in the victim's
 * request (login CSRF; RFC 6749 §10.12). The cookie is cleared on every
 * callback response. Where [redirectUri] is `http:` on a loopback host
 * (`localhost`, `127.0.0.1`, `[::1]`) a browser will not store a `Secure`
 * cookie, so the name is `axiam_oidc_bind` and `Secure` is omitted — there
 * only. Two sign-ins started concurrently in one browser: the later login
 * replaces the cookie, so the earlier callback is refused and the user starts
 * again.
 *
 * **Upgrade note.** Entries saved by 1.3.x glue carry no digest and are refused
 * at the callback (one in-flight sign-in per user fails once and restarts). A
 * caller-supplied [store] must persist [OidcStateEntry.bindingDigest] and return
 * it unchanged.
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
 * @param successRedirect where to send the browser after a successful login,
 *   which the integrator configures and which therefore wins; falls back to
 *   the `return_to` query parameter captured at login time, then to a `200`
 *   JSON summary. **`return_to` is followed only as a same-origin relative
 *   path** (CONTRACT.md §12.8 rule 3; C6): it must start with a single `/`, not
 *   `//` or `/\`, and contain no `\` or control character. It is checked when
 *   stored (a failing value is dropped) and again before redirecting (a stored
 *   value that fails is not followed). A dropped `return_to` is treated as if
 *   none had been given
 * @param allowReturnTo optional predicate that may WIDEN the `return_to` rule —
 *   e.g. an allowlist of the application's other origins. Consulted at both
 *   points, and only for a value the default rule refuses; a predicate that
 *   throws accepts nothing. There is no default predicate: absolute URLs are
 *   never followed unless the integrator says so
 * @param onSuccessWithCall like [onSuccess] but also receives the Ktor
 *   [ApplicationCall] that completed the sign-in, so the application creates
 *   its session on THAT request without ambient context (§12.8 rule 2). Runs
 *   after [onSuccess] when both are set; the old hook is kept so the published
 *   signature of [onSuccess] does not change. **The hook must not send a
 *   response**: the glue sends the outcome itself. A
 *   hook that throws gets the framework's error response, which still clears the
 *   binding cookie (the clearing header is set before the hook can run)
 * @param onSuccess called with the validated token set once the exchange
 *   succeeds — the hook where the host application establishes its OWN
 *   session (sign a cookie, write a session row, ...). Receives the consumed
 *   [OidcStateEntry] too, so `returnTo` and any other data captured at login
 *   time is available. It runs only after the browser binding and the code
 *   exchange have both succeeded
 */
fun Route.axiamOidcLogin(
    client: AxiamClient,
    redirectUri: String,
    store: OidcStateStore = MemoryOidcStateStore(),
    loginPath: String = "/login",
    callbackPath: String = "/callback",
    scope: String? = null,
    successRedirect: String? = null,
    allowReturnTo: ((String) -> Boolean)? = null,
    onSuccessWithCall: (suspend (OidcTokenSet, OidcStateEntry, ApplicationCall) -> Unit)? = null,
    onSuccess: (suspend (OidcTokenSet, OidcStateEntry) -> Unit)? = null,
) {
    val cookieName = oidcBindingCookieName(redirectUri)
    get(loginPath) {
        val returnTo = call.request.queryParameters["return_to"]
        val outcome = beginOidcLogin(client, store, redirectUri, scope, returnTo, allowReturnTo)
        respondOutcome(call, outcome)
    }
    get(callbackPath) {
        val query = call.request.queryParameters
        val applicationCall = call
        // §12.8 rule 1 (d): every callback response — success, the uniform
        // 401, every other error AND the framework's error response when a hook
        // or the store throws — clears the binding cookie. The header is set
        // before anything that can throw runs, so no exit path can miss it.
        call.response.headers.append(HttpHeaders.SetCookie, oidcBindingCookie(redirectUri, value = "", clear = true))
        val outcome = completeOidcLogin(
            client = client,
            store = store,
            successRedirect = successRedirect,
            onSuccess = if (onSuccess == null && onSuccessWithCall == null) {
                null
            } else {
                { tokens, entry ->
                    onSuccess?.invoke(tokens, entry)
                    onSuccessWithCall?.invoke(tokens, entry, applicationCall)
                }
            },
            state = query["state"],
            code = query["code"],
            idpError = query["error"],
            idpErrorDescription = query["error_description"],
            // Only the one name the redirect URI selects is read: a `__Host-`
            // cookie on a loopback deployment, or the loopback name on an
            // HTTPS one, is treated as no cookie (§12.8 rule 1 (b)).
            bindingCookie = call.request.cookies[cookieName],
            allowReturnTo = allowReturnTo,
        )
        respondOutcome(call, outcome)
    }
}

/**
 * The 1.3.1 signature of [axiamOidcLogin], kept in the bytecode so a caller
 * compiled against 1.3.x still links; hidden from source, where the full
 * signature above applies.
 */
@Deprecated("Binary compatibility with 1.3.1 only.", level = DeprecationLevel.HIDDEN)
fun Route.axiamOidcLogin(
    client: AxiamClient,
    redirectUri: String,
    store: OidcStateStore = MemoryOidcStateStore(),
    loginPath: String = "/login",
    callbackPath: String = "/callback",
    scope: String? = null,
    successRedirect: String? = null,
    onSuccess: (suspend (OidcTokenSet, OidcStateEntry) -> Unit)? = null,
) = axiamOidcLogin(
    client = client,
    redirectUri = redirectUri,
    store = store,
    loginPath = loginPath,
    callbackPath = callbackPath,
    scope = scope,
    successRedirect = successRedirect,
    allowReturnTo = null,
    onSuccessWithCall = null,
    onSuccess = onSuccess,
)

/**
 * What a login/callback route should do next — one arm per response shape.
 * [axiamOidcLogin] translates this into the actual Ktor response so the two
 * routes cannot drift apart.
 */
internal sealed class OidcLoginOutcome {
    /** Send a `302` to [url], with one `Set-Cookie` header when [setCookie] is given. */
    data class Redirect(val url: String, val setCookie: String? = null) : OidcLoginOutcome()

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
    allowReturnTo: ((String) -> Boolean)? = null,
): OidcLoginOutcome = try {
    val configuration = client.oidcDiscover()
    val request = client.oidcBegin(
        OidcBeginParams(configuration = configuration, redirectUri = redirectUri, scope = scope),
    )
    // §12.8 rule 1 (a): a NEW value every login — a cookie the request
    // presents is never reused, so a value an attacker planted beforehand
    // cannot become the binding. Only its digest is stored.
    val binding = newBindingValue()
    store.save(
        OidcStateEntry(
            state = request.state,
            nonce = request.nonce,
            codeVerifier = request.codeVerifier,
            redirectUri = redirectUri,
            // §12.8 rule 3: a return_to that fails is dropped here and the
            // entry is stored without it.
            returnTo = returnTo?.takeIf { isAcceptableReturnTo(it, allowReturnTo) },
            bindingDigest = bindingDigest(binding),
        ),
    )
    OidcLoginOutcome.Redirect(request.url, setCookie = oidcBindingCookie(redirectUri, binding, clear = false))
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
    bindingCookie: String?,
    allowReturnTo: ((String) -> Boolean)? = null,
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
    //
    // The consume comes BEFORE the binding check (§12.8 rule 1 (c)): whatever
    // the check decides, the state is spent, so a refused callback cannot be
    // retried for another reason.
    val entry = store.consume(state)
        ?: return unknownLoginState()

    // §12.8 rule 1 (c): the callback completes only for the browser that began
    // the login. A missing cookie, an entry with no digest and a different
    // digest all get THE SAME 401 as an unknown state — the refusal does not say
    // which check failed — and the code is not exchanged, so neither the token
    // endpoint nor `onSuccess` ever sees the attacker's code.
    if (!bindingMatches(bindingCookie, entry.bindingDigest)) {
        return unknownLoginState()
    }

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

    // The integrator's own successRedirect wins; a stored return_to is checked
    // AGAIN before it is followed (the store may be the integrator's, the entry
    // older glue's) — §12.8 rule 3.
    val destination = successRedirect
        ?: entry.returnTo?.takeIf { isAcceptableReturnTo(it, allowReturnTo) }
    if (!destination.isNullOrEmpty()) {
        return OidcLoginOutcome.Redirect(destination)
    }
    return OidcLoginOutcome.Success(sub = tokens.idClaims?.sub, expiresIn = tokens.expiresIn)
}

private suspend fun respondOutcome(call: ApplicationCall, outcome: OidcLoginOutcome) {
    when (outcome) {
        is OidcLoginOutcome.Redirect -> {
            outcome.setCookie?.let { call.response.headers.append(HttpHeaders.SetCookie, it) }
            // Decision 7 (login-glue binding): the adapter encodes the Location value.
            call.respondRedirect(encodeRedirectLocation(outcome.url))
        }
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

private fun unknownLoginState(): OidcLoginOutcome.Error =
    OidcLoginOutcome.Error(
        HttpStatusCode.Unauthorized,
        "authentication_failed",
        "unknown, expired, or already-used login state",
    )

// ---- browser binding (CONTRACT.md §12.8 rule 1) and return_to (rule 3) -------
//
// One implementation each, shared by the login and callback routes.

/** The binding cookie's name on every `redirect_uri` but plain-HTTP loopback. */
internal const val OIDC_BIND_COOKIE = "__Host-axiam_oidc_bind"

/** The plain-HTTP loopback development name — a browser will not store a `Secure` cookie there. */
internal const val OIDC_BIND_COOKIE_LOOPBACK = "axiam_oidc_bind"

private const val OIDC_BIND_MAX_AGE_SECONDS = 600

private val bindingRandom = SecureRandom()

/** `true` when [redirectUri] is `http:` on `localhost`, `127.0.0.1` or `[::1]` — and nowhere else. */
private fun isPlainHttpLoopback(redirectUri: String): Boolean {
    val uri = try {
        URI(redirectUri)
    } catch (_: Exception) {
        return false
    }
    if (!"http".equals(uri.scheme, ignoreCase = true)) return false
    return uri.host?.lowercase(Locale.ROOT) in LOOPBACK_HOSTS
}

private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "[::1]")

/**
 * Which cookie name the glue uses for [redirectUri]: a pure function of the
 * configured URI, so login and callback cannot disagree. The fallback is
 * selectable only on plain-HTTP loopback, never by configuration.
 */
internal fun oidcBindingCookieName(redirectUri: String): String =
    if (isPlainHttpLoopback(redirectUri)) OIDC_BIND_COOKIE_LOOPBACK else OIDC_BIND_COOKIE

/**
 * The whole `Set-Cookie` header value, so the attributes cannot drift between
 * the setting and the clearing response. [clear] writes an empty value with
 * `Max-Age=0`.
 */
internal fun oidcBindingCookie(redirectUri: String, value: String, clear: Boolean): String {
    val secure = if (isPlainHttpLoopback(redirectUri)) "" else "; Secure"
    val maxAge = if (clear) 0 else OIDC_BIND_MAX_AGE_SECONDS
    return "${oidcBindingCookieName(redirectUri)}=$value; Path=/; HttpOnly$secure; SameSite=Lax; Max-Age=$maxAge"
}

/** 32 CSPRNG bytes, base64url without padding (43 characters). */
internal fun newBindingValue(): String {
    val bytes = ByteArray(32)
    bindingRandom.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/** Lower-case hex SHA-256 of the ASCII bytes of the cookie value as set. */
internal fun bindingDigest(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII))
        .joinToString("") { "%02x".format(it) }

/** Constant-time comparison of the presented cookie's digest with the entry's; absent either side is a mismatch. */
internal fun bindingMatches(presented: String?, expectedDigest: String?): Boolean {
    if (presented.isNullOrEmpty() || expectedDigest.isNullOrEmpty()) return false
    return MessageDigest.isEqual(
        bindingDigest(presented).toByteArray(Charsets.US_ASCII),
        expectedDigest.toByteArray(Charsets.US_ASCII),
    )
}

/**
 * §12.8 rule 3: a same-origin relative path — a single leading `/`, not `//` or
 * `/\`, no `\` anywhere, no control character (U+0000–U+001F, U+007F).
 */
internal fun isSafeReturnTo(value: String): Boolean {
    if (!value.startsWith("/")) return false
    if (value.startsWith("//") || value.startsWith("/\\")) return false
    return value.none { it == '\\' || it.code <= 0x1F || it.code == 0x7F }
}

/** The default rule, widened — only for values it refuses — by the integrator's predicate; a throwing predicate accepts nothing. */
internal fun isAcceptableReturnTo(value: String, allow: ((String) -> Boolean)?): Boolean {
    if (isSafeReturnTo(value)) return true
    if (allow == null) return false
    return try {
        allow(value)
    } catch (e: Throwable) {
        // A predicate that fails — an Error included (a stack overflow in a
        // recursive matcher, say) — accepts nothing. Only a dying JVM is not ours to swallow.
        if (e is VirtualMachineError) throw e
        false
    }
}

/**
 * The `Location` value for a redirect to [destination]: its percent-encoded form
 * (login-glue binding, Decision 7). Every character outside the URL-safe set is
 * UTF-8 percent-encoded with upper-case hex (space `%20`, `é` `%C3%A9`, CR `%0D`,
 * LF `%0A`); a `%` that already starts a well-formed escape is kept, any other
 * `%` becomes `%25`; every lone surrogate becomes U+FFFD (then UTF-8 encoded, never a crash); `\` is kept as it is. The result
 * is pure ASCII with no byte below `0x21`, so CR/LF can never split the header.
 */
internal fun encodeRedirectLocation(destination: String): String {
    val out = StringBuilder(destination.length + 8)
    var i = 0
    while (i < destination.length) {
        val c = destination[i]
        val code = c.code
        when {
            c == '%' -> {
                val wellFormed = i + 2 < destination.length &&
                    isHexDigit(destination[i + 1]) && isHexDigit(destination[i + 2])
                out.append(if (wellFormed) "%" else "%25")
                i++
            }
            code == 0x21 || code in 0x23..0x3B || code == 0x3D || code in 0x3F..0x5F || code in 0x61..0x7A || code == 0x7C || code == 0x7E -> {
                out.append(c)
                i++
            }
            else -> {
                val cp = when {
                    Character.isHighSurrogate(c) && i + 1 < destination.length &&
                        Character.isLowSurrogate(destination[i + 1]) -> {
                        val pair = Character.toCodePoint(c, destination[i + 1])
                        i++
                        pair
                    }
                    Character.isSurrogate(c) -> 0xFFFD
                    else -> code
                }
                i++
                for (b in String(Character.toChars(cp)).toByteArray(Charsets.UTF_8)) {
                    out.append('%').append("%02X".format(b.toInt() and 0xFF))
                }
            }
        }
    }
    return out.toString()
}

private fun isHexDigit(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
