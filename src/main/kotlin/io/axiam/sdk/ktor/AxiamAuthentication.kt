package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.AxiamUser
import io.axiam.sdk.annotations.AxiamRequireAccess
import io.axiam.sdk.annotations.AxiamRequireAuth
import io.axiam.sdk.annotations.AxiamRequireRole
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.AxiamException
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.oidc.RequestedPermission
import io.axiam.sdk.oidc.umaChallengeHeader
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
import io.ktor.server.response.respondText
import io.ktor.util.AttributeKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/**
 * Ktor integration for the §10 middleware / route-guard interface and the §11
 * declarative-authorization helpers.
 *
 * Install [AxiamAuthentication] with an [AxiamClient]; on every call it extracts
 * the session token (`Authorization: Bearer` first, else the `axiam_access`
 * cookie), verifies it against AXIAM ([AxiamClient.verifySession], which applies
 * the full CONTRACT.md §10.1 minimum local-verification set: EdDSA/JWKS
 * signature with `alg` pinned before key lookup, REQUIRED `exp`, `nbf`, tenant
 * scoping, and `iss`/`aud` when configured), and injects the [AxiamUser] into the call
 * (readable via [axiamUser]).
 *
 * **A token that FAILS verification is rejected here with 401** (§15.3.3). An
 * earlier revision swallowed the `AuthError` and left the user attribute absent,
 * deferring the decision to the per-route helpers — which meant a route that
 * forgot [requireAuth] ran **unauthenticated** for a caller who had presented an
 * expired, foreign-tenant or forged token. Java and C# make the same
 * leave-it-absent choice deliberately, but they sit behind Spring Security and
 * ASP.NET Core authorization respectively; Ktor has no equivalent layer behind
 * this plugin, so the omission is not caught anywhere else.
 *
 * A call carrying **no token at all** is left absent, exactly as before: that is
 * not a failed authentication, and public routes must keep working. The
 * distinction is deliberate — reject a bad credential, ignore an absent one.
 *
 * The §11 helpers ([requireAuth], [requireAccess], [requireRole], and the
 * annotation-driven [enforce]) run strictly AFTER this injection and consume the
 * identity — they never re-implement token extraction/verification. They respond
 * with the standardized `{ "error", "message" }` body and return `null` on
 * rejection so a handler can `?: return@get`.
 *
 * Spring Boot users reuse the Java SDK's `AxiamAuthorizationInterceptor` instead.
 */
val AxiamAuthentication = createApplicationPlugin(
    name = "AxiamAuthentication",
    createConfiguration = ::AxiamAuthConfig,
) {
    val client = requireNotNull(pluginConfig.client) {
        "AxiamAuthentication requires an AxiamClient (config.client = ...)"
    }
    val challenger = pluginConfig.umaChallenge
    onCall { call ->
        call.attributes.put(CLIENT_KEY, client)
        challenger?.let { call.attributes.put(CHALLENGER_KEY, it) }
        val token = extractToken(call)
        if (token != null) {
            try {
                val user = withContext(Dispatchers.IO) { client.verifySession(token) }
                call.attributes.put(USER_KEY, user)
            } catch (_: AuthError) {
                // §15.3.3: the caller PRESENTED a credential and it did not
                // verify. Leaving the attribute absent and continuing makes a
                // route that forgets `requireAuth()` serve that caller
                // unauthenticated — fail-open by omission. Reject here.
                //
                // Only a *presented* token reaches this branch; a call with no
                // token never enters it, so public routes are unaffected.
                call.respondError(
                    HttpStatusCode.Unauthorized,
                    "authentication_failed",
                    "invalid or expired token",
                )
            }
        }
    }
}

/** Configuration for [AxiamAuthentication]. */
class AxiamAuthConfig {
    /** The AXIAM client used to verify sessions and evaluate authorization checks. */
    var client: AxiamClient? = null

    /**
     * An optional §20.3 challenge emitter. When set, a [requireAccess] denial
     * additionally carries `WWW-Authenticate: UMA` with a freshly minted ticket
     * for the action that was refused; when left `null` (the default) a denial
     * is the plain 403 it has always been. See [UmaChallenger] for why this is
     * opt-in and why a minting failure still denies plainly.
     */
    var umaChallenge: UmaChallenger? = null
}

private val USER_KEY = AttributeKey<AxiamUser>("AxiamUser")
private val CLIENT_KEY = AttributeKey<AxiamClient>("AxiamClient")
private val CHALLENGER_KEY = AttributeKey<UmaChallenger>("AxiamUmaChallenger")

/** The authenticated [AxiamUser] injected by [AxiamAuthentication], or `null`. */
val ApplicationCall.axiamUser: AxiamUser?
    get() = attributes.getOrNull(USER_KEY)

private fun ApplicationCall.axiamClient(): AxiamClient =
    attributes.getOrNull(CLIENT_KEY)
        ?: error("AxiamAuthentication plugin is not installed")

private fun extractToken(call: ApplicationCall): String? {
    val auth = call.request.headers["Authorization"]
    if (auth != null && auth.startsWith("Bearer ", ignoreCase = true)) {
        return auth.substring(7).trim().ifEmpty { null }
    }
    return call.request.cookies["axiam_access"]
}

/**
 * §11 `require_auth`: returns the authenticated [AxiamUser], or responds 401
 * (`authentication_failed`) and returns `null`.
 */
suspend fun ApplicationCall.requireAuth(): AxiamUser? {
    val user = axiamUser
    if (user == null) {
        respondError(HttpStatusCode.Unauthorized, "authentication_failed", "authentication required")
        return null
    }
    return user
}

/**
 * §11 `require_role`: a LOCAL check that the caller holds at least one of
 * [roles]. 401 if unauthenticated, 403 if none match.
 */
suspend fun ApplicationCall.requireRole(vararg roles: String): AxiamUser? {
    val user = requireAuth() ?: return null
    if (roles.none { it in user.roles }) {
        respondError(HttpStatusCode.Forbidden, "authorization_denied", "caller lacks a required role")
        return null
    }
    return user
}

/**
 * §11 `require_access`: checks `(action, resourceId[, scope])` for the
 * authenticated caller. 401 if unauthenticated, 400 if [resourceId] is not a
 * UUID, 403 if denied, 503 if the authz endpoint is unreachable (fail closed).
 */
suspend fun ApplicationCall.requireAccess(
    action: String,
    resourceId: String,
    scope: String? = null,
): AxiamUser? {
    val user = requireAuth() ?: return null
    if (!isUuid(resourceId)) {
        respondError(HttpStatusCode.BadRequest, "invalid_request", "missing or invalid resource identifier")
        return null
    }
    return try {
        val result = axiamClient().checkAccess(user.userId, action, resourceId, scope)
        if (result.allowed) {
            user
        } else {
            denied(action, resourceId)
            null
        }
    } catch (_: AuthzError) {
        denied(action, resourceId)
        null
    } catch (_: NetworkError) {
        // §11.2.5: fail closed on transport failure — never a silent allow.
        respondError(HttpStatusCode.ServiceUnavailable, "authz_unavailable", "authorization service unavailable")
        null
    } catch (_: AuthError) {
        respondError(HttpStatusCode.Unauthorized, "authentication_failed", "authentication required")
        null
    }
}

/**
 * Annotation-driven enforcement (§11): applies any of [AxiamRequireAuth],
 * [AxiamRequireRole], [AxiamRequireAccess] present in [annotations], resolving a
 * [AxiamRequireAccess] resource from its static `resourceId` or the route
 * parameter named by `resourceParam`. Returns the [AxiamUser] on success, or
 * `null` (after responding) on any failure. State-changing methods with an
 * absent token still resolve to 401 via [requireAuth].
 */
suspend fun ApplicationCall.enforce(vararg annotations: Annotation): AxiamUser? {
    if (annotations.none { it is AxiamRequireAuth || it is AxiamRequireRole || it is AxiamRequireAccess }) {
        return axiamUser
    }
    var user = requireAuth() ?: return null

    annotations.filterIsInstance<AxiamRequireRole>().firstOrNull()?.let { ann ->
        user = requireRole(*ann.roles) ?: return null
    }
    annotations.filterIsInstance<AxiamRequireAccess>().firstOrNull()?.let { ann ->
        val resourceId = ann.resourceId.ifEmpty { parameters[ann.resourceParam] ?: "" }
        val scope = ann.scope.ifEmpty { null }
        user = requireAccess(ann.action, resourceId, scope) ?: return null
    }
    // Method is read from the request for completeness (state-changing calls are
    // handled identically — auth is already enforced above).
    @Suppress("UNUSED_EXPRESSION") request.httpMethod
    return user
}

/**
 * The single deny path for a resource check: a 403, carrying a
 * `WWW-Authenticate: UMA` challenge when — and only when — a [UmaChallenger]
 * was configured on the plugin.
 */
private suspend fun ApplicationCall.denied(action: String, resourceId: String) {
    umaChallengeHeaderOrNull(action, resourceId)?.let {
        // Set before responding: `respondText` commits the status line.
        response.headers.append(HttpHeaders.WWWAuthenticate, it)
    }
    respondError(HttpStatusCode.Forbidden, "authorization_denied", "access denied")
}

/**
 * Mints one ticket for the pair that was just refused and formats the
 * challenge, or returns `null` when there is no challenger or minting fails.
 *
 * The requested scope is the AXIAM *action* (§20.2): asking for anything else
 * would offer the caller authority other than the one they were denied, and
 * would step outside the grants the engine just evaluated — deny rules
 * included.
 */
private suspend fun ApplicationCall.umaChallengeHeaderOrNull(action: String, resourceId: String): String? {
    val challenger = attributes.getOrNull(CHALLENGER_KEY) ?: return null
    return try {
        val ticket = challenger.client.umaRequestTicket(
            challenger.pat,
            listOf(RequestedPermission(resourceId, listOf(action))),
        )
        umaChallengeHeader(challenger.realm, challenger.asUri, ticket)
    } catch (_: AxiamException) {
        // Swallowed deliberately — see [UmaChallenger]. The denial stands on
        // its own; only the sugar is lost.
        null
    }
}

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String, message: String) {
    val body = "{\"error\":${jsonString(error)},\"message\":${jsonString(message)}}"
    respondText(body, ContentType.Application.Json, status)
}

private fun jsonString(value: String): String = kotlinx.serialization.json.Json.encodeToString(
    kotlinx.serialization.json.JsonPrimitive.serializer(),
    kotlinx.serialization.json.JsonPrimitive(value),
)

private fun isUuid(value: String): Boolean =
    try {
        UUID.fromString(value); true
    } catch (_: IllegalArgumentException) {
        false
    }
