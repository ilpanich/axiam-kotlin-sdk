package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.AxiamUser
import io.axiam.sdk.annotations.AxiamRequireAccess
import io.axiam.sdk.annotations.AxiamRequireAuth
import io.axiam.sdk.annotations.AxiamRequireRole
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import io.ktor.http.ContentType
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
 * cookie), verifies it against AXIAM ([AxiamClient.verifySession] — EdDSA/JWKS,
 * tenant scoping, expiry), and injects the resulting [AxiamUser] into the call
 * (readable via [axiamUser]). Verification failures leave the user absent; each
 * route decides via the helpers below whether that is a 401.
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
    onCall { call ->
        call.attributes.put(CLIENT_KEY, client)
        val token = extractToken(call)
        if (token != null) {
            try {
                val user = withContext(Dispatchers.IO) { client.verifySession(token) }
                call.attributes.put(USER_KEY, user)
            } catch (_: AuthError) {
                // Leave the user absent; per-route helpers turn this into 401.
            }
        }
    }
}

/** Configuration for [AxiamAuthentication]. */
class AxiamAuthConfig {
    /** The AXIAM client used to verify sessions and evaluate authorization checks. */
    var client: AxiamClient? = null
}

private val USER_KEY = AttributeKey<AxiamUser>("AxiamUser")
private val CLIENT_KEY = AttributeKey<AxiamClient>("AxiamClient")

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
            respondError(HttpStatusCode.Forbidden, "authorization_denied", "access denied")
            null
        }
    } catch (_: AuthzError) {
        respondError(HttpStatusCode.Forbidden, "authorization_denied", "access denied")
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
