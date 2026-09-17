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
import io.axiam.sdk.mcp.McpGuardChallenges
import io.axiam.sdk.mcp.challengeFor401
import io.axiam.sdk.mcp.challengeFor403
import io.axiam.sdk.mcp.isMetadataDocumentRequest
import io.axiam.sdk.mcp.mcpGuardChallenges
import io.axiam.sdk.oidc.RequestedPermission
import io.axiam.sdk.oidc.umaChallengeHeader
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
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
 *
 * ### MCP resource-server helpers (§28, opt-in)
 *
 * Setting [AxiamAuthConfig.resourceMetadataUrl] turns on CONTRACT.md §28: every
 * 401 this plugin and the §11 helpers below emit gains a `WWW-Authenticate`
 * challenge, and the one `GET`/`HEAD` of that URL's path is exempted from this
 * plugin's own credential check (§28.3 rule 2) so
 * `io.axiam.sdk.ktor.serveProtectedResourceMetadata` can answer it
 * unauthenticated. The configured [AxiamClient]'s own [AxiamClient.expectedAudience]
 * becomes mandatory once the option is set — refused at install time, naming
 * both — because §28 adds no second audience option. Left unset (the
 * default), this plugin's behaviour is byte-for-byte what it was before §28
 * existed.
 */
val AxiamAuthentication = createApplicationPlugin(
    name = "AxiamAuthentication",
    createConfiguration = ::AxiamAuthConfig,
) {
    val client = requireNotNull(pluginConfig.client) {
        "AxiamAuthentication requires an AxiamClient (config.client = ...)"
    }
    val challenger = pluginConfig.umaChallenge
    val mcpChallenges = mcpGuardChallenges(
        pluginConfig.resourceMetadataUrl,
        client.expectedAudience(),
        "AxiamAuthentication",
    )
    onCall { call ->
        call.attributes.put(CLIENT_KEY, client)
        challenger?.let { call.attributes.put(CHALLENGER_KEY, it) }
        mcpChallenges?.let { call.attributes.put(MCP_CHALLENGES_KEY, it) }

        // §28.3 rule 2: the metadata document MUST answer without a
        // credential, and this plugin runs globally — so the exemption is
        // here, explicit, and derived from the one path `resourceMetadataUrl`
        // names. A no-op when §28 is off (`mcpChallenges` is `null`).
        if (isMetadataDocumentRequest(mcpChallenges, call.request.httpMethod.value, call.request.path())) {
            return@onCall
        }

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
                mcpChallenges?.let {
                    call.response.headers.append(HttpHeaders.WWWAuthenticate, challengeFor401(it, credentialPresented = true))
                }
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

    /**
     * CONTRACT.md §28.5's option, off (`null`) by default. Setting it is what
     * turns §28 on: feed it `ProtectedResourceMetadata.metadataUrl`, the value
     * [io.axiam.sdk.mcp.Mcp.protectedResourceMetadata] derived, rather than
     * retyping the string — retyping is how the two come to disagree.
     *
     * Requires [client] to be built with `AxiamClient.Builder.expectedAudience(...)`
     * set to the same document's `resource`; [install] refuses the
     * configuration otherwise, naming both options (§28.5 rule 2).
     */
    var resourceMetadataUrl: String? = null
}

private val USER_KEY = AttributeKey<AxiamUser>("AxiamUser")
private val CLIENT_KEY = AttributeKey<AxiamClient>("AxiamClient")
private val CHALLENGER_KEY = AttributeKey<UmaChallenger>("AxiamUmaChallenger")
private val MCP_CHALLENGES_KEY = AttributeKey<McpGuardChallenges>("AxiamMcpGuardChallenges")

private fun ApplicationCall.mcpChallenges(): McpGuardChallenges? = attributes.getOrNull(MCP_CHALLENGES_KEY)

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
        // Only a call with NO token reaches here: the plugin's own onCall
        // already rejected a presented-but-invalid one with 401 before any
        // route handler ran (§15.3.3), so this is always §28.4's first
        // vector — no `error` parameter, never `invalid_token`.
        mcpChallenges()?.let {
            response.headers.append(HttpHeaders.WWWAuthenticate, challengeFor401(it, credentialPresented = false))
        }
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
            denied(action, resourceId, scope, result.reasonCode)
            null
        }
    } catch (_: AuthzError) {
        // No `reason_code` reaches this branch — §11 rule 9 requires an
        // absent/unrecognised one to leave the outcome header-free (§28.5
        // rule 5), so this denial never carries a challenge.
        denied(action, resourceId, scope, reasonCode = null)
        null
    } catch (_: NetworkError) {
        // §11.2.5: fail closed on transport failure — never a silent allow.
        respondError(HttpStatusCode.ServiceUnavailable, "authz_unavailable", "authorization service unavailable")
        null
    } catch (_: AuthError) {
        // A credential was presented (requireAuth already succeeded above),
        // so — as for the plugin's own onCall rejection — this is §28.4's
        // `invalid_token` vector.
        mcpChallenges()?.let {
            response.headers.append(HttpHeaders.WWWAuthenticate, challengeFor401(it, credentialPresented = true))
        }
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
 * The single deny path for a resource check: a 403, carrying one
 * `WWW-Authenticate` challenge when eligible — a UMA ticket (§20.3) when a
 * [UmaChallenger] is configured and minting succeeds, else the §28
 * `insufficient_scope` hint (§28.5 rule 5) when [scope] was named and
 * [reasonCode] is `no_grant`. A successfully-minted UMA ticket wins when
 * both apply: it is a working ticket the caller can act on immediately,
 * where §28's hint only points at a document to go discover one from.
 */
private suspend fun ApplicationCall.denied(action: String, resourceId: String, scope: String?, reasonCode: String?) {
    val header = umaChallengeHeaderOrNull(action, resourceId)
        ?: challengeFor403(mcpChallenges(), reasonCode, scope)
    header?.let {
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
