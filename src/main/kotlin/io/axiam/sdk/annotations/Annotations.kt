package io.axiam.sdk.annotations

/**
 * Declares that an endpoint requires an authenticated AXIAM identity
 * (CONTRACT.md §11 `require_auth`). A request reaching the guarded handler
 * without a verified identity is rejected with HTTP 401
 * (`authentication_failed`).
 *
 * Framework-free (Kotlin's analog of the Java SDK's `@AxiamRequireAuth`);
 * enforced by the Ktor plugin
 * ([io.axiam.sdk.ktor.AxiamAuthentication]) or, for Spring users, by reusing
 * the Java SDK's Spring interceptor.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class AxiamRequireAuth

/**
 * Declares that an endpoint requires the authenticated caller to pass an AXIAM
 * authorization check for [action] on a resource resolved from the request
 * (CONTRACT.md §11 `require_access`). Argument order follows §1:
 * `(action, resource[, scope])`.
 *
 * The check is made for the request's authenticated user (`subject_id`), not the
 * app's own session. The resource UUID is resolved from the static [resourceId]
 * literal when non-empty, else the route parameter named by [resourceParam]. A
 * missing/non-UUID value is a 400 (`invalid_request`); a denied check or server
 * 403 is a 403 (`authorization_denied`); a transport failure fails closed with
 * 503 (`authz_unavailable`).
 *
 * @property action        the action to authorize
 * @property resourceParam the route-parameter name holding the resource UUID (default `"id"`)
 * @property resourceId     a static resource UUID literal (takes precedence when non-empty)
 * @property scope          an optional sub-resource scope passed through verbatim
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class AxiamRequireAccess(
    val action: String,
    val resourceParam: String = "id",
    val resourceId: String = "",
    val scope: String = "",
)

/**
 * Declares that the authenticated caller must hold at least one of [roles]
 * (CONTRACT.md §11 `require_role`). A LOCAL check against the verified token's
 * roles — it never calls the server. 401 if unauthenticated, 403 if the caller
 * holds none of the roles.
 *
 * Role names are tenant-defined; this is cheaper but coarser than
 * [AxiamRequireAccess], which is the authoritative resource-level check.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class AxiamRequireRole(vararg val roles: String)
