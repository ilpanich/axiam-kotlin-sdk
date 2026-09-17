package io.axiam.sdk.ktor

import io.axiam.sdk.mcp.ProtectedResourceMetadata
import io.axiam.sdk.mcp.requireMetadataMatchesGuard
import io.axiam.sdk.mcp.toJson
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

/**
 * `serveProtectedResourceMetadata(app, metadata)` (CONTRACT.md §28.3) —
 * register the one `GET` route that serves the RFC 9728 protected-resource
 * metadata document, on this application's own routing tree, and return the
 * same [metadata] so [AxiamAuthConfig.resourceMetadataUrl] can be fed from
 * [ProtectedResourceMetadata.metadataUrl] rather than retyped.
 *
 * **The path is derived, not chosen**, and **exactly one route is
 * registered** — call this once per resource; a deployment fronting several
 * resources calls it once per resource, and the derived paths cannot
 * collide because each comes from its own resource's own `metadataPath`.
 *
 * The response is `200` with `Content-Type: application/json`, the document
 * as its body, `Cache-Control: public, max-age=3600` and
 * `Access-Control-Allow-Origin: *` — the last because an MCP client running
 * in a browser cannot read the document without it, and it is safe
 * precisely because the response is identical for every caller. It carries
 * no `Access-Control-Allow-Credentials`, which would be asking a browser to
 * attach the user's cookies to a request that has no use for them. Nothing
 * is read from the request, so there is no `Set-Cookie` and no per-caller
 * content. The body is serialized **once**, at registration time.
 *
 * **Serving it needs no route ordering.** `AxiamAuthentication` exempts this
 * exact path from its own credential check itself, from the
 * `resourceMetadataUrl` it was configured with (§28.3 rule 2) — so this call
 * can come before or after `install(AxiamAuthentication)`.
 *
 * @param metadata the value [io.axiam.sdk.mcp.Mcp.protectedResourceMetadata] returned.
 * @param guardResourceMetadataUrl optionally, the paired `AxiamAuthConfig.resourceMetadataUrl`
 *   this document is meant to pair with — passing it applies §28.5 rule 3's
 *   cross-check. Omit it (the default) where the guard is configured in a
 *   different process: nothing can be checked there, and both sides are
 *   configured from the one [ProtectedResourceMetadata.metadataUrl] constant instead.
 * @param guardExpectedAudience the paired guard's `AxiamClient.expectedAudience`,
 *   checked against [metadata]'s `resource` under the same condition as
 *   [guardResourceMetadataUrl].
 * @throws io.axiam.sdk.errors.ValidationError when [guardResourceMetadataUrl] is given and is not exactly
 *   [ProtectedResourceMetadata.metadataUrl], or [guardExpectedAudience] is given and is not exactly
 *   [ProtectedResourceMetadata.document]'s `resource`.
 *
 * Example:
 * ```kotlin
 * val metadata = Mcp.protectedResourceMetadata(
 *     resource = "https://mcp.example.com/mcp",
 *     authorizationServers = listOf("https://axiam.example.com"),
 *     scopesSupported = listOf("mcp:read", "mcp:tools"),
 * )
 * val guardClient = AxiamClient.builder(baseUrl, tenantId)
 *     .expectedAudience(metadata.document.resource)
 *     .build()
 *
 * install(AxiamAuthentication) {
 *     client = guardClient
 *     resourceMetadataUrl = metadata.metadataUrl
 * }
 * routing {
 *     serveProtectedResourceMetadata(metadata, metadata.metadataUrl, guardClient.expectedAudience())
 * }
 * ```
 */
fun Route.serveProtectedResourceMetadata(
    metadata: ProtectedResourceMetadata,
    guardResourceMetadataUrl: String? = null,
    guardExpectedAudience: String? = null,
): ProtectedResourceMetadata {
    requireMetadataMatchesGuard(metadata, guardResourceMetadataUrl, guardExpectedAudience)

    // §28.3 rule 4: identical for every caller, so there is nothing
    // per-request to (re)build.
    val body = metadata.document.toJson()

    get(metadata.metadataPath) {
        call.response.headers.append(HttpHeaders.CacheControl, "public, max-age=3600")
        call.response.headers.append(HttpHeaders.AccessControlAllowOrigin, "*")
        call.respondText(body, ContentType.Application.Json, HttpStatusCode.OK)
    }
    return metadata
}
