package io.axiam.sdk.mcp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The RFC 9728 §2 document (CONTRACT.md §28.2) — carries **at most** the five
 * members below, in this order, and no others. Member names are the wire
 * names: this type serializes to the document byte for byte.
 *
 * Two members are **omitted rather than emitted empty or `null`**:
 * [scopesSupported] when the caller passed no scopes, and
 * [resourceDocumentation] when the caller passed none. [Mcp.protectedResourceMetadata]
 * is the only supported way to build one — its validation is what makes every
 * instance of this type a document CONTRACT.md §28.2 actually permits.
 *
 * @property resource the resource identifier this server publishes for itself
 *   — the string an RFC 8707 `resource` parameter carries and the `aud` the
 *   guard checks
 * @property authorizationServers the issuer identifiers of the authorization
 *   servers that guard this resource. At least one, each verbatim
 * @property scopesSupported the scope tokens this resource server
 *   understands, in the caller's order. `null` (and omitted from the JSON)
 *   when the caller passed none
 * @property bearerMethodsSupported always `["header"]` in this contract
 *   version — §10's guard reads a bearer credential from the `Authorization`
 *   header alone
 * @property resourceDocumentation a human-readable documentation page.
 *   `null` (and omitted from the JSON) when the caller passed none — never
 *   emitted as `null`
 */
@Serializable
data class ProtectedResourceMetadataDocument(
    val resource: String,
    @SerialName("authorization_servers") val authorizationServers: List<String>,
    @SerialName("scopes_supported") val scopesSupported: List<String>? = null,
    @SerialName("bearer_methods_supported") val bearerMethodsSupported: List<String>,
    @SerialName("resource_documentation") val resourceDocumentation: String? = null,
)

/**
 * What [Mcp.protectedResourceMetadata] returns: the document, the path it is
 * served at, and the URL that path resolves to.
 *
 * [metadataUrl] exists so that the guard's `resourceMetadataUrl` option
 * (CONTRACT.md §28.5) is fed from the helper that derived it rather than
 * retyped — retyping is how the two come to disagree, and a challenge
 * pointing at a document that is not this resource server's is worse than no
 * challenge at all.
 *
 * @property document the RFC 9728 §2 document, ready to serialize
 * @property metadataPath the absolute path the document is served at,
 *   derived from [document]'s `resource` per §28.3 — never chosen
 * @property metadataUrl [metadataPath] resolved against the resource's
 *   scheme and authority. Feed this to `AxiamAuthConfig.resourceMetadataUrl`
 */
data class ProtectedResourceMetadata(
    val document: ProtectedResourceMetadataDocument,
    val metadataPath: String,
    val metadataUrl: String,
)

/**
 * RFC 6750 §3.1's three `error` codes — the complete vocabulary a
 * `WWW-Authenticate: Bearer` challenge may name (CONTRACT.md §28.4). Not even
 * a well-formed-looking OAuth error code such as `invalid_grant` is accepted
 * outside these three.
 *
 * @property wireValue the exact token this error is spelled with inside the
 *   challenge, e.g. `error="invalid_token"`
 */
enum class BearerChallengeError(val wireValue: String) {
    /** A 400 an application builds for its own malformed request; never emitted by this SDK's own guards. */
    INVALID_REQUEST("invalid_request"),

    /** A credential was presented and rejected — the only reason this SDK's own guards ever name. */
    INVALID_TOKEN("invalid_token"),

    /** A `requireAccess` check named a scope and the decision came back `no_grant` (§28.5 rule 5). */
    INSUFFICIENT_SCOPE("insufficient_scope"),
}

/** `explicitNulls = false` is what omits [ProtectedResourceMetadataDocument]'s two optional members rather than writing them as `null`. */
private val DOCUMENT_JSON = Json { explicitNulls = false }

/** Serializes [ProtectedResourceMetadataDocument] to the exact JSON of CONTRACT.md §28.2. */
internal fun ProtectedResourceMetadataDocument.toJson(): String =
    DOCUMENT_JSON.encodeToString(ProtectedResourceMetadataDocument.serializer(), this)
