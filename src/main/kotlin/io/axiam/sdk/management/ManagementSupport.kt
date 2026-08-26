package io.axiam.sdk.management

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.ManagementTransport
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.UUID

/**
 * The pieces every generated namespace handle leans on.
 *
 * `internal` on purpose: the generated handles live in this module, so nothing
 * here needs to be public, and none of it is API a caller should reach for.
 */
internal object ManagementSupport {

    /**
     * Resolves `{org_id}`: the handle's override, else the client's.
     *
     * A client built with an organization *slug* that has not logged in fails
     * HERE, with no wire call. §27.4 rule 3 forbids resolving the slug behind
     * the caller's back: a silent extra round-trip on an admin path is what
     * §12.1 rule 2 refuses for `/oauth2/…`, and for the same reason — the
     * caller cannot see it, cannot cache it, and pays for it on every call.
     */
    fun resolveOrg(transport: ManagementTransport, scope: NamespaceScope, operation: String): UUID =
        scope.orgId
            ?: transport.session().resolvedOrgId()
            ?: throw NetworkError(
                "$operation: this route needs an organization UUID and the client has none. " +
                    "Build the client with orgId(...), log in so the access token's org_id " +
                    "claim resolves one, or name one on the handle with inOrg(...).",
            )

    /**
     * Resolves `{tenant_id}` where it names the *context*, not the object.
     *
     * Namespaces where `{tenant_id}` names the thing being acted on — `tenants`,
     * and the signing CAs under `ca_certificates` — take it as an ordinary
     * argument instead and never reach this.
     */
    fun resolveTenant(transport: ManagementTransport, scope: NamespaceScope, operation: String): UUID =
        scope.tenantId
            ?: transport.session().resolvedTenantId()
            ?: throw NetworkError(
                "$operation: this route needs a tenant UUID, but none has been resolved yet. " +
                    "Call login() so the access token's tenant_id claim resolves one, or name " +
                    "one on the handle with forTenant(...).",
            )

    /**
     * The query contribution of a [PageRequest].
     *
     * `limit` is omitted entirely when unset rather than sent as `0` — the
     * server reads `limit=0` as "none", which would return an empty page.
     */
    fun pageQuery(query: Map<String, String?>, page: PageRequest?): Map<String, String?> {
        val request = page ?: PageRequest.first()
        return query + mapOf(
            "offset" to request.offset.toString(),
            "limit" to request.limit?.toString(),
        )
    }

    /**
     * Encodes a request body exactly as it goes on the socket.
     *
     * Routed through [ManagementTransport.WIRE] — the single writer that
     * serializes a `Sensitive` in the clear (§27.5) and omits unset properties
     * (§27.4 rule 5). A body encoded with any other `Json` throws rather than
     * quietly emitting a placeholder the server would reject.
     */
    fun <T> encodeBody(operation: String, serializer: SerializationStrategy<T>, body: T): String =
        try {
            ManagementTransport.WIRE.encodeToString(serializer, body)
        } catch (e: Exception) {
            throw NetworkError("$operation: could not encode the request body: ${e.message}", e)
        }

    /** Converts a response node into a model, or throws a [NetworkError]. */
    fun <T> decode(operation: String, deserializer: DeserializationStrategy<T>, node: JsonElement?): T {
        val element = node ?: throw NetworkError(
            "$operation: the server returned no body where one was expected",
        )
        return try {
            ManagementTransport.READER.decodeFromJsonElement(deserializer, element)
        } catch (e: Exception) {
            throw NetworkError("$operation: the server's response did not match: ${e.message}", e)
        }
    }

    /** Converts a bare-array response into a list of models (§27.4 rule 4). */
    fun <T> decodeList(
        operation: String,
        deserializer: DeserializationStrategy<T>,
        node: JsonElement?,
    ): List<T> {
        if (node == null || node is JsonNull) return emptyList()
        val array = try {
            node.jsonArray
        } catch (_: IllegalArgumentException) {
            // An empty list is the honest answer to "what scopes are there" when
            // the server sent something that is not a list of them, and it keeps
            // a malformed read from taking down a plan that was only surveying.
            return emptyList()
        }
        return array.map { decode(operation, deserializer, it) }
    }

    /**
     * Converts an `{items, total, offset, limit}` envelope into a [Page].
     *
     * `total` is read from the envelope and never inferred from the item count:
     * the whole point of the type is that the two differ (§27.4 rule 4).
     */
    fun <T> decodePage(
        operation: String,
        deserializer: DeserializationStrategy<T>,
        node: JsonElement?,
    ): Page<T> {
        if (node == null || node is JsonNull) return Page.empty()
        val obj = try {
            node.jsonObject
        } catch (_: IllegalArgumentException) {
            return Page.empty()
        }
        return Page(
            items = decodeList(operation, deserializer, obj["items"]),
            total = obj.intOr("total"),
            offset = obj.intOr("offset"),
            limit = obj.intOr("limit"),
        )
    }

    private fun kotlinx.serialization.json.JsonObject.intOr(key: String): Int =
        try {
            this[key]?.takeIf { it !is JsonNull }?.jsonPrimitive?.int ?: 0
        } catch (_: Exception) {
            0
        }

    /**
     * Walks a paginated read to exhaustion, concatenating every page.
     *
     * The `listAll` shape §27.4 rule 4 requires. The walk stops on an empty page
     * even when `total` disagrees, so a misreporting server costs one wasted
     * request rather than an unbounded loop.
     */
    suspend fun <T> collectPages(start: PageRequest?, fetch: suspend (PageRequest) -> Page<T>): List<T> {
        var request = start ?: PageRequest.first()
        val out = mutableListOf<T>()
        while (true) {
            val page = fetch(request)
            out += page.items
            val next = page.nextPage() ?: return out
            request = next
        }
    }
}
