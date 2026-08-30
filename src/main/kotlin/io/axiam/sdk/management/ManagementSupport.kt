package io.axiam.sdk.management

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.ManagementTransport
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
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
            "search" to normalizeSearch(request.search),
        )
    }

    /**
     * The trimmed term, or `null` when there is nothing to filter on.
     *
     * Mirrors the server's own normalisation minus the length cap, which is the
     * server's to apply. A `null` value here is dropped before the request is
     * built, so an unfiltered read and a read whose search box was cleared are
     * the same request on the wire (§27.4 rule 4).
     */
    fun normalizeSearch(term: String?): String? = term?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * The one field an EMPTY list must not reach the wire as.
     *
     * CONTRACT.md §5.2.3 rule 1: `tenant_scope: []` is refused with `400`, and an
     * empty list is exactly what building the field from a filtered collection
     * produces for "no tenants named" — so both spellings of absent have to travel
     * the same way, by not appearing. `encodeDefaults = false` covers the `null`
     * default and nothing else: a list explicitly set to empty is not its default.
     *
     * Deliberately an allowlist of ONE, not a blanket "drop empty arrays". Elsewhere
     * `[]` is meaningful — a replacement body clearing a list — and dropping it
     * would make "remove every entry" inexpressible. `ManagementSemanticsTest` pins
     * that with a webhook whose event list is being cleared.
     */
    private val OMIT_WHEN_EMPTY = setOf("tenant_scope")

    /**
     * Encodes a request body exactly as it goes on the socket.
     *
     * Routed through [ManagementTransport.WIRE] — the single writer that
     * serializes a `Sensitive` in the clear (§27.5) and omits unset properties
     * (§27.4 rule 5). A body encoded with any other `Json` throws rather than
     * quietly emitting a placeholder the server would reject.
     *
     * The one thing the serializer configuration cannot express is [OMIT_WHEN_EMPTY],
     * which is applied here — the single choke point every generated write goes
     * through, so no namespace handle can be written that skips it.
     */
    fun <T> encodeBody(operation: String, serializer: SerializationStrategy<T>, body: T): String =
        try {
            dropEmptyAllowlisted(
                ManagementTransport.WIRE.encodeToJsonElement(serializer, body),
            ).toString()
        } catch (e: Exception) {
            throw NetworkError("$operation: could not encode the request body: ${e.message}", e)
        }

    /** Removes any [OMIT_WHEN_EMPTY] property that encoded to an empty array. */
    private fun dropEmptyAllowlisted(encoded: JsonElement): JsonElement {
        val obj = encoded as? JsonObject ?: return encoded
        val empty = OMIT_WHEN_EMPTY.filter { (obj[it] as? JsonArray)?.isEmpty() == true }
        if (empty.isEmpty()) return encoded
        return JsonObject(obj.filterKeys { it !in empty })
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
            // The term is carried, not dropped (§27.4 rule 4): a walk that
            // filtered only its first request would concatenate the matches
            // with the unfiltered remainder.
            val next = page.nextPage(request.search) ?: return out
            request = next
        }
    }
}
