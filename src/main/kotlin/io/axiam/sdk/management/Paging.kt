package io.axiam.sdk.management

/**
 * Where to start a paginated read and how much to ask for (CONTRACT.md §27.4
 * rule 4).
 *
 * A `limit` of `null` means "do not send one", which is not the same as
 * sending zero: the server reads `limit=0` as none and answers with an empty
 * page. Leaving it out lets the server apply its own default, and [Page.total]
 * still tells the caller the rest exists.
 *
 * @property offset how many items to skip; never negative
 * @property limit  how many to ask for, or `null` to let the server decide
 */
data class PageRequest(val offset: Int = 0, val limit: Int? = null) {

    init {
        require(offset >= 0) { "offset must not be negative, got $offset" }
        require(limit == null || limit > 0) { "limit must be positive when given, got $limit" }
    }

    /** The next window of the same size, for a manual walk. */
    fun next(consumed: Int): PageRequest = copy(offset = offset + consumed)

    companion object {
        /** The first page, with the server's own default size. */
        fun first(): PageRequest = PageRequest()

        /** The first page of [limit] items. */
        fun of(limit: Int): PageRequest = PageRequest(0, limit)
    }
}

/**
 * One page of a paginated read (CONTRACT.md §27.4 rule 4).
 *
 * [total] is the size of the **whole** set, not of [items]. That distinction is
 * the entire reason this type exists rather than a bare `List`: an SDK that
 * returned the list alone would let a caller conclude a tenant has 50 users
 * because the first page held 50, and §27.4 rule 4 forbids exactly that.
 *
 * @property items  this page's items, in the server's order
 * @property total  how many items exist in total, as the server reported it
 * @property offset the offset this page starts at
 * @property limit  the page size the server actually applied
 */
data class Page<out T>(
    val items: List<T>,
    val total: Int,
    val offset: Int,
    val limit: Int,
) {

    /** `true` when this page is the last one the server can produce. */
    val isLast: Boolean get() = items.isEmpty() || offset + items.size >= total

    /** Where the next page starts, or `null` when [isLast]. */
    fun nextPage(): PageRequest? =
        if (isLast) null else PageRequest(offset + items.size, limit.takeIf { it > 0 })

    companion object {
        /** An empty page, for a read the server answered with no body. */
        fun <T> empty(): Page<T> = Page(emptyList(), 0, 0, 0)
    }
}

/**
 * A per-handle override of the organization or tenant a route interpolates
 * (CONTRACT.md §27.4 rule 3).
 *
 * Both `null` means "inherit from the client", which is the ordinary case.
 * A handle carrying an override is a **new** handle: `inOrg(...)` never mutates
 * the one it was called on, so a scoped call cannot leak into unrelated code
 * holding the same reference.
 *
 * @property orgId    the organization to address, or `null` to inherit
 * @property tenantId the tenant to address, or `null` to inherit
 */
data class NamespaceScope(
    val orgId: java.util.UUID? = null,
    val tenantId: java.util.UUID? = null,
) {
    companion object {
        /** Inherit both from the client. */
        fun inherited(): NamespaceScope = NamespaceScope()
    }
}
