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
 * [search] lives here rather than as a third argument on each of the twenty
 * generated `list` methods, which is what §27.4 rule 4 requires: the term is
 * part of *which page this is*, not an unrelated filter. That is also what makes
 * [Page.nextPage] — and so `listAll` — carry it across the whole walk for free.
 * A walk that filtered the first request and not the rest would return the
 * matches followed by the unfiltered tail, which reads as a server bug from the
 * caller's side.
 *
 * @property offset how many items to skip; never negative
 * @property limit  how many to ask for, or `null` to let the server decide
 * @property search a free-text filter applied by the **server**, before
 *   `offset`/`limit`, or `null` for none. Matched case-insensitively against
 *   the identifying fields of whatever is being listed — a name or username,
 *   plus the record id, so a UUID out of a log line can be pasted in as-is.
 *   [Page.total] then counts *matches*, not rows. An empty or all-whitespace
 *   term is the same request as `null`: a search box that fires on every
 *   keystroke sends one the moment it is cleared, and "rows containing the
 *   empty string" is a different question from "all rows". The server caps the
 *   term's length; this SDK deliberately does not re-implement that cap,
 *   because a client-side truncation the server would not have made is a
 *   silently different query.
 */
data class PageRequest(
    val offset: Int = 0,
    val limit: Int? = null,
    val search: String? = null,
) {

    init {
        require(offset >= 0) { "offset must not be negative, got $offset" }
        require(limit == null || limit > 0) { "limit must be positive when given, got $limit" }
    }

    /** The next window of the same size and term, for a manual walk. */
    fun next(consumed: Int): PageRequest = copy(offset = offset + consumed)

    companion object {
        /** The first page, with the server's own default size. */
        fun first(): PageRequest = PageRequest()

        /** The first page of [limit] items. */
        fun of(limit: Int): PageRequest = PageRequest(0, limit)

        /**
         * The first page of [limit] items matching [term].
         *
         * The §27.4 rule 4 shape: the term rides on the page request, so
         * `listAll` carries it across every request of the walk rather than
         * only the first.
         */
        fun matching(limit: Int, term: String?): PageRequest = PageRequest(0, limit, term)
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

    /**
     * Where the next page starts, or `null` when [isLast].
     *
     * @param search the term the walk is filtering by, carried forward. A walk
     *   that filtered only its first request would concatenate the matches with
     *   the unfiltered remainder (§27.4 rule 4), so this is not optional in
     *   practice — `collectPages` always passes what it started with.
     */
    fun nextPage(search: String? = null): PageRequest? =
        if (isLast) null else PageRequest(offset + items.size, limit.takeIf { it > 0 }, search)

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
