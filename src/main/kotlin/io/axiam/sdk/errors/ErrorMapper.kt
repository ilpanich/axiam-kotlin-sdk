package io.axiam.sdk.errors

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Response

/**
 * Central HTTP-status → error-type mapper (CONTRACT.md §2). The single source
 * of truth for the taxonomy so no call site can drift from the contract's
 * status table:
 *
 * | Status        | Type          |
 * |---------------|---------------|
 * | 401           | [AuthError]   |
 * | 403, 409      | [AuthzError]  |
 * | 400/408/429/5xx/other | [NetworkError] |
 *
 * [sanitize] is the ONLY path from a live [Response] into a [NetworkError]: it
 * redacts every header not on a small allowlist and returns a lightweight
 * string summary — the live response (with its unredacted headers) is never
 * retained on the exception.
 */
object ErrorMapper {

    private val json = Json { ignoreUnknownKeys = true }

    // Only these response headers survive verbatim into a NetworkError summary;
    // every other header value is redacted. Allowlist (not denylist) so a
    // custom sensitive header can never leak. Compared case-insensitively.
    private val SAFE_HEADERS = setOf(
        "content-type", "content-length", "date", "server", "retry-after",
        "x-request-id", "x-tenant-id",
    )
    private const val REDACTED_HEADER = "[REDACTED]"
    private const val MAX_AUTHZ_BODY_PEEK_BYTES = 8192L

    /**
     * Maps an HTTP [status] to the contract's error type. For 403/409 the
     * response body is parsed (non-destructively) for `action`/`resource_id`.
     */
    fun fromHttpStatus(status: Int, message: String, response: Response?): AxiamException =
        when (status) {
            401 -> AuthError(message)
            403, 409 -> authzErrorFromBody(message, response)
            else -> NetworkError.withSummary(message, sanitize(response))
        }

    private fun authzErrorFromBody(message: String, response: Response?): AuthzError {
        if (response == null || response.body == null) {
            return AuthzError(message)
        }
        return try {
            val bodyString = response.peekBody(MAX_AUTHZ_BODY_PEEK_BYTES).string()
            if (bodyString.isBlank()) {
                AuthzError(message)
            } else {
                val obj = json.parseToJsonElement(bodyString).jsonObject
                val action = obj["action"]?.jsonPrimitive?.contentOrNullSafe()
                val resourceId = obj["resource_id"]?.jsonPrimitive?.contentOrNullSafe()
                AuthzError(message, action, resourceId)
            }
        } catch (_: Exception) {
            // Malformed/non-JSON body: never let a parse failure mask the 403/409.
            AuthzError(message)
        }
    }

    private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
        if (this is kotlinx.serialization.json.JsonNull) null else content

    /**
     * Redacts every non-allowlisted header to a placeholder and returns a
     * string summary — never the live [Response].
     */
    private fun sanitize(response: Response?): String? {
        if (response == null) return null
        val safe = StringBuilder()
        for (name in response.headers.names()) {
            val isSafe = SAFE_HEADERS.contains(name.lowercase())
            for (value in response.headers.values(name)) {
                if (safe.isNotEmpty()) safe.append(", ")
                safe.append(name).append('=').append(if (isSafe) value else REDACTED_HEADER)
            }
        }
        return "http status ${response.code}, headers: [$safe]"
    }
}
