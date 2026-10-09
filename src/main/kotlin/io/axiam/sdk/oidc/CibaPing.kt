package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ValidationError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest

/**
 * The receiving half of CIBA ping mode — CONTRACT.md §33.1's
 * `ciba_handle_ping`, a pure function over the raw request: no I/O, no state.
 */
internal object CibaPing {

    /**
     * Checks a ping's bearer and body and returns the `auth_req_id` it names.
     *
     * 1. Exactly one `Authorization` header (name matched case-insensitively),
     *    `Bearer` (any case), one space, and the token — compared in constant
     *    time with [MessageDigest.isEqual]. Otherwise an [AuthError] whose
     *    message names no value.
     * 2. A JSON object with a non-empty string `auth_req_id`; any other member
     *    is ignored. Otherwise a [ValidationError].
     */
    fun handle(
        headers: Iterable<Pair<String, String>>,
        body: String,
        expectedToken: Sensitive<String>,
    ): Sensitive<String> {
        val authorization = headers.filter { (name, _) -> name.equals("Authorization", ignoreCase = true) }
        if (authorization.size != 1) throw refused()
        val value = authorization.single().second
        val space = value.indexOf(' ')
        if (space <= 0) throw refused()
        val scheme = value.substring(0, space)
        val token = value.substring(space + 1)
        if (!scheme.equals("Bearer", ignoreCase = true) || token.isEmpty()) throw refused()
        val expected = expectedToken.expose()
        if (expected.isEmpty() ||
            !MessageDigest.isEqual(token.toByteArray(Charsets.UTF_8), expected.toByteArray(Charsets.UTF_8))
        ) {
            throw refused()
        }

        val parsed = try {
            Json.parseToJsonElement(body)
        } catch (_: Exception) {
            throw ValidationError("cibaHandlePing: the ping body is not JSON (CONTRACT.md §33.1)")
        }
        val id = ((parsed as? JsonObject)?.get("auth_req_id") as? JsonPrimitive)
            ?.takeIf { it.isString }?.content
        if (id.isNullOrEmpty()) {
            throw ValidationError(
                "cibaHandlePing: the ping body carries no non-empty auth_req_id string (CONTRACT.md §33.1)",
            )
        }
        return Sensitive.of(id)
    }

    private fun refused() = AuthError(
        "CIBA ping refused: the Authorization header is not the expected bearer (CONTRACT.md §33.1)",
    )
}
