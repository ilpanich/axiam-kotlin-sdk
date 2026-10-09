package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.Retry
import io.axiam.sdk.internal.Sessionless
import io.axiam.sdk.internal.TelemetryDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

/**
 * The engine behind the three RFC 7592 client configuration operations
 * (CONTRACT.md §28.12) — reached only through
 * [io.axiam.sdk.AxiamClient.readClientRegistration],
 * [io.axiam.sdk.AxiamClient.updateClientRegistration] and
 * [io.axiam.sdk.AxiamClient.deleteClientRegistration].
 *
 * Four rules shape all three (§28.12.2):
 *
 * 1. **The URI is used verbatim, and only at the configured AXIAM.** A URI
 *    whose scheme, host or port differs from the client's base URL — or an
 *    `http` URI when the base URL is not `http` on a loopback host — is
 *    refused locally with a [ValidationError], before any request: the token
 *    is a bearer, and a helper that followed a URI to another origin would
 *    hand it to whoever wrote the URI. The refusal names no part of the URI.
 * 2. **The token travels in `Authorization: Bearer` only** — never in the
 *    query, never in a body.
 * 3. **It is not the SDK's session.** These requests go out on a
 *    [Sessionless] transport — no cookie jar, no access token, no CSRF
 *    header, no redirect following — and a `401` from them is mapped straight
 *    to an error, never into the §9 refresh guard.
 * 4. **Neither write is retried.** An update that reached the server and lost
 *    its response has already rotated the token; a delete whose `204` was lost
 *    would read `401` on a retry. Only the read follows §16 — and only on a
 *    transport failure, `408`, `429` or `5xx`.
 */
internal class ClientRegistrationSupport(
    httpClient: OkHttpClient,
    baseUrl: String,
    private val retryEnabled: Boolean,
    private val telemetry: TelemetryDispatcher,
    private val jitter: () -> Double,
) {
    private val bare: OkHttpClient by lazy { Sessionless.of(httpClient) }
    /** The configured origin. The builder already refused a base URL that does not parse. */
    private val base: HttpUrl = baseUrl.toHttpUrl()

    suspend fun read(uri: String, token: Sensitive<String>): ClientRegistration {
        val url = checkUri(uri, "readClientRegistration")
        var lastStatus: Int? = null
        return Retry.withRetry(
            operation = "readClientRegistration",
            enabled = retryEnabled,
            telemetry = telemetry,
            random = jitter,
            // §28.12.2 rule 5 lets the read follow §16 — whose table retries a
            // transport failure, 408, 429 and 5xx, and nothing else. A bodiless
            // 400 maps to NetworkError under §2 and must not be repeated.
            retryable = { lastStatus == null || Retry.isRetryableStatus(lastStatus!!) },
        ) { _ ->
            lastStatus = null
            val request = Request.Builder().url(url).get()
                .header("Authorization", "Bearer ${token.expose()}")
                .header("Accept", "application/json")
                .build()
            execute(request, "readClientRegistration").use { response ->
                lastStatus = response.code
                decode(response, "readClientRegistration")
            }
        }
    }

    suspend fun update(uri: String, token: Sensitive<String>, metadata: ClientRegistration): ClientRegistration {
        val url = checkUri(uri, "updateClientRegistration")
        val body = Json.encodeToString(JsonObject.serializer(), metadata.updateBody()).toRequestBody(JSON_MEDIA)
        val request = Request.Builder().url(url).put(body)
            .header("Authorization", "Bearer ${token.expose()}")
            .header("Accept", "application/json")
            .build()
        return execute(request, "updateClientRegistration").use { decode(it, "updateClientRegistration") }
    }

    suspend fun delete(uri: String, token: Sensitive<String>) {
        val url = checkUri(uri, "deleteClientRegistration")
        val request = Request.Builder().url(url).delete()
            .header("Authorization", "Bearer ${token.expose()}")
            .build()
        execute(request, "deleteClientRegistration").use { response ->
            if (!response.isSuccessful) {
                throw ErrorMapper.fromOAuth2ResponseAtAnyStatus("deleteClientRegistration failed", response)
            }
        }
    }

    /**
     * §28.12.2 rule 1: accept [uri] only at the configured AXIAM origin.
     *
     * The refusal names no part of the URI: it is caller input, and an error
     * message is the one thing most often logged.
     */
    private fun checkUri(uri: String, operation: String): HttpUrl {
        val parsed = uri.toHttpUrlOrNull()
            ?: throw refusal(operation, "is not an absolute https URL")
        val sameOrigin = parsed.scheme == base.scheme &&
            parsed.host.equals(base.host, ignoreCase = true) && parsed.port == base.port
        val why = when {
            !sameOrigin -> "is not at the configured AXIAM origin (scheme, host and port must match the client's base URL)"
            // Unreachable through the builder today (SEC-073 refuses a plaintext
            // non-loopback base URL), and kept so rule 1 holds on its own.
            parsed.scheme == "http" && !isLoopback(base.host) -> "must be https unless the base URL is http on a loopback host"
            else -> null
        }
        if (why != null) throw refusal(operation, why)
        return parsed
    }

    private fun refusal(operation: String, why: String): ValidationError =
        ValidationError("$operation: registration_client_uri $why (CONTRACT.md §28.12.2 rule 1)")

    private suspend fun execute(request: Request, operation: String): Response = withContext(Dispatchers.IO) {
        try {
            bare.newCall(request).execute()
        } catch (e: IOException) {
            // The message names the operation and the transport fault only —
            // never the URL, which may carry the tenant, or the token.
            throw NetworkError("$operation request failed: ${e.javaClass.simpleName}", e)
        }
    }

    private fun decode(response: Response, operation: String): ClientRegistration {
        if (!response.isSuccessful) {
            throw ErrorMapper.fromOAuth2ResponseAtAnyStatus("$operation failed", response)
        }
        val text = response.body?.string().orEmpty()
        val json = try {
            Json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw NetworkError("$operation: the response is not a JSON object", e)
        }
        return ClientRegistration.fromJson(json)
    }

    private companion object {
        val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

        fun isLoopback(host: String): Boolean =
            host.equals("localhost", ignoreCase = true) || host == "127.0.0.1" || host == "::1"
    }
}
