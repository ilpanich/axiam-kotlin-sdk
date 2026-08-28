package io.axiam.sdk.internal

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.FieldError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.telemetry.TelemetryEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

/**
 * The one request path every CONTRACT.md §27 management operation goes through.
 *
 * §27.8 is explicit that the generated layer MUST sit on the SDK's existing
 * request path and MUST NOT build its own. That is what this class is: 147
 * generated operations all funnel into [send], so they inherit §3 (CSRF), §4
 * (the cookie jar), §5 (`X-Tenant-Id`), §6 (TLS), §16 (retry) and §19
 * (telemetry) by construction rather than by 147 opportunities to forget one —
 * the first four because every request goes through the same decorated
 * [OkHttpClient] the rest of the SDK uses.
 *
 * Internal plumbing. It is public only because the generated
 * `io.axiam.sdk.management` surface lives in another package; it is not part of
 * this SDK's supported API and may change without notice.
 */
class ManagementTransport internal constructor(
    private val http: OkHttpClient,
    private val baseUrl: String,
    private val sessionState: SessionState,
    private val telemetry: TelemetryDispatcher,
    private val retryEnabled: Boolean,
    private val ensureOpen: () -> Unit,
) {

    /** The session every management call rides on; read for §27.4 rule 3. */
    fun session(): SessionState = sessionState

    /**
     * Issues one management request and returns its parsed body.
     *
     * @param operation the canonical `namespace.operation` name, for errors and §19 labels
     * @param method the HTTP method the registry declares
     * @param pathTemplate the UNSUBSTITUTED path, used as the §19.1 telemetry label
     * @param path the substituted path actually requested
     * @param query query parameters; a `null` value is omitted rather than sent empty
     * @param body the already-encoded JSON request body, or `null` for none
     * @return the parsed response body, or `null` for a 204 or an empty body
     */
    suspend fun send(
        operation: String,
        method: String,
        pathTemplate: String,
        path: String,
        query: Map<String, String?> = emptyMap(),
        body: String? = null,
    ): JsonElement? {
        ensureOpen()
        requireSession(operation)

        // §27.4 rule 8: every GET here is read-only and retry-eligible under
        // §16.2; every POST, PUT and DELETE is not — including the ones that
        // look idempotent. certificates.generate twice mints two certificates.
        if (method != "GET") {
            return attempt(operation, method, pathTemplate, path, query, body, 1)
        }
        return Retry.withRetry(
            operation = operation,
            enabled = retryEnabled,
            telemetry = telemetry,
            // A rejected body is not a transient fault: the same bytes earn the
            // same refusal, three times as slowly.
            retryable = { it !is ValidationError },
        ) { n -> attempt(operation, method, pathTemplate, path, query, body, n) }
    }

    /**
     * §27.4 rule 1: no session means no wire call.
     *
     * Refused here, once, rather than in 147 generated operations — and refused
     * BEFORE the socket, so an unauthenticated caller gets a message naming the
     * missing session instead of a 401 they have to interpret.
     */
    private fun requireSession(operation: String) {
        if (sessionState.cachedAccessToken() == null) {
            throw AuthError(
                "$operation: no active session. The management API acts as the logged-in " +
                    "administrator, so call login() (or complete an OAuth2 flow) first — " +
                    "this call was refused locally and never reached the network.",
            )
        }
    }

    private suspend fun attempt(
        operation: String,
        method: String,
        pathTemplate: String,
        path: String,
        query: Map<String, String?>,
        body: String?,
        attemptNumber: Int,
    ): JsonElement? {
        val url = (baseUrl + path).toHttpUrlOrNull()?.newBuilder()
            ?: throw NetworkError("$operation: could not build a URL for $path")
        // Sorted so a request is reproducible from its telemetry, and so two
        // otherwise-identical requests cannot differ by map iteration order.
        for ((name, value) in query.toSortedMap()) {
            if (value != null) {
                url.addQueryParameter(name, value)
            }
        }

        val request = Request.Builder().url(url.build())
        val payload = body?.toRequestBody(JSON_MEDIA)
        when {
            payload != null -> request.method(method, payload)
            method == "GET" || method == "DELETE" -> request.method(method, null)
            else -> request.method(method, EMPTY_BODY.toRequestBody(JSON_MEDIA))
        }

        // §19.1: the label is the TEMPLATE, never the substituted path — a label
        // carrying a tenant's user identifiers is a cardinality explosion and a
        // disclosure at once.
        val span = telemetry.startRequest(operation, method, pathTemplate, attemptNumber)

        val response = try {
            execute(operation, request.build())
        } catch (e: Throwable) {
            span.end(null, TelemetryEvent.Outcome.FAILURE)
            throw e
        }

        response.use {
            if (!it.isSuccessful) {
                span.end(it.code, TelemetryEvent.Outcome.FAILURE)
                throw classify(operation, it)
            }
            span.end(it.code, TelemetryEvent.Outcome.SUCCESS)
            return readBody(operation, it)
        }
    }

    private suspend fun execute(operation: String, request: Request): Response =
        withContext(Dispatchers.IO) {
            try {
                http.newCall(request).execute()
            } catch (e: IOException) {
                throw NetworkError("$operation: request failed: ${e.message}", e)
            }
        }

    private fun readBody(operation: String, response: Response): JsonElement? {
        if (response.code == 204) return null
        val text = response.body?.string()
        if (text.isNullOrBlank()) return null
        return try {
            Json.parseToJsonElement(text)
        } catch (e: Exception) {
            throw NetworkError("$operation: could not parse the server's response: ${e.message}", e)
        }
    }

    /**
     * Maps a failed management response onto the §2 taxonomy.
     *
     * §27.4 rule 7 adds three classifications and widens the taxonomy no
     * further: everything the table does not name falls through to
     * [ErrorMapper], which is §2's own mapping and stays the single source of
     * truth for it.
     */
    private fun classify(operation: String, response: Response): Throwable {
        val body = peek(response)
        val detail = describe(body)
        return when (response.code) {
            404 -> NotFoundError("$operation: not found$detail")
            409 -> ConflictError("$operation: conflict$detail")
            400, 422 -> ValidationError("$operation: rejected$detail", parseFieldErrors(body))
            else -> ErrorMapper.fromHttpStatus(response.code, "$operation failed", response)
        }
    }

    /** At most a few KB of an error body is needed to explain the refusal. */
    private fun peek(response: Response): String =
        try {
            response.peekBody(MAX_ERROR_PEEK_BYTES).string()
        } catch (_: IOException) {
            ""
        }

    private fun describe(body: String): String {
        if (body.isBlank()) return ""
        return try {
            val obj = Json.parseToJsonElement(body).jsonObject
            val message = obj["message"] ?: obj["error"]
            if (message == null || message is JsonNull) {
                ""
            } else {
                ": " + message.jsonPrimitive.content
            }
        } catch (_: Exception) {
            ": " + body.take(MAX_ERROR_TEXT_CHARS)
        }
    }

    /**
     * Pulls field-level detail out of an error body, on a best-effort basis.
     *
     * Two shapes are recognised — an array of `{field, message}` and an object
     * keyed by field name. A body in neither shape yields no fields rather than
     * an error: failing to parse an error body would replace a useful message
     * with a useless one.
     */
    private fun parseFieldErrors(body: String): List<FieldError> {
        if (body.isBlank()) return emptyList()
        val errors = try {
            Json.parseToJsonElement(body).jsonObject["errors"] ?: return emptyList()
        } catch (_: Exception) {
            return emptyList()
        }
        return try {
            when {
                errors is JsonNull -> emptyList()
                errors.toString().startsWith("[") -> errors.jsonArray.mapNotNull { item ->
                    val obj = item.jsonObject
                    val field = obj["field"]?.jsonPrimitive?.content ?: return@mapNotNull null
                    FieldError(field, obj["message"]?.jsonPrimitive?.content ?: "is invalid")
                }
                else -> errors.jsonObject.map { (field, value) ->
                    FieldError(field, fieldMessage(value))
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun fieldMessage(value: JsonElement): String =
        try {
            if (value.toString().startsWith("[")) {
                value.jsonArray.joinToString("; ") { it.jsonPrimitive.content }
            } else {
                value.jsonPrimitive.content
            }
        } catch (_: Exception) {
            value.toString()
        }

    companion object {
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val EMPTY_BODY = ByteArray(0)
        private const val MAX_ERROR_PEEK_BYTES = 8192L
        private const val MAX_ERROR_TEXT_CHARS = 200

        /**
         * Reads §27 responses. Secrets deserialize into `Sensitive`, and
         * re-serializing one renders `[SENSITIVE]` (§27.5).
         */
        val READER: Json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            serializersModule = kotlinx.serialization.modules.SerializersModule {
                contextual(io.axiam.sdk.Sensitive::class) {
                    io.axiam.sdk.management.SensitiveRedactingSerializer
                }
            }
        }

        /**
         * The ONE writer that serializes a `Sensitive` in the clear.
         *
         * `encodeDefaults = false` is what gives §27.4 rule 5 its teeth: a
         * sparse body's properties all default to `null`, so a property the
         * caller never named is absent from the JSON entirely rather than sent
         * as `null` — which the server reads as "clear this field". A
         * replacement body has no defaults, so every one of its fields is
         * written.
         */
        val WIRE: Json = Json {
            encodeDefaults = false
            explicitNulls = false
            serializersModule = kotlinx.serialization.modules.SerializersModule {
                contextual(io.axiam.sdk.Sensitive::class) {
                    io.axiam.sdk.management.SensitiveExposingSerializer
                }
            }
        }
    }
}
