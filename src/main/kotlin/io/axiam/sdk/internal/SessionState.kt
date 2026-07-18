package io.axiam.sdk.internal

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.CookieManager
import java.net.URI
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

/**
 * Per-[io.axiam.sdk.AxiamClient] session/cookie/CSRF/tenant/org state
 * (CONTRACT.md §3/§4/§5).
 *
 * Holds no token copy of its own: [cachedAccessToken] always reads the live
 * `axiam_access` cookie from the shared [CookieManager], which OkHttp's
 * `JavaNetCookieJar` keeps in sync on every response — avoiding a second,
 * potentially-stale in-memory token.
 *
 * [doHttpRefresh] is the `suspend` function the [RefreshGuard] invokes: it
 * performs the real `POST /api/v1/auth/refresh`, whose body carries the
 * tenant/org UUIDs decoded (unverified) from the current access token. That
 * decode is only ever an operational hint (tenant/org resolution, near-expiry),
 * never an authorization decision — [JwksVerifier] owns signature verification.
 */
class SessionState(
    private val cookieManager: CookieManager,
    baseUrl: String,
    private val tenantId: String,
    private val configuredOrgSlug: String?,
    private val configuredOrgId: UUID?,
) {
    private val baseUrl: String = baseUrl.trimEnd('/')
    private val baseUri: URI = URI.create(this.baseUrl)
    private val csrf = AtomicReference<String?>(null)
    private val httpClient = AtomicReference<OkHttpClient?>(null)

    fun tenantId(): String = tenantId
    fun baseUrl(): String = baseUrl
    fun configuredOrgSlug(): String? = configuredOrgSlug
    fun configuredOrgId(): UUID? = configuredOrgId

    /** Two-phase wiring: set once by AxiamClient after it builds the OkHttpClient. */
    fun attachHttpClient(client: OkHttpClient) = httpClient.set(client)

    /**
     * Host-isolation guard: `true` only when [host] is this session's own
     * origin. Tenant id, bearer, and CSRF token attach only to same-origin
     * requests, so they never leak to a third-party URL or off-origin redirect.
     * A `null` host fails closed.
     */
    fun isBaseHost(host: String?): Boolean = host != null && host.equals(baseUri.host, ignoreCase = true)

    fun csrfToken(): String? = csrf.get()
    fun setCsrfToken(token: String) = csrf.set(token)

    /** Live `axiam_access` cookie value, or `null`. Never blocks. */
    fun cachedAccessToken(): String? = cookieValue(ACCESS_COOKIE)

    /**
     * Unverified `exp`-claim near-expiry hint (no network round trip). `false`
     * when the token has no decodable `exp` (conservatively not-near, since
     * this is only a proactive hint).
     */
    fun isNearExpiry(accessToken: String, bufferMillis: Long): Boolean {
        val claims = decodeUnverifiedClaims(accessToken) ?: return false
        if (claims.exp <= 0) return false
        return System.currentTimeMillis() >= (claims.exp * 1000L) - bufferMillis
    }

    /** Resets locally-derived state after logout (the cookie jar is cleared by the server's Set-Cookie). */
    fun clear() = csrf.set(null)

    private fun cookieValue(name: String): String? =
        cookieManager.cookieStore.get(baseUri).firstOrNull { it.name == name }?.value

    /**
     * Performs `POST /api/v1/auth/refresh` (CONTRACT.md §1). The body carries
     * the tenant/org UUIDs resolved from the current access token's claims (the
     * real handler requires both). Runs on [Dispatchers.IO]; the refresh path is
     * special-cased by the header interceptor so this can never recursively
     * trigger a nested refresh.
     */
    suspend fun doHttpRefresh(): TokenPair = withContext(Dispatchers.IO) {
        val observed = cachedAccessToken()
            ?: throw AuthError("no access token to refresh — call login() first")
        val observedClaims = decodeUnverifiedClaims(observed)
        if (observedClaims?.tenantId == null) {
            throw AuthError("tenant_id could not be resolved; login() must succeed before refresh()")
        }
        val tenantUuid = parseUuidOrThrow(observedClaims.tenantId, "tenant_id")
        val orgUuid = resolveOrgId(observedClaims)
            ?: throw AuthError(
                "org_id could not be resolved; supply orgId()/orgSlug() or call login() first",
            )

        val body = buildJsonObject {
            put("tenant_id", tenantUuid.toString())
            put("org_id", orgUuid.toString())
        }
        val request = Request.Builder()
            .url(baseUrl + REFRESH_PATH)
            .post(JSON.encodeToString(JsonObject.serializer(), body).toRequestBody(JSON_MEDIA))
            .build()

        val client = httpClient.get()
            ?: throw IllegalStateException("SessionState.attachHttpClient() was never called")

        val response = try {
            client.newCall(request).execute()
        } catch (e: Exception) {
            throw NetworkError("refresh request failed: ${e.message}", e)
        }
        response.use {
            if (!it.isSuccessful) {
                // §9.3: no retry — propagated as-is to every waiter.
                throw ErrorMapper.fromHttpStatus(it.code, "token refresh failed", it)
            }
            val newAccess = cookieValue(ACCESS_COOKIE)
                ?: throw AuthError("refresh response did not set the axiam_access cookie")
            val newRefresh = cookieValue(REFRESH_COOKIE) ?: ""
            val newClaims = decodeUnverifiedClaims(newAccess)
            val expiresAt = if (newClaims != null && newClaims.exp > 0) {
                newClaims.exp * 1000L
            } else {
                System.currentTimeMillis()
            }
            TokenPair(newAccess, newRefresh, expiresAt)
        }
    }

    private fun resolveOrgId(fallback: Claims): UUID? {
        configuredOrgId?.let { return it }
        fallback.orgId?.let {
            return try {
                UUID.fromString(it)
            } catch (_: IllegalArgumentException) {
                null
            }
        }
        return null
    }

    /**
     * Subset of access-token claims decoded WITHOUT verifying the signature —
     * tenant/org resolution and near-expiry only, never an authz decision.
     *
     * @property roles derived from the space-separated `scope` claim (AXIAM has
     *   no dedicated `roles` claim); empty when absent.
     */
    data class Claims(
        val sub: String?,
        val tenantId: String?,
        val orgId: String?,
        val jti: String?,
        val roles: List<String>,
        val exp: Long,
    )

    companion object {
        private const val ACCESS_COOKIE = "axiam_access"
        private const val REFRESH_COOKIE = "axiam_refresh"

        /** The refresh path; special-cased so a refresh cannot nest. */
        const val REFRESH_PATH = "/api/v1/auth/refresh"

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val JSON = Json { ignoreUnknownKeys = true }

        fun isRefreshPath(encodedPath: String): Boolean = REFRESH_PATH == encodedPath

        private fun parseUuidOrThrow(value: String, claimName: String): UUID =
            try {
                UUID.fromString(value)
            } catch (e: IllegalArgumentException) {
                throw AuthError("$claimName claim is not a valid UUID")
            }

        /** Decodes [token]'s claims without verifying its signature; `null` if malformed. */
        fun decodeUnverifiedClaims(token: String): Claims? {
            val parts = token.split(".")
            if (parts.size != 3) return null
            val payloadBytes = try {
                Base64.getUrlDecoder().decode(padBase64Url(parts[1]))
            } catch (_: IllegalArgumentException) {
                return null
            }
            val node = try {
                JSON.parseToJsonElement(String(payloadBytes)) as? JsonObject ?: return null
            } catch (_: Exception) {
                return null
            }
            val scope = node["scope"]?.jsonPrimitiveContentOrNull()
            val roles = if (scope.isNullOrBlank()) emptyList() else scope.trim().split(Regex("\\s+"))
            val exp = node["exp"]?.jsonPrimitiveContentOrNull()?.toLongOrNull() ?: 0L
            return Claims(
                sub = node["sub"]?.jsonPrimitiveContentOrNull(),
                tenantId = node["tenant_id"]?.jsonPrimitiveContentOrNull(),
                orgId = node["org_id"]?.jsonPrimitiveContentOrNull(),
                jti = node["jti"]?.jsonPrimitiveContentOrNull(),
                roles = roles,
                exp = exp,
            )
        }

        private fun kotlinx.serialization.json.JsonElement.jsonPrimitiveContentOrNull(): String? {
            val prim = (this as? kotlinx.serialization.json.JsonPrimitive) ?: return null
            if (prim is kotlinx.serialization.json.JsonNull) return null
            return prim.jsonPrimitive.content
        }

        private fun padBase64Url(s: String): String {
            val rem = s.length % 4
            return if (rem == 0) s else s + "====".substring(rem)
        }
    }
}
