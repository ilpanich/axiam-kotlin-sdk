package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.AuthHeaderInterceptor
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.RefreshGuard
import io.axiam.sdk.internal.SessionState
import io.axiam.sdk.internal.TlsFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.net.CookieManager
import java.net.CookiePolicy
import java.time.Duration
import java.util.UUID

/**
 * The AXIAM Kotlin SDK's public REST entry point (CONTRACT.md §1–§7, §9).
 *
 * All auth/authz operations are `suspend` functions (coroutines) — the
 * canonical names ARE the suspend forms (§1); there are no `*Async` twins. A
 * caller needing a blocking form wraps a call in `runBlocking`.
 *
 * Construction is only via [builder]: `tenantId` (a tenant slug or UUID string)
 * is required (§5) — there is no default tenant. Owns exactly one
 * [RefreshGuard], one [SessionState], and one [JwksVerifier].
 *
 * Conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).
 */
class AxiamClient private constructor(b: Builder) : AutoCloseable {

    private val baseUrl: String = b.baseUrl.trimEnd('/')
    private val tenantId: String = b.tenantId
    private val customCaPem: ByteArray? = b.customCaPem
    private val httpClient: OkHttpClient
    private val refreshGuard = RefreshGuard()
    private val jwksVerifier = JwksVerifier(baseUrl)
    private val session: SessionState

    init {
        val cookieManager = CookieManager(null, CookiePolicy.ACCEPT_ALL)
        session = SessionState(cookieManager, baseUrl, tenantId, b.orgSlug, b.orgId)

        val tls = TlsFactory.build(customCaPem, b.clientCertPem, b.clientKeyPem)

        val base = b.overrideHttpClient?.newBuilder() ?: OkHttpClient.Builder()
        httpClient = base
            // §4: per-client cookie jar. §6/§6.1: strict TLS (+ optional customCa,
            // + optional client identity) is ALWAYS re-applied — an override can
            // never drop the jar or weaken verification.
            .cookieJar(okhttp3.JavaNetCookieJar(cookieManager))
            .sslSocketFactory(tls.sslContext.socketFactory, tls.trustManager)
            .connectTimeout(b.connectTimeout)
            .readTimeout(b.readTimeout)
            .writeTimeout(b.writeTimeout)
            .addInterceptor(AuthHeaderInterceptor(session))
            .build()
        session.attachHttpClient(httpClient)
    }

    // ---- SDK-internal accessors (middleware/§10 seam) --------------------

    /** This client's configured tenant identifier (§5). */
    fun tenantId(): String = tenantId

    /** This client's trailing-slash-stripped base URL. */
    fun baseUrl(): String = baseUrl

    /** The shared, fully-configured OkHttpClient (cookie jar, strict TLS, header interceptor). */
    fun okHttpClient(): OkHttpClient = httpClient

    /** The single [JwksVerifier] used by the §10 middleware to verify sessions. */
    fun jwksVerifier(): JwksVerifier = jwksVerifier

    // ---- Auth methods (§1): login / verifyMfa / refresh / logout --------

    /**
     * `POST /api/v1/auth/login`. Returns a typed [LoginResult]; an MFA challenge
     * (HTTP 202) is an expected outcome, not an exception — check
     * [LoginResult.mfaRequired].
     */
    suspend fun login(email: String, password: String): LoginResult {
        val body = buildJsonObject {
            put("tenant_slug", tenantId)
            session.configuredOrgId()?.let { put("org_id", it.toString()) }
                ?: session.configuredOrgSlug()?.let { put("org_slug", it) }
            put("username_or_email", email)
            put("password", password)
        }
        postJson(LOGIN_PATH, body).use { response ->
            when (response.code) {
                200 -> return LoginResult(mfaRequired = false, user = buildUser())
                202 -> {
                    val wire = readJson(response)
                    val challenge = wire["challenge_token"]?.jsonPrimitive?.content ?: ""
                    return LoginResult(mfaRequired = true, challengeToken = Sensitive.of(challenge))
                }
                else -> throw ErrorMapper.fromHttpStatus(response.code, "login failed", response)
            }
        }
    }

    /**
     * `POST /api/v1/auth/mfa/verify` (§1), completing the two-phase flow started
     * by [login] when `mfaRequired` was `true`.
     */
    suspend fun verifyMfa(mfaToken: Sensitive<String>, totpCode: String): LoginResult {
        val body = buildJsonObject {
            put("challenge_token", mfaToken.expose())
            put("totp_code", totpCode)
        }
        postJson(MFA_VERIFY_PATH, body).use { response ->
            if (response.code != 200) {
                throw ErrorMapper.fromHttpStatus(response.code, "MFA verification failed", response)
            }
            return LoginResult(mfaRequired = false, user = buildUser())
        }
    }

    /**
     * `POST /api/v1/auth/refresh` (§1), routed through the single-flight
     * [RefreshGuard] (§9). A 401 on the refresh call itself is an [AuthError]
     * with no retry (§9.3).
     */
    suspend fun refresh() {
        val observed = session.cachedAccessToken()
            ?: throw AuthError("no access token to refresh — call login() first")
        refreshGuard.refreshIfNeeded(observed) { session.doHttpRefresh() }
    }

    /** `POST /api/v1/auth/logout` (§1) and clears in-memory session state. */
    suspend fun logout() {
        val access = session.cachedAccessToken()
            ?: throw AuthError("no active session to log out")
        val claims = SessionState.decodeUnverifiedClaims(access)
        val jti = claims?.jti
            ?: throw AuthError("access token has no session id (jti) to log out")

        val body = buildJsonObject { put("session_id", jti) }
        postJson(LOGOUT_PATH, body).use { response ->
            if (response.code >= 300) {
                throw ErrorMapper.fromHttpStatus(response.code, "logout failed", response)
            }
            session.clear()
        }
    }

    // ---- Authz methods (§1): checkAccess / can / batchCheck -------------

    /**
     * `POST /api/v1/authz/check` — a single authorization check for the client's
     * own session. Argument order is always `(action, resource[, scope])`.
     */
    suspend fun checkAccess(action: String, resourceId: String, scope: String? = null): AccessResult {
        val body = buildJsonObject {
            put("action", action)
            put("resource_id", resourceId)
            scope?.let { put("scope", it) }
        }
        return sendCheck(body)
    }

    /**
     * `POST /api/v1/authz/check` for an explicit [subjectId] (§11.2 subject
     * propagation) — used by the §11 helpers to check the request's
     * authenticated end user rather than the app's own service-account session.
     */
    suspend fun checkAccess(
        subjectId: String,
        action: String,
        resourceId: String,
        scope: String?,
    ): AccessResult {
        val body = buildJsonObject {
            put("subject_id", subjectId)
            put("action", action)
            put("resource_id", resourceId)
            scope?.let { put("scope", it) }
        }
        return sendCheck(body)
    }

    /** Browser/UI alias for [checkAccess] (§1) returning the boolean decision. */
    suspend fun can(action: String, resourceId: String, scope: String? = null): Boolean =
        checkAccess(action, resourceId, scope).allowed

    /**
     * `POST /api/v1/authz/check/batch` — evaluates an ordered list of checks;
     * results are returned in the same order as [checks].
     */
    suspend fun batchCheck(checks: List<AccessCheck>): List<AccessResult> {
        val body = buildJsonObject {
            put(
                "checks",
                buildJsonArray {
                    for (check in checks) {
                        addJsonObject {
                            put("action", check.action)
                            put("resource_id", check.resourceId)
                            check.scope?.let { put("scope", it) }
                        }
                    }
                },
            )
        }
        val response = postWithRefresh(BATCH_CHECK_PATH, body)
        response.use {
            if (!it.isSuccessful) {
                throw ErrorMapper.fromHttpStatus(it.code, "batchCheck failed", it)
            }
            val wire = readJson(it)
            return wire["results"]?.jsonArray?.map { element ->
                val obj = element.jsonObject
                AccessResult(
                    allowed = obj["allowed"]?.jsonPrimitive?.boolean ?: false,
                    reason = obj["reason"]?.jsonPrimitive?.contentOrNull(),
                )
            } ?: emptyList()
        }
    }

    /**
     * Verifies a bearer/cookie session token for the §10 middleware: EdDSA
     * signature (JWKS), tenant scoping, and expiry — returning the injected
     * [AxiamUser]. Signature failure/tenant mismatch/expiry all surface as
     * [AuthError].
     */
    fun verifySession(token: String): AxiamUser {
        val claims = jwksVerifier.verify(token)
        JwksVerifier.assertTenant(claims, tenantId)
        val exp = claims.expirationTime
        if (exp != null && exp.time <= System.currentTimeMillis()) {
            throw AuthError("token is expired")
        }
        val sub = claims.subject ?: throw AuthError("token has no subject (sub) claim")
        val scope = try {
            claims.getStringClaim("scope")
        } catch (_: Exception) {
            null
        }
        val roles = if (scope.isNullOrBlank()) emptyList() else scope.trim().split(Regex("\\s+"))
        return AxiamUser(sub, tenantId, roles)
    }

    override fun close() {
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
        httpClient.cache?.close()
    }

    // ---- shared HTTP mechanics ------------------------------------------

    private suspend fun sendCheck(body: JsonObject): AccessResult {
        val response = postWithRefresh(CHECK_PATH, body)
        response.use {
            if (!it.isSuccessful) {
                throw ErrorMapper.fromHttpStatus(it.code, "checkAccess failed", it)
            }
            val wire = readJson(it)
            return AccessResult(
                allowed = wire["allowed"]?.jsonPrimitive?.boolean ?: false,
                reason = wire["reason"]?.jsonPrimitive?.contentOrNull(),
            )
        }
    }

    /**
     * Executes a POST; on a 401 with an existing session it runs a single-flight
     * refresh (§9) and retries exactly once. The refresh path is never retried
     * (§9.3).
     */
    private suspend fun postWithRefresh(path: String, body: JsonObject): Response {
        val first = postJson(path, body)
        if (first.code == 401 && !SessionState.isRefreshPath(path)) {
            val observed = session.cachedAccessToken()
            if (observed != null) {
                first.close()
                refreshGuard.refreshIfNeeded(observed) { session.doHttpRefresh() }
                return postJson(path, body)
            }
        }
        return first
    }

    private suspend fun postJson(path: String, body: JsonObject): Response = withContext(Dispatchers.IO) {
        val payload = Json.encodeToString(JsonObject.serializer(), body).toRequestBody(JSON_MEDIA)
        val request = Request.Builder().url(baseUrl + path).post(payload).build()
        try {
            httpClient.newCall(request).execute()
        } catch (e: IOException) {
            throw NetworkError("request failed: ${e.message}", e)
        }
    }

    private fun buildUser(): AxiamUser {
        val access = session.cachedAccessToken()
            ?: throw AuthError("login succeeded but no access token was set")
        val claims = SessionState.decodeUnverifiedClaims(access)
        if (claims?.sub == null || claims.tenantId == null) {
            throw AuthError("failed to decode access token claims after login")
        }
        return AxiamUser(claims.sub, claims.tenantId, claims.roles)
    }

    private fun readJson(response: Response): JsonObject {
        val text = response.body?.string()
        if (text.isNullOrBlank()) return JsonObject(emptyMap())
        return try {
            Json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw NetworkError("failed to parse response body: ${e.message}", e)
        }
    }

    /** Fluent builder — the ONLY construction path. Obtain via [AxiamClient.builder]. */
    class Builder internal constructor(baseUrl: String, internal val tenantId: String) {
        internal val baseUrl: String = baseUrl
        internal var orgSlug: String? = null
        internal var orgId: UUID? = null
        internal var customCaPem: ByteArray? = null
        internal var clientCertPem: ByteArray? = null
        internal var clientKeyPem: Sensitive<ByteArray>? = null
        internal var overrideHttpClient: OkHttpClient? = null
        internal var connectTimeout: Duration = Duration.ofSeconds(10)
        internal var readTimeout: Duration = Duration.ofSeconds(30)
        internal var writeTimeout: Duration = Duration.ofSeconds(30)

        /** Organization slug (mutually exclusive with [orgId]; last call wins). */
        fun orgSlug(slug: String) = apply { orgSlug = slug; orgId = null }

        /** Organization UUID (mutually exclusive with [orgSlug]; last call wins). */
        fun orgId(id: UUID) = apply { orgId = id; orgSlug = null }

        /**
         * The ONLY TLS escape hatch (§6): add a PEM CA to the verification chain,
         * alongside (never instead of) the system trust store.
         */
        fun customCa(pem: ByteArray) = apply { customCaPem = pem }

        /**
         * Configure a client identity certificate for mutual TLS (§6.1). Both a
         * PEM cert chain and a PEM PKCS#8 private key are required; the key is
         * wrapped [Sensitive] and never logged or exposed.
         */
        fun clientCertificate(certPem: ByteArray, keyPem: ByteArray) = apply {
            clientCertPem = certPem
            clientKeyPem = Sensitive.of(keyPem)
        }

        /** Adopt a base OkHttpClient's non-TLS/jar config; the SDK re-applies its own. */
        fun httpClient(client: OkHttpClient) = apply { overrideHttpClient = client }

        fun connectTimeout(d: Duration) = apply { connectTimeout = d }
        fun readTimeout(d: Duration) = apply { readTimeout = d }
        fun writeTimeout(d: Duration) = apply { writeTimeout = d }

        fun build(): AxiamClient = AxiamClient(this)
    }

    companion object {
        private const val LOGIN_PATH = "/api/v1/auth/login"
        private const val MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify"
        private const val LOGOUT_PATH = "/api/v1/auth/logout"
        private const val CHECK_PATH = "/api/v1/authz/check"
        private const val BATCH_CHECK_PATH = "/api/v1/authz/check/batch"

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

        /**
         * The ONLY construction path (§5). Requires a base URL and a tenant
         * identifier (slug or UUID string) — AXIAM is multi-tenant with no
         * default tenant.
         *
         * @throws AuthError if [baseUrl] or [tenantId] is blank.
         */
        fun builder(baseUrl: String, tenantId: String?): Builder {
            if (baseUrl.isBlank()) {
                throw AuthError("baseUrl is required")
            }
            if (tenantId.isNullOrBlank()) {
                throw AuthError(
                    "tenantId is required — AXIAM is multi-tenant and there is no default tenant (§5)",
                )
            }
            return Builder(baseUrl, tenantId)
        }

        private fun kotlinx.serialization.json.JsonPrimitive.contentOrNull(): String? =
            if (this is kotlinx.serialization.json.JsonNull) null else content
    }
}
