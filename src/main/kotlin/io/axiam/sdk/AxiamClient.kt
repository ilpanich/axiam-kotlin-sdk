package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.AuthHeaderInterceptor
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.RefreshGuard
import io.axiam.sdk.internal.SessionState
import io.axiam.sdk.internal.TlsFactory
import io.axiam.sdk.oidc.AuthorizationRequest
import io.axiam.sdk.oidc.DeviceAuthorization
import io.axiam.sdk.oidc.RequestedPermission
import io.axiam.sdk.oidc.RequestingPartyToken
import io.axiam.sdk.oidc.ResourceSet
import io.axiam.sdk.oidc.UmaExchangeTicketParams
import io.axiam.sdk.oidc.DeviceAuthorizeParams
import io.axiam.sdk.oidc.DeviceLoginParams
import io.axiam.sdk.oidc.DevicePollParams
import io.axiam.sdk.oidc.ExchangedToken
import io.axiam.sdk.oidc.IntrospectParams
import io.axiam.sdk.oidc.LogoutUrlParams
import io.axiam.sdk.oidc.IntrospectionResult
import io.axiam.sdk.oidc.LoginClientCredentialsParams
import io.axiam.sdk.oidc.OidcBeginParams
import io.axiam.sdk.oidc.OidcConfiguration
import io.axiam.sdk.oidc.OidcExchangeParams
import io.axiam.sdk.oidc.OidcRefreshParams
import io.axiam.sdk.oidc.TokenExchangeParams
import io.axiam.sdk.oidc.VerifiedLogoutToken
import io.axiam.sdk.oidc.OidcSupport
import io.axiam.sdk.oidc.OidcTokenSet
import io.axiam.sdk.oidc.RevokeParams
import io.axiam.sdk.oidc.SsoCompleteParams
import io.axiam.sdk.oidc.SsoCompleteResult
import io.axiam.sdk.oidc.SsoStartParams
import io.axiam.sdk.oidc.SsoStartResult
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
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import io.axiam.sdk.internal.DecisionMemo
import io.axiam.sdk.internal.Retry
import io.axiam.sdk.internal.TelemetryDispatcher
import io.axiam.sdk.telemetry.TelemetryEvent
import io.axiam.sdk.telemetry.TelemetryHook
import java.io.IOException
import java.net.CookieManager
import java.net.CookiePolicy
import java.time.Duration
import java.util.UUID
import kotlin.time.toKotlinDuration

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

    /** CONTRACT.md §10.1 rule 5 — unset (the default) means "do not check". */
    private val expectedIssuer: String? = b.expectedIssuer

    /** CONTRACT.md §10.1 rule 6 — unset (the default) means "do not check". */
    private val expectedAudience: String? = b.expectedAudience

    private val customCaPem: ByteArray? = b.customCaPem
    private val httpClient: OkHttpClient
    private val refreshGuard = RefreshGuard()
    private val jwksVerifier = JwksVerifier(baseUrl)
    private val session: SessionState
    private val oidcSupport: OidcSupport

    /**
     * §16.1 disable switch. There is deliberately no field for the attempt cap,
     * base delay or delay cap: §16.1 forbids raising them, and eleven SDKs
     * agreeing on one table is the point.
     */
    private val retryEnabled: Boolean = b.retryEnabled

    /** §17 decision memo. Disabled unless the builder was given a TTL. */
    private val decisionMemo = DecisionMemo(b.decisionMemoTtl.toKotlinDuration())

    /** §19 telemetry dispatcher. Inert unless a hook was installed. */
    private val telemetry = TelemetryDispatcher(b.telemetryHook)

    /** §16 jitter source, injectable for tests. */
    private val jitter: () -> Double = b.jitterSource

    /** §18 shutdown flag, read on every operation. */
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

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

        // CONTRACT.md §12 — built on this SAME httpClient (§4 cookie jar, §6
        // TLS, §5 tenant header via AuthHeaderInterceptor already installed
        // above) and this SAME session (for org defaults / tenant_id
        // resolution), never a forked transport.
        oidcSupport = OidcSupport(
            httpClient = httpClient,
            baseUrl = baseUrl,
            configuredTenantId = tenantId,
            session = session,
            oidcClientId = b.oidcClientId,
            oidcClientSecret = b.oidcClientSecret,
            discoveryTtlMs = b.oidcDiscoveryTtlMs,
            clockSkewSecInput = b.oidcClockSkewSec,
        )

        // §19.2 rule 6: a setting we lowered is reported, not swallowed. The
        // memo TTL is the only clamped setting here — §16.1's table is not
        // configurable, only switchable — so it is the only emitter.
        decisionMemo.reportClamp(b.decisionMemoTtl.toKotlinDuration(), telemetry)
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

    /**
     * Visible-for-testing seam onto `oidcRefresh`'s §9 coalescer; see
     * [io.axiam.sdk.internal.SingleFlight.afterPublishHook]. Lets a CONTRACT.md
     * §9 rule 6a test pin the "outcome published, slot not yet vacated" window
     * open deterministically. **Never set in production** (always `null`).
     */
    internal var oidcRefreshAfterPublishHook: (() -> Unit)?
        get() = oidcSupport.afterRefreshPublishHook
        set(value) {
            oidcSupport.afterRefreshPublishHook = value
        }

    // ---- Auth methods (§1): login / verifyMfa / refresh / logout --------

    /**
     * `POST /api/v1/auth/login`. Returns a typed [LoginResult]; an MFA challenge
     * (HTTP 202) is an expected outcome, not an exception — check
     * [LoginResult.mfaRequired].
     */
    suspend fun login(email: String, password: String): LoginResult {
        ensureOpen()
        onCredentialChange()
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
        ensureOpen()
        onCredentialChange()
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
        ensureOpen()
        onCredentialChange()
        val observed = session.cachedAccessToken()
            ?: throw AuthError("no access token to refresh — call login() first")
        refreshGuard.refreshIfNeeded(observed) { session.doHttpRefresh() }
    }

    /** `POST /api/v1/auth/logout` (§1) and clears in-memory session state. */
    suspend fun logout() {
        ensureOpen()
        onCredentialChange()
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
    suspend fun checkAccess(action: String, resourceId: String, scope: String? = null): AccessResult =
        memoizedCheck(null, action, resourceId, scope)

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
    ): AccessResult = memoizedCheck(subjectId, action, resourceId, scope)

    /**
     * The shared body of both [checkAccess] overloads: §18 guard, §17 memo,
     * §16 retry, §19 telemetry.
     *
     * The call is a `POST` but changes no server state, so it is retry-eligible:
     * §16.2's test is "changes no server state", **not** "is a GET". Gating on
     * the verb would exclude the single most important operation this policy
     * covers.
     */
    private suspend fun memoizedCheck(
        subjectId: String?,
        action: String,
        resourceId: String,
        scope: String?,
    ): AccessResult {
        ensureOpen()

        // §17: consult the memo first. Disabled by default, in which case this
        // is one map lookup that always misses.
        val key = DecisionMemo.key(subjectId, resourceId, action, scope)
        decisionMemo.get(key)?.let { return it }

        val body = buildJsonObject {
            subjectId?.let { put("subject_id", it) }
            put("action", action)
            put("resource_id", resourceId)
            scope?.let { put("scope", it) }
        }

        val result = Retry.withRetry(
            operation = "checkAccess",
            enabled = retryEnabled,
            telemetry = telemetry,
            random = jitter,
        ) { attempt -> sendCheck(body, "checkAccess", attempt) }

        // Only a decision the server actually returned is memoized: reaching
        // here means success, so §17.1 rule 7's ban on caching a failure is
        // structural rather than a check that could be forgotten.
        decisionMemo.put(key, result)
        return result
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
                    reasonCode = obj["reason_code"]?.jsonPrimitive?.contentOrNull(),
                )
            } ?: emptyList()
        }
    }

    /**
     * The §10 guard entry point: verifies a bearer/cookie session token and
     * returns the [AxiamUser] to inject.
     *
     * Applies the CONTRACT.md §10.1 **minimum local-verification set** in
     * full — EdDSA signature against the org JWKS with `alg` pinned before
     * key lookup, REQUIRED `exp`, `nbf` when present, REQUIRED `tenant_id`
     * asserted against the configured tenant, and `iss`/`aud` when this
     * client was configured with an expected value (see
     * [Builder.expectedIssuer] / [Builder.expectedAudience]) — with a single
     * bounded [JwksVerifier.CLOCK_SKEW_SECONDS] leeway on the time claims.
     * Every failure, including a required claim that is simply absent,
     * surfaces as [AuthError].
     *
     * The signature-only primitive
     * ([JwksVerifier.verifySignatureOnlyUnchecked]) is NOT a substitute for
     * this method.
     */
    fun verifySession(token: String): AxiamUser {
        val claims = jwksVerifier.verifySignatureOnlyUnchecked(token)
        JwksVerifier.assertLocalClaims(
            claims = claims,
            configuredTenantId = tenantId,
            expectedIssuer = expectedIssuer,
            expectedAudience = expectedAudience,
        )
        val sub = claims.subject ?: throw AuthError("token has no subject (sub) claim")
        val scope = try {
            claims.getStringClaim("scope")
        } catch (_: Exception) {
            null
        }
        val roles = if (scope.isNullOrBlank()) emptyList() else scope.trim().split(Regex("\\s+"))
        return AxiamUser(sub, tenantId, roles)
    }

    // ---- OIDC / SSO relying-party helpers (CONTRACT.md §12) --------------
    //
    // The nine canonical §12 operations, under the exact §12.2 Kotlin names.
    // Networking/orchestration lives in [io.axiam.sdk.oidc.OidcSupport]
    // (file-size hygiene only) — every method below is a thin delegation, so
    // these ARE "operations on the existing client" per §12's requirement.
    //
    // `oidcBegin` is deliberately NOT `suspend`: CONTRACT.md §12.1 fixes it as
    // pure local computation with no network I/O, and §12.2's C# carve-out
    // ("the single deliberate exception... performs no network I/O... no
    // Async suffix") makes the same call for a TAP-style language. The
    // TypeScript reference makes the identical choice. A `suspend` wrapper
    // that never suspends would be a needless coroutine-context hop for
    // every caller.

    /**
     * `GET /.well-known/openid-configuration` (§12.1) — fetch and cache the
     * OIDC discovery document (≥5-minute TTL, single-flight de-duplication,
     * per-origin cache key; §12.3 rule 6).
     */
    suspend fun oidcDiscover(): OidcConfiguration = oidcSupport.oidcDiscover()

    /**
     * Builds an [AuthorizationRequest] (§12.1) — PURE LOCAL COMPUTATION, no
     * network I/O. See [OidcBeginParams] for the CSPRNG/PKCE construction
     * rules. The caller owns [AuthorizationRequest.state],
     * [AuthorizationRequest.nonce], and [AuthorizationRequest.codeVerifier]
     * (§12.3 rule 1) — this SDK stores none of them.
     */
    fun oidcBegin(params: OidcBeginParams): AuthorizationRequest = oidcSupport.oidcBegin(params)

    /**
     * `POST /oauth2/token` with `grant_type=authorization_code` (§12.1) —
     * exchange an authorization code for a validated [OidcTokenSet]. See the
     * CONTRACT.md §12.4 ID-token validation checklist: on any failure the
     * whole token set is discarded and [io.axiam.sdk.errors.AuthError] is
     * raised with the matching `reason`.
     */
    suspend fun oidcExchange(params: OidcExchangeParams): OidcTokenSet = oidcSupport.oidcExchange(params)

    /**
     * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1), under its
     * own single-flight guard (§9). Distinct from [refresh] — the two are
     * never merged or aliased.
     */
    suspend fun oidcRefresh(params: OidcRefreshParams): OidcTokenSet = oidcSupport.oidcRefresh(params)

    /**
     * `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) —
     * service-account machine-to-machine login.
     */
    suspend fun loginClientCredentials(params: LoginClientCredentialsParams = LoginClientCredentialsParams()): OidcTokenSet =
        oidcSupport.loginClientCredentials(params)

    /** `POST /oauth2/introspect` (RFC 7662, §12.1). Requires confidential-client credentials. */
    suspend fun introspect(params: IntrospectParams): IntrospectionResult = oidcSupport.introspect(params)

    /** `POST /oauth2/revoke` (RFC 7009, §12.1). Idempotent: any `200` (including for an unknown token) is success. */
    suspend fun revoke(params: RevokeParams) = oidcSupport.revoke(params)

    /**
     * `POST /oauth2/device_authorization` (§14.1) — start the device grant.
     *
     * **Unauthenticated by design**: a device that cannot show a browser also
     * cannot hold a client secret, so this never sends `client_secret` and
     * never refuses a client built without one.
     */
    suspend fun deviceAuthorize(params: DeviceAuthorizeParams = DeviceAuthorizeParams()): DeviceAuthorization =
        oidcSupport.deviceAuthorize(params)

    /**
     * `POST /oauth2/token` with the device-code grant (§14.1) — **one** poll
     * attempt, for an application driving its own loop. Most callers want
     * [deviceLogin].
     */
    suspend fun devicePoll(params: DevicePollParams): OidcTokenSet = oidcSupport.devicePoll(params)

    /**
     * The composed §14.3 helper: start the grant, hand the caller the user
     * code (before the first poll), poll to completion.
     *
     * Returns the token set; this SDK does not adopt it, matching its
     * [loginClientCredentials] posture (§14.3 rule 4, contract 1.7).
     */
    suspend fun deviceLogin(params: DeviceLoginParams): OidcTokenSet = oidcSupport.deviceLogin(params)

    /**
     * `POST /oauth2/token` with the RFC 8693 grant (§15.1) — exchange a token
     * for a **narrower** one.
     *
     * Requires confidential-client credentials. Never defaults `actorToken`,
     * never auto-narrows after `invalid_scope`, never adopts the result.
     */
    suspend fun tokenExchange(params: TokenExchangeParams): ExchangedToken =
        oidcSupport.tokenExchange(params)

    // -- §20 UMA 2.0 — Protection API and ticket grant ----------------------

    /**
     * `POST /uma2/rreg/resource_set` — register a resource set (§20.1).
     *
     * The [pat] is an explicit parameter, not this client's session: a
     * Protection API Token must be a **client-credentials** token, because a
     * ticket binds to the `client_id` that minted it (§20.2 rule 1).
     */
    suspend fun umaRegisterResource(pat: Sensitive<String>, resource: ResourceSet): ResourceSet =
        oidcSupport.umaRegisterResource(pat, resource)

    /** `GET /uma2/rreg/resource_set/{id}` — read a resource set (§20.1). */
    suspend fun umaReadResource(pat: Sensitive<String>, resourceId: String): ResourceSet =
        oidcSupport.umaReadResource(pat, resourceId)

    /**
     * `PUT /uma2/rreg/resource_set/{id}` — replace a resource set (§20.1).
     *
     * **The scope list is replaced, not merged** (§20.2 rule 8); this performs
     * no read-before-write.
     */
    suspend fun umaUpdateResource(
        pat: Sensitive<String>,
        resourceId: String,
        resource: ResourceSet,
    ): ResourceSet = oidcSupport.umaUpdateResource(pat, resourceId, resource)

    /** `DELETE /uma2/rreg/resource_set/{id}` — deregister (§20.1). */
    suspend fun umaDeleteResource(pat: Sensitive<String>, resourceId: String): Unit =
        oidcSupport.umaDeleteResource(pat, resourceId)

    /**
     * `GET /uma2/rreg/resource_set` — list the ids **this client** registered
     * (§20.1). Not the tenant's whole resource tree.
     */
    suspend fun umaListResources(pat: Sensitive<String>): List<String> =
        oidcSupport.umaListResources(pat)

    /** `POST /uma2/perm` — mint a permission ticket (§20.1). */
    suspend fun umaRequestTicket(
        pat: Sensitive<String>,
        permissions: List<RequestedPermission>,
    ): Sensitive<String> = oidcSupport.umaRequestTicket(pat, permissions)

    /**
     * `POST /oauth2/token` with the uma-ticket grant (§20.1).
     *
     * **Never retries** (§20.2 rule 6): the ticket is consumed before the
     * request is evaluated, so a failed exchange has already spent it — and
     * under concurrency a retry is the concurrent redemption a server whose
     * storage engine this SDK cannot attest may admit twice
     * (ilpanich/axiam#302). Request a new ticket instead.
     */
    suspend fun umaExchangeTicket(params: UmaExchangeTicketParams): RequestingPartyToken =
        oidcSupport.umaExchangeTicket(params)

    /**
     * Build the RP-initiated logout URL to redirect the user agent to
     * (§12.7.2). Does **not** clear this client's own session.
     */
    suspend fun logoutUrl(params: LogoutUrlParams): String = oidcSupport.logoutUrl(params)

    /**
     * Verify a back-channel logout token the OP pushed to this application's
     * `backchannel_logout_uri` (§12.7.3).
     *
     * Returns the `sid`/`sub`/`jti` the token names — never a bare `Boolean`,
     * because the RP has to know *which* session to end. **Dedup on `jti`
     * yourself**: delivery is at-least-once.
     */
    suspend fun verifyLogoutToken(
        logoutToken: String,
        configuration: OidcConfiguration? = null,
    ): VerifiedLogoutToken = oidcSupport.verifyLogoutToken(logoutToken, configuration)

    /** `POST /api/v1/auth/federation/oidc/start` (§12.1) — step 1 of upstream-IdP SSO. */
    suspend fun ssoStart(params: SsoStartParams): SsoStartResult = oidcSupport.ssoStart(params)

    /**
     * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — step 2 of
     * upstream-IdP SSO. The session arrives as `Set-Cookie`; this client's §4
     * cookie jar captures it automatically.
     */
    suspend fun ssoComplete(params: SsoCompleteParams): SsoCompleteResult = oidcSupport.ssoComplete(params)

    /**
     * Releases this client's local resources (CONTRACT.md §18).
     *
     * Idempotent — `compareAndSet` means even a concurrent double-close does
     * the work once rather than racing the executor shutdown. Cleanup runs from
     * error paths, and an error path that itself throws hides the original
     * failure.
     *
     * **This does not log out.** §18.1 rule 5: shutting down a client releases
     * *local* resources and never reaches the network. The server-side session
     * deliberately outlives the client object, which is what lets a process
     * restart and resume; a `close()` that logged out would silently end every
     * user's session on each deploy. Call [logout] first if ending the session
     * is what you want.
     *
     * After this returns, every operation on this client throws [NetworkError]
     * rather than silently reconnecting.
     */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        decisionMemo.clear()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
        httpClient.cache?.close()
    }

    /**
     * Throws if [close] has been called (§18.1 rule 4).
     *
     * Use-after-close is an error, not a silent reconnect: a client that
     * quietly rebuilt its transport would make [close] meaningless and hide the
     * lifecycle bug that caused the call.
     */
    private fun ensureOpen() {
        if (closed.get()) {
            throw NetworkError("client is closed: this AxiamClient was shut down with close()")
        }
    }

    /**
     * Drops memoized decisions (§17.1 rule 9).
     *
     * Entries are keyed by subject rather than session, so a re-authentication
     * as a *different* principal would otherwise inherit the previous one's
     * decisions.
     */
    private fun onCredentialChange() {
        decisionMemo.clear()
    }

    // ---- shared HTTP mechanics ------------------------------------------

    private suspend fun sendCheck(body: JsonObject, operation: String, attempt: Int): AccessResult {
        val span = telemetry.startRequest(operation, "POST", CHECK_PATH, attempt)
        val response = try {
            postWithRefresh(CHECK_PATH, body)
        } catch (e: Throwable) {
            span.end(null, TelemetryEvent.Outcome.FAILURE)
            throw e
        }
        response.use {
            if (!it.isSuccessful) {
                span.end(it.code, TelemetryEvent.Outcome.FAILURE)
                throw ErrorMapper.fromHttpStatus(it.code, "checkAccess failed", it)
            }
            span.end(it.code, TelemetryEvent.Outcome.SUCCESS)
            val wire = readJson(it)
            return AccessResult(
                allowed = wire["allowed"]?.jsonPrimitive?.boolean ?: false,
                reason = wire["reason"]?.jsonPrimitive?.contentOrNull(),
                // §11 rule 9: surfaced verbatim, including a code this SDK has
                // never heard of — the outcome is carried by `allowed` alone,
                // so an unknown code can never change it.
                reasonCode = wire["reason_code"]?.jsonPrimitive?.contentOrNull(),
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
        internal var retryEnabled: Boolean = true
        internal var decisionMemoTtl: Duration = Duration.ZERO
        internal var telemetryHook: TelemetryHook? = null
        internal var jitterSource: () -> Double = { kotlin.random.Random.Default.nextDouble() }
        internal var orgSlug: String? = null
        internal var orgId: UUID? = null
        internal var customCaPem: ByteArray? = null
        internal var clientCertPem: ByteArray? = null
        internal var clientKeyPem: Sensitive<ByteArray>? = null
        internal var overrideHttpClient: OkHttpClient? = null
        internal var connectTimeout: Duration = Duration.ofSeconds(10)
        internal var readTimeout: Duration = Duration.ofSeconds(30)
        internal var writeTimeout: Duration = Duration.ofSeconds(30)
        internal var oidcClientId: String? = null
        internal var oidcClientSecret: Sensitive<String>? = null
        internal var oidcDiscoveryTtlMs: Long = OidcSupport.MIN_DISCOVERY_TTL_MS
        internal var oidcClockSkewSec: Int? = null
        internal var expectedIssuer: String? = null
        internal var expectedAudience: String? = null

        /**
         * CONTRACT.md §10.1 rule 5 — the `iss` the §10 guard
         * ([AxiamClient.verifySession]) requires an inbound access token to
         * carry. OPTIONAL and unset by default: leaving it unset means the
         * issuer is not checked. When set, a token whose `iss` is absent or
         * different is rejected.
         */
        fun expectedIssuer(issuer: String) = apply { expectedIssuer = issuer }

        /**
         * CONTRACT.md §10.1 rule 6 — an audience the §10 guard
         * ([AxiamClient.verifySession]) requires an inbound access token's
         * `aud` to contain. OPTIONAL and unset by default: leaving it unset
         * means the audience is not checked. A resource server guarding a
         * user-facing API SHOULD set `axiam:user`.
         */
        fun expectedAudience(audience: String) = apply { expectedAudience = audience }

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

        /**
         * The relying party's OAuth2 `client_id` (CONTRACT.md §12.1), required
         * before calling any §12 operation other than [oidcDiscover]. Matched
         * against the ID token's `aud`/`azp` (§12.4 rule 4) — it comes from
         * client configuration, never a per-call argument, since §12.4 rule 4
         * needs the SAME value the caller used to build the authorization
         * request.
         */
        fun oidcClientId(clientId: String) = apply { oidcClientId = clientId }

        /**
         * A confidential client's `client_secret` (CONTRACT.md §12.1), held
         * behind [Sensitive] (§12.5). Omit for a public client:
         * [loginClientCredentials], [introspect], and [revoke] then throw
         * [io.axiam.sdk.errors.AuthError] client-side, without a wire call
         * (§12.1 note 4 — a public client cannot call them).
         */
        fun oidcClientSecret(clientSecret: String) = apply { oidcClientSecret = Sensitive.of(clientSecret) }

        /**
         * Overrides the OIDC discovery-document cache TTL, in milliseconds.
         * Floored at [OidcSupport.MIN_DISCOVERY_TTL_MS] (5 minutes) per
         * CONTRACT.md §12.3 rule 6 — a smaller configured value is silently
         * raised to the floor.
         */
        fun oidcDiscoveryTtlMillis(ttlMs: Long) = apply { oidcDiscoveryTtlMs = ttlMs }

        /**
         * Overrides the permitted ID-token clock skew, in seconds. Clamped to
         * `[0, 60]` per CONTRACT.md §12.4 rule 5 — the contract forbids
         * configuring it above that bound.
         */
        fun oidcClockSkewSeconds(seconds: Int) = apply { oidcClockSkewSec = seconds }

        /**
         * Disables the CONTRACT.md §16 bounded read-only retry policy, making
         * every operation exactly one attempt.
         *
         * That is the right choice for a caller who owns their own retry layer
         * — they know their deadline and this SDK does not — but it is not a
         * way to make failures quieter: a transient [NetworkError] simply
         * surfaces immediately.
         *
         * §16.1 permits this switch but forbids raising the attempt cap, base
         * delay or delay cap above the contract's values, so there is no
         * builder method for those.
         */
        fun retryDisabled(): Builder = apply { retryEnabled = false }

        /**
         * Enables the CONTRACT.md §17 client-side decision memo.
         *
         * **Disabled by default** — §11.2 rule 6's ban on caching authorization
         * decisions is still the default behaviour, and this is the single
         * opt-in exception.
         *
         * **What you are accepting:** the staleness bound is [ttl] in *both*
         * directions. A grant revoked on the server can still read as allowed
         * for up to the TTL, and a grant just added can still read as denied
         * for up to the TTL.
         *
         * **Reads-your-own-writes is not guaranteed.** An admin UI that grants
         * a role and immediately re-checks is the case that breaks, and it
         * breaks silently. If that is your workload, do not set this.
         *
         * [ttl] is clamped to 5 seconds rather than rejected. Allows and denies
         * are memoized identically (asymmetric caching leaks the outcome
         * through latency), failures are never memoized, and the memo is
         * cleared on any credential change.
         */
        fun decisionMemoTtl(ttl: Duration): Builder = apply { decisionMemoTtl = ttl }

        /**
         * Installs a CONTRACT.md §19 telemetry sink.
         *
         * It receives request start/end, §16 retry and §9 refresh events, so
         * metrics can be wired without this module depending on any metrics
         * library.
         *
         * A hook that throws cannot fail the operation that fired it (§19.2
         * rule 2), and no event payload can carry a token — `TelemetryEvent` is
         * a sealed hierarchy with fixed property lists (§19.2 rule 3). It is
         * invoked on the calling coroutine, so it must not block.
         */
        fun telemetryHook(hook: TelemetryHook): Builder = apply { telemetryHook = hook }

        /** Injects the §16 jitter draw. Test seam — not part of the public contract. */
        internal fun jitterSource(source: () -> Double): Builder = apply { jitterSource = source }

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
         * @throws AuthError if [baseUrl] or [tenantId] is blank, or if
         *   [baseUrl] does not use `https://` (SEC-073; see [ensureSecureBaseUrl]).
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
            ensureSecureBaseUrl(baseUrl)
            return Builder(baseUrl, tenantId)
        }

        /**
         * SEC-073 / CONTRACT.md §6: reject a plaintext (non-`https`) [baseUrl]
         * at construction, so a misconfigured `http://` endpoint can never
         * silently carry login credentials, the bearer session cookie, the
         * CSRF token, or the tenant header in cleartext.
         *
         * The sole exception is a loopback host (`localhost`, `127.0.0.1`,
         * `::1`) so local development against a non-TLS dev server still
         * works — the same carve-out the Rust SDK's `ensure_secure_scheme`
         * uses (there is no flag to disable the check for a routable host).
         *
         * @throws AuthError if [baseUrl] does not parse as an `http(s)` URL,
         *   or parses with a non-`https` scheme against a non-loopback host.
         */
        private fun ensureSecureBaseUrl(baseUrl: String) {
            val parsed = baseUrl.toHttpUrlOrNull()
                ?: throw AuthError("baseUrl is not a valid http(s) URL: $baseUrl")
            if (parsed.scheme.equals("https", ignoreCase = true)) return
            if (isLoopbackHost(parsed.host)) return
            throw AuthError(
                "baseUrl must use the encrypted \"https://\" scheme (got \"${parsed.scheme}://\"); " +
                    "plaintext transport is refused because it would expose tenant identifiers, CSRF " +
                    "tokens, and session cookies — the only exception is a loopback host " +
                    "(localhost/127.0.0.1/::1) for local development (SEC-073, CONTRACT.md §6).",
            )
        }

        /** The sole plaintext exception (SEC-073): loopback / localhost literals only — never DNS-resolved. */
        private fun isLoopbackHost(host: String): Boolean =
            host.equals("localhost", ignoreCase = true) || host == "127.0.0.1" || host == "::1"

        private fun kotlinx.serialization.json.JsonPrimitive.contentOrNull(): String? =
            if (this is kotlinx.serialization.json.JsonNull) null else content
    }
}
