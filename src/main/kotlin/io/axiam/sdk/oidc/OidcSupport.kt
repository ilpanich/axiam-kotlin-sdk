package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AxiamException
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.SessionState
import io.axiam.sdk.internal.SingleFlight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

/**
 * The networking/orchestration engine behind [io.axiam.sdk.AxiamClient]'s nine
 * §12 operations (CONTRACT.md §12) — one instance per `AxiamClient`, holding
 * the discovery cache, the per-`jwks_uri` verifier cache, and `oidcRefresh`'s
 * own single-flight guard.
 *
 * Split out of `AxiamClient` purely for file-size hygiene: every method here
 * is reached ONLY through the corresponding `suspend fun` on `AxiamClient`,
 * which is the "operations on the existing client" shape CONTRACT.md §12
 * asks for. Everything besides PKCE ([OidcPkce]) and ID-token validation
 * ([OidcIdToken]) is reuse, not reimplementation (§12 forbids forking):
 *
 *  - transport + §4 cookie jar + §5 tenant header + §6 TLS -> the SAME shared
 *    [httpClient] `AxiamClient` already built (its `AuthHeaderInterceptor`
 *    decorates every request to the client's own host, and its cookie jar
 *    captures `ssoComplete`'s `Set-Cookie` automatically — no separate wiring
 *    needed);
 *  - §2 error mapping -> [ErrorMapper], extended with the endpoint-qualified
 *    §12.3 rule 3 `OAuth2ErrorResponse` -> [OAuthProtocolError] mapping;
 *  - §12.4 signature verification -> [JwksVerifier.verifyForIdToken], the SAME
 *    verifier the §10 middleware uses;
 *  - §7/§12.5 redaction -> the existing [Sensitive] wrapper.
 *
 * `oidcRefresh` uses its OWN single-flight guard ([refreshFlight]), a SEPARATE
 * [SingleFlight] instance from [io.axiam.sdk.internal.RefreshGuard] — that
 * type's `refreshIfNeeded` API compares an "observed" `axiam_access` cookie
 * value against a cached [io.axiam.sdk.internal.TokenPair], which has no
 * meaning for an OAuth2 `refresh_token` grant operating on an entirely
 * different, cookie-independent token namespace (documented deviation from the
 * TypeScript reference, matching the Go port's reasoning). §9 rule 5 permits
 * exactly that — a dedicated INSTANCE of an equally strong mechanism — and
 * because both guards are instances of the one [SingleFlight] implementation,
 * both satisfy §9 rules 1-3 and rule 6's four invariants identically: one
 * in-flight refresh per burst, every caller gets that one outcome, no retry on
 * failure.
 */
internal class OidcSupport(
    private val httpClient: OkHttpClient,
    private val baseUrl: String,
    private val configuredTenantId: String,
    private val session: SessionState,
    private val oidcClientId: String?,
    private val oidcClientSecret: Sensitive<String>?,
    discoveryTtlMs: Long,
    clockSkewSecInput: Int?,
) {
    private val discoveryTtlMs: Long = discoveryTtlMs.coerceAtLeast(MIN_DISCOVERY_TTL_MS)
    private val clockSkewSec: Int = OidcIdToken.resolveClockSkewSec(clockSkewSecInput)

    // -- 1. oidcDiscover: per-client discovery cache, single-flight fetch ---

    private val discoveryFlight = SingleFlight<OidcConfiguration>()

    @Volatile
    private var cachedDoc: OidcConfiguration? = null

    @Volatile
    private var cachedExpiresAtMs: Long = 0L

    /**
     * `GET /.well-known/openid-configuration` (§12.1) — fetch and cache the
     * OIDC discovery document, with a >=5-minute TTL and single-flight
     * de-duplication of concurrent callers (§12.3 rule 6).
     *
     * Because an `AxiamClient` is bound to exactly ONE base URL for its whole
     * lifetime, this cache needs no origin-keyed map the way a multi-origin
     * SDK would: every call for a given client always targets the same
     * origin, so a single cached document already satisfies §12.3 rule 6's
     * "keyed by origin, never process-global, never shared across tenants"
     * requirement (each `AxiamClient` owns its own `OidcSupport`).
     *
     * De-duplication uses the same [SingleFlight] coalescer — and therefore the
     * same §9 rule 6 invariants — as the two refresh guards; only the cached
     * DOCUMENT (never the settled in-flight slot) outlives an attempt.
     */
    suspend fun oidcDiscover(): OidcConfiguration = discoveryFlight.run(
        fastPath = { cachedDoc?.takeIf { System.currentTimeMillis() < cachedExpiresAtMs } },
        beforePublish = { doc ->
            cachedDoc = doc
            cachedExpiresAtMs = System.currentTimeMillis() + this.discoveryTtlMs
        },
        block = { fetchDiscoveryDocument() },
    )

    private suspend fun fetchDiscoveryDocument(): OidcConfiguration {
        val request = Request.Builder().url(baseUrl + DISCOVERY_PATH).get().build()
        val response = executeRequest(request)
        response.use {
            if (it.code != 200) throw ErrorMapper.fromHttpStatus(it.code, "oidc discovery request failed", it)
            return parseDiscoveryDocument(parseJsonObject(it))
        }
    }

    private fun parseDiscoveryDocument(json: JsonObject): OidcConfiguration = OidcConfiguration(
        issuer = json.str("issuer"),
        authorization_endpoint = json.str("authorization_endpoint"),
        token_endpoint = json.str("token_endpoint"),
        userinfo_endpoint = json.str("userinfo_endpoint"),
        jwks_uri = json.str("jwks_uri"),
        revocation_endpoint = json.str("revocation_endpoint"),
        introspection_endpoint = json.str("introspection_endpoint"),
        response_types_supported = json.strList("response_types_supported"),
        subject_types_supported = json.strList("subject_types_supported"),
        id_token_signing_alg_values_supported = json.strList("id_token_signing_alg_values_supported"),
        scopes_supported = json.strList("scopes_supported"),
        token_endpoint_auth_methods_supported = json.strList("token_endpoint_auth_methods_supported"),
        claims_supported = json.strList("claims_supported"),
        grant_types_supported = json.strList("grant_types_supported"),
        device_authorization_endpoint = json.strOrNull("device_authorization_endpoint"),
        end_session_endpoint = json.strOrNull("end_session_endpoint"),
        backchannel_logout_supported = json.boolOrFalse("backchannel_logout_supported"),
        backchannel_logout_session_supported = json.boolOrFalse("backchannel_logout_session_supported"),
    )

    // -- 2. oidcBegin: pure local computation, no network I/O ---------------

    /**
     * Builds an [AuthorizationRequest] (§12.1) — PURE LOCAL COMPUTATION, no
     * network I/O, hence not `suspend` on [io.axiam.sdk.AxiamClient].
     *
     * Generates a 32-byte CSPRNG `state`/`nonce` (base64url, unpadded) and a
     * fresh PKCE verifier/challenge pair using S256 ONLY. The URL is built
     * from [OidcBeginParams.configuration]'s `authorization_endpoint` with
     * exactly the eight parameters §12.1 rule 5 mandates, plus any
     * `extraParams` the caller adds.
     *
     * Nothing is stored: persist the returned `state`/`nonce`/`codeVerifier`
     * yourself (§12.3 rule 1).
     *
     * @throws IllegalArgumentException a PROGRAMMING error (deliberately NOT
     *   the auth-error taxonomy, CONTRACT.md §12 port addendum item 9) when
     *   `extraParams` tries to override one of the eight SDK-owned parameters.
     * @throws AuthError client-side, no wire call, when no `oidcClientId` was
     *   configured at `AxiamClient` construction time.
     */
    fun oidcBegin(params: OidcBeginParams): AuthorizationRequest {
        val clientId = requireClientId()
        val state = OidcPkce.randomUrlSafeToken()
        val nonce = OidcPkce.randomUrlSafeToken()
        val codeVerifier = OidcPkce.generateCodeVerifier()
        val codeChallenge = OidcPkce.computeCodeChallenge(codeVerifier.expose())

        val query = LinkedHashMap<String, String>()
        for ((key, value) in params.extraParams) {
            require(key !in RESERVED_AUTHORIZE_PARAMS) {
                "oidcBegin: extraParams may not override the SDK-owned authorization parameter " +
                    "\"$key\" (CONTRACT.md §12.1 rule 5)."
            }
            query[key] = value
        }
        query["response_type"] = "code"
        query["client_id"] = clientId
        query["redirect_uri"] = params.redirectUri
        query["scope"] = normalizeScope(params.scope)
        query["state"] = state
        query["nonce"] = nonce
        query["code_challenge"] = codeChallenge
        query["code_challenge_method"] = OidcPkce.CODE_CHALLENGE_METHOD_S256

        val url = appendQuery(params.configuration.authorization_endpoint, query)
        return AuthorizationRequest(url = url, state = state, nonce = nonce, codeVerifier = codeVerifier)
    }

    // -- 3. oidcExchange ------------------------------------------------------

    /**
     * `POST /oauth2/token` with `grant_type=authorization_code` (§12.1) —
     * exchange an authorization code for a token set, validating the returned
     * ID token in full before returning. [OidcExchangeParams.nonce] is
     * mandatory: this grant always requests the `openid` scope, so §12.4
     * rule 6 always applies.
     */
    suspend fun oidcExchange(params: OidcExchangeParams): OidcTokenSet {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val form = buildForm(
            "grant_type" to "authorization_code",
            "code" to params.code,
            "code_verifier" to params.codeVerifier.expose(),
            "redirect_uri" to params.redirectUri,
            "client_id" to clientId,
            "client_secret" to oidcClientSecret?.expose(),
        )
        val json = postToken(configuration, form, params.tenantId)
        val expectations = OidcIdToken.Expectations(
            issuer = configuration.issuer,
            clientId = clientId,
            nonce = params.nonce,
            hasNonce = true,
            clockSkewSec = clockSkewSec,
        )
        return toTokenSet(json, configuration, expectations)
    }

    // -- 4. oidcRefresh -------------------------------------------------------

    private val refreshFlight = SingleFlight<OidcTokenSet>()

    /**
     * Visible-for-testing seam; see [SingleFlight.afterPublishHook]. Never set
     * in production.
     */
    internal var afterRefreshPublishHook: (() -> Unit)?
        get() = refreshFlight.afterPublishHook
        set(value) {
            refreshFlight.afterPublishHook = value
        }

    /**
     * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1) — refresh
     * an [OidcTokenSet] under [refreshFlight]'s single-flight guard (§9):
     * concurrent callers collapse into ONE HTTP request and all receive the
     * same result (or the same failure), with no retry loop on failure
     * (§9 rule 3). See [SingleFlight] for how §9 rule 6's four invariants are
     * met — in particular why cancelling one caller can never strand the rest
     * of the burst, which matters most here: `/oauth2/token` consumes a
     * single-use, rotating `refresh_token`, so a discarded outcome is an
     * unrecoverable session and a second wire call is an `invalid_grant`.
     *
     * A DISTINCT operation from `AxiamClient.refresh()`, which drives the
     * cookie/opaque-token session path at `POST /api/v1/auth/refresh` — the
     * two are never merged, aliased, or made to fall back to one another, and
     * (§9 rule 5) each owns its own guard instance because the two run on
     * different token namespaces.
     *
     * An `id_token` in the response is validated against §12.4 rules 1-5
     * and 7; rule 6 (nonce) is skipped, since OIDC Core §12.2 does not
     * require a nonce in a refresh-issued ID token.
     */
    suspend fun oidcRefresh(params: OidcRefreshParams): OidcTokenSet =
        refreshFlight.run { doOidcRefresh(params) }

    private suspend fun doOidcRefresh(params: OidcRefreshParams): OidcTokenSet {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val form = buildForm(
            "grant_type" to "refresh_token",
            "refresh_token" to params.refreshToken.expose(),
            "client_id" to clientId,
            "client_secret" to oidcClientSecret?.expose(),
            "scope" to params.scope,
        )
        val json = postToken(configuration, form, params.tenantId)
        // No nonce: rule 6 does not apply to a refresh-issued ID token.
        val expectations = OidcIdToken.Expectations(
            issuer = configuration.issuer,
            clientId = clientId,
            nonce = null,
            hasNonce = false,
            clockSkewSec = clockSkewSec,
        )
        return toTokenSet(json, configuration, expectations)
    }

    // -- 5. loginClientCredentials --------------------------------------------

    /**
     * `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) —
     * service-account machine-to-machine login. Requests no `openid` scope,
     * so the response carries no `id_token`.
     *
     * Note: this SDK does NOT implement the §12.1 "adopt the returned
     * `access_token` as this client's own bearer credential" allowance — it
     * is an explicit contract MAY, and this port skips it (matching the
     * Python reference port; CONTRACT.md §12 port addendum item 13).
     *
     * @throws AuthError client-side, no wire call, when no `oidcClientSecret`
     *   was configured — this grant cannot be performed by a public client.
     */
    suspend fun loginClientCredentials(params: LoginClientCredentialsParams): OidcTokenSet {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val secret = requireClientSecret("loginClientCredentials")
        val form = buildForm(
            "grant_type" to "client_credentials",
            "client_id" to clientId,
            "client_secret" to secret,
            "scope" to params.scope,
        )
        val json = postToken(configuration, form, params.tenantId)
        // No nonce: rule 6 does not apply to this grant.
        val expectations = OidcIdToken.Expectations(
            issuer = configuration.issuer,
            clientId = clientId,
            nonce = null,
            hasNonce = false,
            clockSkewSec = clockSkewSec,
        )
        return toTokenSet(json, configuration, expectations)
    }

    // -- 6. introspect ---------------------------------------------------------

    /**
     * `POST /oauth2/introspect` (RFC 7662, §12.1) — ask the server whether a
     * token is active and, if so, for its metadata. Requires
     * confidential-client credentials (§12.1 note 4). A `401` here is a
     * CLIENT-CREDENTIAL failure surfaced as [OAuthProtocolError]; it never
     * touches [refreshFlight] or [io.axiam.sdk.internal.RefreshGuard] —
     * refreshing a session cannot fix a bad `client_secret` (§12.3 rule 3).
     */
    suspend fun introspect(params: IntrospectParams): IntrospectionResult {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val secret = requireClientSecret("introspect")
        val form = buildForm(
            "token" to params.token.expose(),
            "client_id" to clientId,
            "client_secret" to secret,
            "token_type_hint" to params.tokenTypeHint,
        )
        val url = endpointUrl(configuration.introspection_endpoint, params.tenantId)
        val json = postOAuth2Form(url, form, "introspect request failed")
        return IntrospectionResult(
            active = json["active"]?.jsonPrimitive?.boolean ?: false,
            sub = json.strOrNull("sub"),
            clientId = json.strOrNull("client_id"),
            scope = json.strOrNull("scope"),
            tokenType = json.strOrNull("token_type"),
            exp = json.longOrNull("exp"),
            iat = json.longOrNull("iat"),
        )
    }

    // -- 7. revoke ---------------------------------------------------------------

    /**
     * `POST /oauth2/revoke` (RFC 7009, §12.1) — revoke an access or refresh
     * token. Per RFC 7009 the server answers `200` for unknown, expired, and
     * already-revoked tokens alike, so revocation is IDEMPOTENT: any `200` is
     * success and no error is raised for a token the server has never seen.
     * Only a `401` (client authentication failed) is mapped to
     * [OAuthProtocolError]; a `5xx` stays a [NetworkError] — returning `Unit`
     * does not make a server error "success" (CONTRACT.md §12 port addendum
     * item 20).
     */
    suspend fun revoke(params: RevokeParams) {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val secret = requireClientSecret("revoke")
        val form = buildForm(
            "token" to params.token.expose(),
            "client_id" to clientId,
            "client_secret" to secret,
            "token_type_hint" to params.tokenTypeHint,
        )
        val url = endpointUrl(configuration.revocation_endpoint, params.tenantId)
        val request = Request.Builder().url(url).post(form).build()
        val response = executeRequest(request)
        response.use {
            if (!it.isSuccessful) throw mapOAuth2ErrorResponse(it, "revoke request failed")
        }
    }

    // -- 8. ssoStart ---------------------------------------------------------------

    /**
     * `POST /api/v1/auth/federation/oidc/start` (§12.1) — step 1 of
     * first-time SSO against an UPSTREAM IdP. No JWT required.
     *
     * One tenant form ([SsoStartParams.tenantId] / [SsoStartParams.tenantSlug])
     * and one org form ([SsoStartParams.orgId] / [SsoStartParams.orgSlug])
     * must be resolvable, from the arguments or from the client's own
     * construction context (§5.1). Redirect the browser to the returned
     * `authorizeUrl` and round-trip `state` back into [ssoComplete] unmodified
     * — the server keeps the nonce to itself (§12.1 note 7).
     *
     * @throws AuthError client-side, no wire call, when organization context
     *   cannot be resolved. (Tenant context, by contrast, is always
     *   resolvable: [io.axiam.sdk.AxiamClient]'s builder requires a non-blank
     *   tenant identifier — CONTRACT.md §5 — which is either a UUID or a
     *   slug, so one of [SsoStartParams.tenantId] / [SsoStartParams.tenantSlug]
     *   always resolves.)
     */
    suspend fun ssoStart(params: SsoStartParams): SsoStartResult {
        val tenantIsUuid = UUID_RE.matches(configuredTenantId)
        val tenantId = params.tenantId ?: configuredTenantId.takeIf { tenantIsUuid }
        val tenantSlug = params.tenantSlug ?: configuredTenantId.takeUnless { tenantIsUuid }
        val orgId = params.orgId ?: session.configuredOrgId()?.toString()
        val orgSlug = params.orgSlug ?: session.configuredOrgSlug()

        if (orgId == null && orgSlug == null) {
            throw AuthError(
                "ssoStart requires organization context: pass orgId or orgSlug, or construct the " +
                    "client with one (CONTRACT.md §5.1).",
            )
        }

        val body = buildJsonObject {
            put("federation_config_id", params.federationConfigId)
            put("redirect_uri", params.redirectUri)
            if (tenantId != null) put("tenant_id", tenantId) else put("tenant_slug", tenantSlug)
            if (orgId != null) put("org_id", orgId) else put("org_slug", orgSlug)
        }
        val response = postJsonAbsolute(baseUrl + SSO_START_PATH, body)
        response.use {
            // §12 port addendum item 12: the federation error body shape is
            // undocumented — fall through to the generic §2 status mapping,
            // never attempt to parse an OAuth2ErrorResponse here.
            if (it.code != 200) throw ErrorMapper.fromHttpStatus(it.code, "ssoStart request failed", it)
            val json = parseJsonObject(it)
            return SsoStartResult(
                authorizeUrl = json.str("authorize_url"),
                state = json.str("state"),
                expiresInSecs = json.long("expires_in_secs"),
            )
        }
    }

    // -- 9. ssoComplete ---------------------------------------------------------------

    /**
     * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — step 2 of
     * upstream SSO: consumes the single-use `state`, provisions or links the
     * user, and establishes the session.
     *
     * The session arrives as `Set-Cookie`, NOT in the response body (§12.1
     * note 6). Because this request runs through the SAME shared
     * [httpClient] every other call in this SDK uses, the §4 cookie jar
     * captures it automatically — no separate absorption step is needed.
     *
     * §12.4 does not apply here: no ID token ever reaches the SDK on the
     * federation path.
     */
    suspend fun ssoComplete(params: SsoCompleteParams): SsoCompleteResult {
        val body = buildJsonObject {
            put("state", params.state)
            put("code", params.code)
        }
        val response = postJsonAbsolute(baseUrl + SSO_CALLBACK_PATH, body)
        response.use {
            if (it.code != 200) throw ErrorMapper.fromHttpStatus(it.code, "ssoComplete request failed", it)
            val json = parseJsonObject(it)
            return SsoCompleteResult(
                userId = json.str("user_id"),
                sessionId = json.str("session_id"),
                expiresIn = json.long("expires_in"),
                redirectUri = json.str("redirect_uri"),
            )
        }
    }

    // -- shared wire mechanics -------------------------------------------------

    // -- §14 Device Authorization Grant (RFC 8628) -------------------------

    /**
     * `POST /oauth2/device_authorization` (§14.1) — start the grant and obtain
     * the code pair.
     *
     * **Unauthenticated by design.** A device that cannot show a browser also
     * cannot hold a client secret, so this never sends `client_secret` and
     * never refuses a client built without one (§14.1).
     *
     * @throws AuthError when the discovery document advertises no
     *   `device_authorization_endpoint`. The URL is never built by
     *   concatenation onto the issuer: that works against AXIAM and breaks
     *   against every other OP the same code is pointed at.
     */
    suspend fun deviceAuthorize(params: DeviceAuthorizeParams): DeviceAuthorization {
        val configuration = params.configuration ?: oidcDiscover()
        val endpoint = configuration.device_authorization_endpoint
            ?: throw AuthError(
                "the authorization server's discovery document advertises no " +
                    "device_authorization_endpoint: this server does not support the device " +
                    "grant (CONTRACT.md §14.1)",
            )

        val form = buildForm(
            "client_id" to requireClientId(),
            "scope" to params.scope,
        )
        val url = endpointUrl(endpoint, params.tenantId)
        val json = postOAuth2Form(url, form, "device authorization request failed")

        val interval = json.intOrNull("interval")
        return DeviceAuthorization(
            deviceCode = Sensitive.of(json.str("device_code")),
            userCode = json.str("user_code"),
            verificationUri = json.str("verification_uri"),
            verificationUriComplete = json.strOrNull("verification_uri_complete"),
            expiresIn = json.str("expires_in").toInt(),
            // §14.2 rule 2: the interval comes from the response; only its
            // absence falls back to the RFC default. A server-sent 0 is treated
            // as absent — polling with no delay is never what the server meant.
            interval = if (interval != null && interval > 0) interval else DEFAULT_POLL_INTERVAL_SECONDS,
        )
    }

    /**
     * `POST /oauth2/token` with the device-code grant (§14.1) — **one** poll
     * attempt.
     *
     * The raw single call, so an application driving its own loop (a UI
     * rendering a countdown, say) can. All five RFC 8628 §3.5 answers surface
     * as [OAuthProtocolError] — `authorization_pending` and `slow_down`
     * included — so a hand-rolled loop sees exactly what [deviceLogin] sees.
     * Most callers want [deviceLogin].
     */
    suspend fun devicePoll(params: DevicePollParams): OidcTokenSet {
        val configuration = params.configuration ?: oidcDiscover()
        val clientId = requireClientId()
        val form = buildForm(
            "grant_type" to DEVICE_CODE_GRANT_TYPE,
            "device_code" to params.deviceCode.expose(),
            "client_id" to clientId,
        )
        val json = postToken(configuration, form, params.tenantId)
        // No nonce: the device grant has no authorization request to carry one.
        val expectations = OidcIdToken.Expectations(
            issuer = configuration.issuer,
            clientId = clientId,
            nonce = null,
            hasNonce = false,
            clockSkewSec = clockSkewSec,
        )
        return toTokenSet(json, configuration, expectations)
    }

    /**
     * The composed §14.3 helper: start the grant, hand the caller the user
     * code, poll to completion.
     *
     * [DeviceLoginParams.onUserCode] is a `suspend` function and is **awaited
     * before the first poll** — §14.3 rule 2 requires the caller to have had
     * the chance to display the code before polling begins, and a device
     * rendering a QR code may need to await a paint. The SDK never prints it.
     *
     * Per §14.3 rule 4 (contract 1.7 errata) the token set is **returned**;
     * this SDK does not adopt it, matching its `loginClientCredentials`
     * posture.
     *
     * Polling follows §14.2: the interval comes from the response; `slow_down`
     * adds 5 s **permanently**; `authorization_pending` loops; `access_denied`
     * and `expired_token` raise distinct errors; polling stops at `expiresIn`
     * even if the server has not yet said `expired_token`. A 5xx or transport
     * failure mid-poll is **not** terminal (rule 6) — a server restart must not
     * lose a grant the user has already approved.
     *
     * The inter-poll wait is `delay`, so cancelling the calling coroutine
     * cancels the login promptly rather than after the current interval.
     */
    suspend fun deviceLogin(params: DeviceLoginParams): OidcTokenSet {
        val configuration = params.configuration ?: oidcDiscover()
        val authorization = deviceAuthorize(
            DeviceAuthorizeParams(
                scope = params.scope,
                tenantId = params.tenantId,
                configuration = configuration,
            ),
        )

        // §14.3 rule 2 — before any polling.
        params.onUserCode(authorization)

        var intervalSeconds = authorization.interval
        var remainingSeconds = authorization.expiresIn

        while (true) {
            // §14.2 rule 4: the deadline is authoritative. Checking before
            // waiting keeps the SDK from issuing a request that can only be
            // refused, and reports it under the same `expired_token` code the
            // server would have used — so a caller's branch does not care which
            // side noticed first.
            if (intervalSeconds >= remainingSeconds) {
                throw OAuthProtocolError(
                    error = "expired_token",
                    errorDescription = "the device authorization expired before the user " +
                        "completed it (client-side deadline from expires_in; " +
                        "CONTRACT.md §14.2 rule 4)",
                )
            }
            remainingSeconds -= intervalSeconds

            delay(intervalSeconds * 1000L)

            try {
                return devicePoll(
                    DevicePollParams(
                        deviceCode = authorization.deviceCode,
                        tenantId = params.tenantId,
                        configuration = configuration,
                    ),
                )
            } catch (e: OAuthProtocolError) {
                when (e.error) {
                    "authorization_pending" -> continue
                    // §14.2 rule 1: cumulative, never reset.
                    "slow_down" -> {
                        intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS
                        continue
                    }
                    // expired_token / access_denied / invalid_grant — terminal.
                    else -> throw e
                }
            } catch (e: NetworkError) {
                // §14.2 rule 6: transport and 5xx failures are not among the
                // five protocol answers and are not terminal.
                continue
            }
        }
    }

    // -- §15 Token Exchange (RFC 8693) -------------------------------------

    /**
     * `POST /oauth2/token` with the RFC 8693 grant (§15.1) — exchange a token
     * for a **narrower** one.
     *
     * The exchanging client authenticates (`client_secret_post`): unlike §14's
     * device, this is a confidential service, so a client with no secret fails
     * here client-side, with no wire call.
     *
     * What this method deliberately does **not** do:
     *
     * - **No default `actorToken`** (§15.2 rule 1). Leaving it `null` asks for
     *   *impersonation*; the SDK will not quietly reuse the client's own
     *   session token as the actor and turn that into a delegation.
     * - **No retry or downgrade on `unauthorized_client`** (rule 2) — a
     *   registration fact an operator must fix.
     * - **No auto-narrowing on `invalid_scope`** (rule 3). The server refuses
     *   instead of silently narrowing precisely so the caller finds out here.
     * - **No adoption** (rule 5). The returned token is handed onward in one
     *   outbound call.
     *
     * A cross-tenant subject token answers `invalid_grant`, identically to an
     * expired one. The SDK does not try to tell them apart (§15.3): the server
     * collapses them because distinguishing them is a tenant-enumeration signal.
     */
    suspend fun tokenExchange(params: TokenExchangeParams): ExchangedToken {
        val configuration = params.configuration ?: oidcDiscover()
        val form = buildForm(
            "grant_type" to TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token" to params.subjectToken.expose(),
            "subject_token_type" to ACCESS_TOKEN_TYPE,
            "actor_token" to params.actorToken?.expose(),
            // Sent exactly when `actor_token` is: RFC 8693 §2.1 requires the
            // pair, and the type alone is a malformed request. `buildForm`
            // drops a null value, so this stays paired without a branch.
            "actor_token_type" to params.actorToken?.let { ACCESS_TOKEN_TYPE },
            "scope" to params.scopes?.takeIf { it.isNotEmpty() }?.joinToString(" "),
            "audience" to params.audience,
            "resource" to params.resource,
            "client_id" to requireClientId(),
            "client_secret" to requireClientSecret("tokenExchange"),
        )
        val url = endpointUrl(configuration.token_endpoint, params.tenantId)
        val json = postOAuth2Form(url, form, "token exchange request failed")

        return ExchangedToken(
            accessToken = Sensitive.of(json.str("access_token")),
            issuedTokenType = json.str("issued_token_type"),
            tokenType = json.str("token_type"),
            expiresIn = json.long("expires_in"),
            scope = json.strOrNull("scope"),
        )
    }

    // -- §12.7 Logout helpers ----------------------------------------------

    /**
     * Build the RP-initiated logout URL to redirect the user agent to (§12.7.2).
     *
     * Performs **no network I/O** beyond the discovery fetch the SDK caches
     * anyway, and does **not** clear this client's own session: whether the
     * local session ends is the application's decision — a backend holding a
     * service-account session must not lose it because a *user* logged out.
     *
     * `end_session_endpoint` is read from discovery and never synthesised from
     * the issuer (rule 1). [LogoutUrlParams.postLogoutRedirectUri] is passed
     * through **unvalidated against any local list** (rule 3): the allow-list
     * lives in the client's server-side registration, and a client-side copy
     * would drift and reject a URI an operator had just registered.
     */
    suspend fun logoutUrl(params: LogoutUrlParams): String {
        val configuration = params.configuration ?: oidcDiscover()
        val endpoint = configuration.end_session_endpoint
            ?: throw AuthError(
                "the authorization server's discovery document advertises no " +
                    "end_session_endpoint: this server does not support RP-initiated logout " +
                    "(CONTRACT.md §12.7.2 rule 1)",
            )
        val httpUrl = endpoint.toHttpUrlOrNull()
            ?: throw NetworkError("invalid end_session_endpoint from discovery document: $endpoint")

        val builder = httpUrl.newBuilder().addQueryParameter("id_token_hint", params.idToken.expose())
        params.postLogoutRedirectUri?.let { builder.addQueryParameter("post_logout_redirect_uri", it) }
        params.state?.let { builder.addQueryParameter("state", it) }
        return builder.build().toString()
    }

    /**
     * Verify a back-channel logout token the OP POSTed to this application's
     * `backchannel_logout_uri` (§12.7.3).
     *
     * Every check exists because skipping it has a name:
     *
     * 1. **Signature**, through the same §12.4 JWKS verifier the ID-token path
     *    uses — no second key-fetching path — which already pins EdDSA and
     *    requires a `kid`, so rotation cannot be defeated by omitting it.
     * 2. **`iss`/`aud`**: a token minted for another RP is not accepted here.
     * 3. **`events` carries the back-channel-logout key.** This is what
     *    distinguishes a logout token from an ID token; skipping it means
     *    accepting a replayed ID token as a logout instruction.
     * 4. **`nonce` is absent.** Back-Channel Logout 1.0 §2.4 forbids it, and
     *    its presence is the documented signature of an ID token being
     *    replayed. Rejected, not ignored.
     * 5. **At least one of `sid`/`sub`** — a token naming neither identifies
     *    nothing.
     * 6. **`exp` in the future, `iat` recent.**
     *
     * @return the `sid`/`sub`/`jti` the token names — never a bare `Boolean`,
     *   because the RP has to know *which* session to end.
     */
    suspend fun verifyLogoutToken(
        logoutToken: String,
        configuration: OidcConfiguration? = null,
    ): VerifiedLogoutToken {
        val config = configuration ?: oidcDiscover()
        val verifier = verifierFor(config.jwks_uri)

        val claims = try {
            verifier.verifyForIdToken(logoutToken)
        } catch (e: AuthError) {
            throw e
        } catch (e: Exception) {
            // The message never embeds the token: an unverifiable logout token
            // is exactly the case a naive implementation logs verbatim.
            throw AuthError("logout token signature verification failed: ${e.message}")
        }

        if (claims.issuer != config.issuer) {
            throw AuthError("logout token issuer does not match the discovery document")
        }
        if (claims.audience?.contains(requireClientId()) != true) {
            throw AuthError("logout token audience does not match this client_id")
        }

        // Without this check the whole method is an elaborate way to accept an
        // ID token.
        val events = claims.getClaim("events")
        if (events !is Map<*, *> || events[BACKCHANNEL_LOGOUT_EVENT] !is Map<*, *>) {
            throw AuthError(
                "not a logout token: the events claim does not carry $BACKCHANNEL_LOGOUT_EVENT",
            )
        }

        if (claims.getClaim("nonce") != null) {
            throw AuthError(
                "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: " +
                    "this is an ID token being replayed as a logout token",
            )
        }

        val sid = claims.getClaim("sid") as? String
        val sub = claims.subject
        if (sid == null && sub == null) {
            throw AuthError("logout token names neither sid nor sub, so it identifies no session")
        }

        val nowSec = System.currentTimeMillis() / 1000L
        val skew = clockSkewSec?.toLong() ?: 0L
        val exp = claims.expirationTime?.time?.div(1000L)
        val iat = claims.issueTime?.time?.div(1000L)
        if (exp == null || exp + skew < nowSec) {
            throw AuthError("logout token has expired")
        }
        if (iat == null || iat - skew > nowSec) {
            throw AuthError("logout token was issued in the future")
        }
        if (nowSec - iat > MAX_LOGOUT_TOKEN_AGE_SECONDS + skew) {
            throw AuthError("logout token is too old to be a live delivery")
        }

        val jti = claims.jwtid
        if (jti.isNullOrEmpty()) {
            throw AuthError("logout token carries no jti, so the RP cannot dedup redeliveries")
        }

        return VerifiedLogoutToken(sid = sid, sub = sub, jti = jti)
    }

    private suspend fun postToken(configuration: OidcConfiguration, form: RequestBody, tenantIdOverride: String?): JsonObject {
        val url = endpointUrl(configuration.token_endpoint, tenantIdOverride)
        return postOAuth2Form(url, form, "token request failed")
    }

    /**
     * POSTs a form-encoded body (§12.1 note 1) through the SAME shared
     * [httpClient] every other request in this SDK uses (so §5's
     * `X-Tenant-ID` header and §6 TLS transport apply unconditionally).
     * Non-2xx responses are mapped via [mapOAuth2ErrorResponse].
     */
    private suspend fun postOAuth2Form(url: String, form: RequestBody, fallbackMessage: String): JsonObject {
        val request = Request.Builder().url(url).post(form).build()
        val response = executeRequest(request)
        response.use {
            if (!it.isSuccessful) throw mapOAuth2ErrorResponse(it, fallbackMessage)
            return parseJsonObject(it)
        }
    }

    private suspend fun postJsonAbsolute(url: String, body: JsonObject): Response {
        val payload = Json.encodeToString(JsonObject.serializer(), body).toRequestBody(JSON_MEDIA)
        val request = Request.Builder().url(url).post(payload).build()
        return executeRequest(request)
    }

    private suspend fun executeRequest(request: Request): Response = withContext(Dispatchers.IO) {
        try {
            httpClient.newCall(request).execute()
        } catch (e: IOException) {
            throw NetworkError("request failed: ${e.message}", e)
        }
    }

    /**
     * Maps a non-2xx response from an `/oauth2/...` endpoint (CONTRACT.md §2,
     * §12.1, §12.3 rule 3): a `400` (token endpoint) or `401`
     * (introspect/revoke) carrying a well-formed `OAuth2ErrorResponse` body
     * maps to [OAuthProtocolError]; anything else — including a `400`/`401`
     * WITHOUT that body shape, and every other status — falls through to
     * [ErrorMapper], which does NOT special-case `400` as an
     * [OAuthProtocolError] (the endpoint-qualified row only wins when the
     * body actually matches).
     */
    private fun mapOAuth2ErrorResponse(response: Response, fallbackMessage: String): AxiamException {
        if (response.code == 400 || response.code == 401) {
            val bodyText = try {
                response.peekBody(MAX_OAUTH2_ERROR_BODY_BYTES).string()
            } catch (_: Exception) {
                null
            }
            val parsed = bodyText?.let(::parseOAuth2ErrorBody)
            if (parsed != null) return OAuthProtocolError(parsed.first, parsed.second)
        }
        return ErrorMapper.fromHttpStatus(response.code, fallbackMessage, response)
    }

    private fun parseOAuth2ErrorBody(text: String): Pair<String, String>? {
        if (text.isBlank()) return null
        return try {
            val obj = Json.parseToJsonElement(text).jsonObject
            val error = obj.strOrNull("error")
            if (error.isNullOrBlank()) return null
            val description = obj.strOrNull("error_description") ?: ""
            error to description
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Converts a `TokenResponse` JSON body into an [OidcTokenSet], validating
     * any `id_token` FIRST (§12.4). Validation precedes construction, so a
     * failure discards the whole set — the caller never sees the access or
     * refresh token from a response whose ID token was rejected (§12.4
     * rule 7).
     */
    private suspend fun toTokenSet(
        json: JsonObject,
        configuration: OidcConfiguration,
        expectations: OidcIdToken.Expectations,
    ): OidcTokenSet {
        val accessToken = json.str("access_token")
        val tokenType = json.str("token_type")
        val expiresIn = json.long("expires_in")
        val scope = json.strOrNull("scope")
        val refreshToken = json.strOrNull("refresh_token")
        val idToken = json.strOrNull("id_token")

        val idClaims = if (!idToken.isNullOrEmpty()) {
            val verifier = verifierFor(configuration.jwks_uri)
            val claims = verifier.verifyForIdToken(idToken)
            OidcIdToken.checkClaims(claims, expectations)
        } else {
            null
        }

        return OidcTokenSet(
            accessToken = Sensitive.of(accessToken),
            tokenType = tokenType,
            expiresIn = expiresIn,
            scope = scope,
            refreshToken = refreshToken?.let { Sensitive.of(it) },
            idToken = idToken?.let { Sensitive.of(it) },
            idClaims = idClaims,
        )
    }

    private val verifiersMutex = Mutex()
    private val verifiers = mutableMapOf<String, JwksVerifier>()

    /**
     * Lazily builds (and reuses) the JWKS verifier for a `jwks_uri` (§12.3
     * rule 6): JWKS is a single global key set, not per-tenant, so this cache
     * is keyed on `jwks_uri`, never on tenant — and built against the
     * discovery document's `jwks_uri` DIRECTLY
     * ([JwksVerifier.forJwksUri]), never a re-derived
     * `baseUrl + "/oauth2/jwks"`, since the two may legitimately differ
     * behind a proxy — UNLESS [resolveJwksUri] rejects it (SEC-075), in
     * which case the fallback path IS the re-derived URL.
     */
    private suspend fun verifierFor(jwksUri: String): JwksVerifier = verifiersMutex.withLock {
        val resolved = resolveJwksUri(jwksUri)
        verifiers.getOrPut(resolved) { JwksVerifier.forJwksUri(resolved) }
    }

    /**
     * SEC-075 anti-key-substitution / anti-SSRF guard (the `SDK-19` class,
     * first fixed in the PHP SDK): the discovery document is itself fetched
     * from [baseUrl], but its `jwks_uri` field is otherwise unconstrained
     * server-provided data. Following it blindly would let a compromised or
     * misconfigured discovery response point EdDSA key resolution at a host
     * of the attacker's choosing — substituting their own signing keys — or
     * coerce this client into fetching an arbitrary URL.
     *
     * Only a `jwks_uri` that is an absolute `https` URL AND same-origin
     * (case-insensitive host, exact port) with [baseUrl] is honoured; every
     * other shape — a relative path, plaintext `http`, or an off-origin
     * absolute URL — falls back to the conventional `{baseUrl}/oauth2/jwks`,
     * the path every sibling SDK hardcodes. This mirrors the PHP SDK's
     * `isSameOriginHttps` exactly (no loopback carve-out here, unlike
     * SEC-073's base-URL check: this guard runs against SERVER-SUPPLIED
     * data, not developer-supplied configuration).
     */
    private fun resolveJwksUri(candidate: String): String =
        if (isSameOriginHttps(candidate)) candidate else baseUrl + FALLBACK_JWKS_PATH

    private fun isSameOriginHttps(candidate: String): Boolean {
        val candidateUrl = candidate.toHttpUrlOrNull() ?: return false
        val baseHttpUrl = baseUrl.toHttpUrlOrNull() ?: return false
        if (!candidateUrl.scheme.equals("https", ignoreCase = true)) return false
        return candidateUrl.host.equals(baseHttpUrl.host, ignoreCase = true) && candidateUrl.port == baseHttpUrl.port
    }

    /**
     * Builds the final endpoint URL: the discovery document's endpoint (read
     * from the document, NEVER hardcoded — §12.3 rule 6) plus the mandatory
     * `?tenant_id=<uuid>` query parameter (§12.1 note 2). Existing query
     * parameters on the endpoint, if any, are preserved.
     */
    private fun endpointUrl(endpoint: String, tenantIdOverride: String?): String {
        val tenantId = resolveTenantId(tenantIdOverride)
        val httpUrl = endpoint.toHttpUrlOrNull()
            ?: throw NetworkError("invalid endpoint URL from discovery document: $endpoint")
        return httpUrl.newBuilder().addQueryParameter("tenant_id", tenantId).build().toString()
    }

    /**
     * Resolves the tenant UUID for the mandatory `?tenant_id=` query
     * parameter (CONTRACT.md §12.3 rule 4): the explicit per-call argument
     * when given; else the client's configured tenant identifier when it is
     * itself a UUID (the client "was constructed in UUID form"); else the
     * `tenant_id` claim decoded (unverified, operational-hint-only — mirrors
     * [SessionState.doHttpRefresh]) from the current session's cached access
     * token, when a prior `login()` resolved one. Neither source available is
     * a CLIENT-SIDE [AuthError], no wire call (same discipline as §1.1
     * rule 3).
     */
    private fun resolveTenantId(explicit: String?): String {
        val candidate = explicit
            ?: configuredTenantId.takeIf { UUID_RE.matches(it) }
            ?: sessionResolvedTenantId()
            ?: throw AuthError(
                "this operation requires a tenant_id UUID for the /oauth2 query parameter: pass " +
                    "tenantId explicitly, or construct the client with a UUID tenantId " +
                    "(CONTRACT.md §12.3 rule 4).",
            )
        if (!UUID_RE.matches(candidate)) {
            throw AuthError(
                "tenant_id must be a UUID for the /oauth2 query parameter; a tenant slug cannot be " +
                    "substituted (CONTRACT.md §12.3 rule 4).",
            )
        }
        return candidate
    }

    private fun sessionResolvedTenantId(): String? {
        val access = session.cachedAccessToken() ?: return null
        return SessionState.decodeUnverifiedClaims(access)?.tenantId
    }

    private fun requireClientId(): String = oidcClientId
        ?: throw AuthError(
            "this OIDC operation requires oidcClientId to be configured at AxiamClient construction " +
                "time (CONTRACT.md §12).",
        )

    private fun requireClientSecret(operation: String): String = oidcClientSecret?.expose()
        ?: throw AuthError(
            "$operation requires confidential-client credentials: construct the client with " +
                "oidcClientSecret (CONTRACT.md §12.1 note 4).",
        )

    private fun buildForm(vararg pairs: Pair<String, String?>): RequestBody {
        val builder = FormBody.Builder()
        for ((key, value) in pairs) {
            if (value != null) builder.add(key, value)
        }
        return builder.build()
    }

    private fun parseJsonObject(response: Response): JsonObject {
        val text = response.body?.string()
        if (text.isNullOrBlank()) return JsonObject(emptyMap())
        return try {
            Json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw NetworkError("failed to parse response body: ${e.message}", e)
        }
    }

    private fun normalizeScope(scope: String?): String {
        val requested = (scope ?: "").split(" ").map { it.trim() }.filter { it.isNotEmpty() }
        val ordered = LinkedHashSet<String>()
        ordered.add(OPENID_SCOPE)
        ordered.addAll(requested)
        return ordered.joinToString(" ")
    }

    /**
     * Appends [params] to [endpoint] as RFC 3986-percent-encoded query
     * parameters (§12.1 rule 5), preserving any existing query string. Spaces
     * are percent-encoded as `%20` (CONTRACT.md §12 port addendum item 10) —
     * unlike `application/x-www-form-urlencoded`, which would use `+`.
     */
    private fun appendQuery(endpoint: String, params: Map<String, String>): String {
        val query = params.entries.joinToString("&") { (key, value) -> "${percentEncode(key)}=${percentEncode(value)}" }
        return if (endpoint.contains('?')) "$endpoint&$query" else "$endpoint?$query"
    }

    private fun percentEncode(value: String): String {
        val encoded = StringBuilder()
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val code = byte.toInt() and 0xFF
            val ch = code.toChar()
            val isUnreserved = ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' ||
                ch == '-' || ch == '.' || ch == '_' || ch == '~'
            if (isUnreserved) {
                encoded.append(ch)
            } else {
                encoded.append('%').append(String.format("%02X", code))
            }
        }
        return encoded.toString()
    }

    companion object {
        /** Path of the OIDC discovery document, relative to the client base URL. */
        const val DISCOVERY_PATH: String = "/.well-known/openid-configuration"

        /** Path of the federation SSO step-1 endpoint. */
        const val SSO_START_PATH: String = "/api/v1/auth/federation/oidc/start"

        /** Path of the federation SSO step-2 (callback) endpoint. */
        const val SSO_CALLBACK_PATH: String = "/api/v1/auth/federation/oidc/callback"

        /** Minimum — and default — discovery-cache TTL (CONTRACT.md §12.3 rule 6). */
        const val MIN_DISCOVERY_TTL_MS: Long = 300_000L

        /** `grant_type` of the device access-token request (RFC 8628 §3.4). */
        const val DEVICE_CODE_GRANT_TYPE: String = "urn:ietf:params:oauth:grant-type:device_code"

        /**
         * Polling interval used when the authorization response omits
         * `interval` (RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT hard-code
         * a faster floor.
         */
        const val DEFAULT_POLL_INTERVAL_SECONDS: Int = 5

        /**
         * Seconds added to the polling interval on each `slow_down` (§14.2
         * rule 1). The increase is permanent and cumulative.
         */
        const val SLOW_DOWN_INCREMENT_SECONDS: Int = 5

        /** `grant_type` of an RFC 8693 exchange. */
        const val TOKEN_EXCHANGE_GRANT_TYPE: String =
            "urn:ietf:params:oauth:grant-type:token-exchange"

        /** The only `subject_token_type`/`actor_token_type` AXIAM accepts. */
        const val ACCESS_TOKEN_TYPE: String = "urn:ietf:params:oauth:token-type:access_token"

        /**
         * The `events` member that distinguishes a logout token from an ID
         * token (OIDC Back-Channel Logout 1.0 §2.4).
         */
        const val BACKCHANNEL_LOGOUT_EVENT: String =
            "http://schemas.openid.net/event/backchannel-logout"

        /**
         * Maximum accepted age for a logout token's `iat`, in seconds. AXIAM
         * issues them with a 120 s lifetime; this bound is the same order and
         * stops a token captured from a mis-configured RP being replayed days
         * later.
         */
        const val MAX_LOGOUT_TOKEN_AGE_SECONDS: Long = 300L

        /** SEC-075 fallback path for a `jwks_uri` that fails the same-origin-https check. */
        private const val FALLBACK_JWKS_PATH = "/oauth2/jwks"

        private const val OPENID_SCOPE = "openid"
        private const val MAX_OAUTH2_ERROR_BODY_BYTES = 8192L

        /** The eight query parameters [oidcBegin] owns (§12.1 rule 5). */
        private val RESERVED_AUTHORIZE_PARAMS = setOf(
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        )

        /** Shape of a UUID, used to reject a slug where §12.3 rule 4 requires a UUID. */
        private val UUID_RE = Regex(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            RegexOption.IGNORE_CASE,
        )

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
    }
}

private fun JsonObject.str(key: String): String =
    this[key]?.jsonPrimitive?.let { if (it is JsonNull) null else it.content }
        ?: throw NetworkError("response is missing the required field \"$key\"")

private fun JsonObject.strOrNull(key: String): String? =
    this[key]?.jsonPrimitive?.let { if (it is JsonNull) null else it.content }

private fun JsonObject.strList(key: String): List<String> =
    this[key]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList()

private fun JsonObject.long(key: String): Long =
    strOrNull(key)?.toLongOrNull() ?: throw NetworkError("response is missing the required field \"$key\"")

private fun JsonObject.longOrNull(key: String): Long? = strOrNull(key)?.toLongOrNull()

private fun JsonObject.intOrNull(key: String): Int? = strOrNull(key)?.toIntOrNull()

private fun JsonObject.boolOrFalse(key: String): Boolean = strOrNull(key)?.toBoolean() ?: false
