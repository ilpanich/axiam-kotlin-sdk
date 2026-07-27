package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AxiamException
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.SessionState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
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
 * `oidcRefresh` uses its OWN single-flight guard ([pendingRefresh]), a
 * SEPARATE instance from [io.axiam.sdk.internal.RefreshGuard] — that type's
 * `refreshIfNeeded` API compares an "observed" `axiam_access` cookie value
 * against a cached [io.axiam.sdk.internal.TokenPair], which has no meaning
 * for an OAuth2 `refresh_token` grant operating on an entirely different,
 * cookie-independent token namespace (documented deviation from the
 * TypeScript reference, matching the Go port's reasoning). A dedicated guard
 * built from the SAME mechanism CONTRACT.md §9 prescribes for Kotlin
 * (`Mutex` guarding a shared `Deferred`) still satisfies §9's actual
 * requirement for this operation — exactly one in-flight refresh, waiters
 * share the outcome, no retry on failure.
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

    private val discoveryMutex = Mutex()

    @Volatile
    private var cachedDoc: OidcConfiguration? = null

    @Volatile
    private var cachedExpiresAtMs: Long = 0L
    private var inFlightDiscovery: CompletableDeferred<OidcConfiguration>? = null

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
     */
    suspend fun oidcDiscover(): OidcConfiguration {
        val leaderDeferred: CompletableDeferred<OidcConfiguration>?
        val joinTarget: CompletableDeferred<OidcConfiguration>

        discoveryMutex.withLock {
            val doc = cachedDoc
            if (doc != null && System.currentTimeMillis() < cachedExpiresAtMs) {
                return doc
            }
            val existing = inFlightDiscovery
            if (existing != null) {
                leaderDeferred = null
                joinTarget = existing
            } else {
                val fresh = CompletableDeferred<OidcConfiguration>()
                inFlightDiscovery = fresh
                leaderDeferred = fresh
                joinTarget = fresh
            }
        }

        if (leaderDeferred == null) {
            return joinTarget.await()
        }

        return try {
            val doc = fetchDiscoveryDocument()
            cachedDoc = doc
            cachedExpiresAtMs = System.currentTimeMillis() + this.discoveryTtlMs
            leaderDeferred.complete(doc)
            doc
        } catch (t: Throwable) {
            leaderDeferred.completeExceptionally(t)
            throw t
        } finally {
            discoveryMutex.withLock { inFlightDiscovery = null }
        }
    }

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

    private val refreshMutex = Mutex()
    private var pendingRefresh: CompletableDeferred<OidcTokenSet>? = null

    /**
     * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1) — refresh
     * an [OidcTokenSet] under [pendingRefresh]'s single-flight guard (§9):
     * concurrent callers collapse into ONE HTTP request and all receive the
     * same result (or the same failure), with no retry loop on failure
     * (§9 rule 3).
     *
     * A DISTINCT operation from `AxiamClient.refresh()`, which drives the
     * cookie/opaque-token session path at `POST /api/v1/auth/refresh` — the
     * two are never merged, aliased, or made to fall back to one another.
     *
     * An `id_token` in the response is validated against §12.4 rules 1-5
     * and 7; rule 6 (nonce) is skipped, since OIDC Core §12.2 does not
     * require a nonce in a refresh-issued ID token.
     */
    suspend fun oidcRefresh(params: OidcRefreshParams): OidcTokenSet {
        val leaderDeferred: CompletableDeferred<OidcTokenSet>?
        val joinTarget: CompletableDeferred<OidcTokenSet>

        refreshMutex.withLock {
            val existing = pendingRefresh
            if (existing != null) {
                leaderDeferred = null
                joinTarget = existing
            } else {
                val fresh = CompletableDeferred<OidcTokenSet>()
                pendingRefresh = fresh
                leaderDeferred = fresh
                joinTarget = fresh
            }
        }

        if (leaderDeferred == null) {
            return joinTarget.await()
        }

        return try {
            val result = doOidcRefresh(params)
            leaderDeferred.complete(result)
            result
        } catch (t: Throwable) {
            leaderDeferred.completeExceptionally(t)
            throw t
        } finally {
            refreshMutex.withLock { pendingRefresh = null }
        }
    }

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
     * touches [pendingRefresh] or [io.axiam.sdk.internal.RefreshGuard] —
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
     * behind a proxy.
     */
    private suspend fun verifierFor(jwksUri: String): JwksVerifier = verifiersMutex.withLock {
        verifiers.getOrPut(jwksUri) { JwksVerifier.forJwksUri(jwksUri) }
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
