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
import io.axiam.sdk.oidc.FederationProviderList
import io.axiam.sdk.oidc.PROTOCOL_OAUTH2
import io.axiam.sdk.oidc.SsoCompleteHandoffParams
import io.axiam.sdk.oidc.SsoCompleteOauth2Params
import io.axiam.sdk.oidc.SsoCompleteParams
import io.axiam.sdk.oidc.SsoCompleteResult
import io.axiam.sdk.oidc.SsoProvidersParams
import io.axiam.sdk.oidc.SsoStartOauth2Params
import io.axiam.sdk.oidc.SsoStartParams
import io.axiam.sdk.oidc.SsoStartResult
import io.axiam.sdk.opaque.KsfParams
import io.axiam.sdk.opaque.Opaque
import io.axiam.sdk.opaque.OpaqueEnrollment
import io.axiam.sdk.account.MfaEnrollment
import io.axiam.sdk.account.PasswordResetConfirmation
import io.axiam.sdk.account.PasswordResetContext
import io.axiam.sdk.account.PasswordResetRequest
import io.axiam.sdk.oidc.OidcParParams
import io.axiam.sdk.oidc.PushedAuthorizationRequest
import io.axiam.sdk.webauthn.WebauthnChallenge
import io.axiam.sdk.webauthn.WebauthnCredential
import io.axiam.sdk.webauthn.WebauthnLoginResult
import io.axiam.sdk.webauthn.WebauthnWorkspace
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonPrimitive
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

    /**
     * CONTRACT.md §5.2.2 — the tenant the signed-in principal's record *lives* in,
     * as reported by the login response.
     *
     * Distinct from [tenantId], which is the tenant being acted on: the two
     * diverge for an organization-level principal that has selected another one.
     * Read by [opaqueEnrollmentForSelf], which must seal a §23 record against the
     * account's own tenant rather than whichever one this client is currently
     * pointed at. `null` until a login completes. `@Volatile` because a client is
     * shared across coroutines and a stale read here would seal against the wrong
     * tenant — the whole failure this field exists to prevent.
     */
    @Volatile
    private var principalTenantId: UUID? = null

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

    /**
     * The CONTRACT.md §27 management API, acting as this client's session.
     *
     * A view over the client, not a connection: building one performs no I/O
     * (§27.2 rule 1), so there is nothing to cache and nothing to close.
     * Everything it issues goes through this client's own request path, so §3
     * CSRF, the §4 cookie jar, the §5 tenant header, §6 TLS, §16 retry and §19
     * telemetry all apply unchanged.
     */
    fun management(): io.axiam.sdk.management.ManagementApi =
        io.axiam.sdk.management.ManagementApi(
            io.axiam.sdk.internal.ManagementTransport(
                http = httpClient,
                baseUrl = baseUrl,
                sessionState = session,
                telemetry = telemetry,
                retryEnabled = retryEnabled,
                ensureOpen = ::ensureOpen,
            ),
        )

    // ---- CONTRACT.md §27.2/§27.3: the namespace handles, on the client ----
    //
    // `client.serviceAccounts.rotateSecret(id)` -- the form §27.3's Kotlin row shows,
    // a PROPERTY rather than a function. `management()` above reaches the same handles
    // behind one accessor, which §27.2 rule 4 makes the ADDITIONAL one ("SHOULD
    // additionally be reachable behind one accessor"); shipping only that had the two
    // the wrong way round, with the optional form present and the one the naming map
    // specifies absent.
    //
    // Each delegates to management(), so rule 4's "where an SDK offers both, the two
    // MUST return equivalent handles" holds structurally rather than by two code paths
    // agreeing to stay in step. A `get()` rather than a stored `val`: §27.2 rule 1 says
    // acquiring a handle performs no I/O, and a stored property would build all 24 of
    // them -- and a ManagementTransport apiece -- when a client is constructed.

    /**
     * The organizations operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().organizations()` (§27.2 rule 4).
     */
    val organizations: io.axiam.sdk.management.OrganizationsApi
        get() = management().organizations()

    /**
     * The tenants operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().tenants()` (§27.2 rule 4).
     */
    val tenants: io.axiam.sdk.management.TenantsApi
        get() = management().tenants()

    /**
     * The users operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().users()` (§27.2 rule 4).
     */
    val users: io.axiam.sdk.management.UsersApi
        get() = management().users()

    /**
     * The groups operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().groups()` (§27.2 rule 4).
     */
    val groups: io.axiam.sdk.management.GroupsApi
        get() = management().groups()

    /**
     * The roles operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().roles()` (§27.2 rule 4).
     */
    val roles: io.axiam.sdk.management.RolesApi
        get() = management().roles()

    /**
     * The permissions operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().permissions()` (§27.2 rule 4).
     */
    val permissions: io.axiam.sdk.management.PermissionsApi
        get() = management().permissions()

    /**
     * The resources operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().resources()` (§27.2 rule 4).
     */
    val resources: io.axiam.sdk.management.ResourcesApi
        get() = management().resources()

    /**
     * The scopes operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().scopes()` (§27.2 rule 4).
     */
    val scopes: io.axiam.sdk.management.ScopesApi
        get() = management().scopes()

    /**
     * The service_accounts operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().serviceAccounts()` (§27.2 rule 4).
     */
    val serviceAccounts: io.axiam.sdk.management.ServiceAccountsApi
        get() = management().serviceAccounts()

    /**
     * The certificates operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().certificates()` (§27.2 rule 4).
     */
    val certificates: io.axiam.sdk.management.CertificatesApi
        get() = management().certificates()

    /**
     * The ca_certificates operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().caCertificates()` (§27.2 rule 4).
     */
    val caCertificates: io.axiam.sdk.management.CaCertificatesApi
        get() = management().caCertificates()

    /**
     * The pgp_keys operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().pgpKeys()` (§27.2 rule 4).
     */
    val pgpKeys: io.axiam.sdk.management.PgpKeysApi
        get() = management().pgpKeys()

    /**
     * The webhooks operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().webhooks()` (§27.2 rule 4).
     */
    val webhooks: io.axiam.sdk.management.WebhooksApi
        get() = management().webhooks()

    /**
     * The oauth2_clients operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().oauth2Clients()` (§27.2 rule 4).
     */
    val oauth2Clients: io.axiam.sdk.management.Oauth2ClientsApi
        get() = management().oauth2Clients()

    /**
     * The federation operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().federation()` (§27.2 rule 4).
     */
    val federation: io.axiam.sdk.management.FederationApi
        get() = management().federation()

    /**
     * The notification_rules operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().notificationRules()` (§27.2 rule 4).
     */
    val notificationRules: io.axiam.sdk.management.NotificationRulesApi
        get() = management().notificationRules()

    /**
     * The email_config operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().emailConfig()` (§27.2 rule 4).
     */
    val emailConfig: io.axiam.sdk.management.EmailConfigApi
        get() = management().emailConfig()

    /**
     * The settings operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().settings()` (§27.2 rule 4).
     */
    val settings: io.axiam.sdk.management.SettingsApi
        get() = management().settings()

    /**
     * The scim_tokens operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().scimTokens()` (§27.2 rule 4).
     */
    val scimTokens: io.axiam.sdk.management.ScimTokensApi
        get() = management().scimTokens()

    /**
     * The reactors operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().reactors()` (§27.2 rule 4).
     */
    val reactors: io.axiam.sdk.management.ReactorsApi
        get() = management().reactors()

    /**
     * The webauthn_policy operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().webauthnPolicy()` (§27.2 rule 4).
     */
    val webauthnPolicy: io.axiam.sdk.management.WebauthnPolicyApi
        get() = management().webauthnPolicy()

    /**
     * The audit operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().audit()` (§27.2 rule 4).
     */
    val audit: io.axiam.sdk.management.AuditApi
        get() = management().audit()

    /**
     * The privacy operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().privacy()` (§27.2 rule 4).
     */
    val privacy: io.axiam.sdk.management.PrivacyApi
        get() = management().privacy()

    /**
     * The platform operations.
     *
     * Acquiring the handle performs no I/O (§27.2 rule 1). The same handle as
     * `management().platform()` (§27.2 rule 4).
     */
    val platform: io.axiam.sdk.management.PlatformApi
        get() = management().platform()

    /**
     * The organization UUID this client can address, if one has resolved.
     *
     * The value §27.4 rule 3 interpolates into every `{org_id}` path: the
     * `orgId(...)` the client was built with, else the `org_id` claim of the
     * live access token. `null` until one of those exists — notably, before
     * [login] on a client built with an organization *slug*, since resolving a
     * slug would cost a wire call the caller did not ask for.
     *
     * Public because §27 has routes where `{org_id}` names the organization
     * being administered rather than the calling context, and those take it as
     * an ordinary argument. Without this, a caller would have no way to pass
     * the same organization the implicit routes are using.
     */
    fun resolvedOrgId(): java.util.UUID? = session.resolvedOrgId()

    /**
     * The tenant UUID this client can address, if one has resolved.
     *
     * Read from the live access token's `tenant_id` claim, so it is `null`
     * until [login] (or an OAuth2 flow) has established a session. Distinct
     * from [tenantId], which is the identifier the client was built with and is
     * a slug as often as a UUID.
     *
     * Public for the same reason as [resolvedOrgId]: on `tenants` and on the
     * signing CAs under `caCertificates`, `{tenant_id}` names the tenant being
     * administered and is an argument rather than an implicit.
     */
    fun resolvedTenantId(): java.util.UUID? = session.resolvedTenantId()

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
                200 -> {
                    val (organizationLevel, scope) = loginScopeOf(response)
                    return LoginResult(
                        mfaRequired = false,
                        user = buildUser(),
                        organizationLevel = organizationLevel,
                        scope = scope,
                    )
                }
                202 -> {
                    val wire = readJson(response)
                    val challenge = wire["challenge_token"]?.jsonPrimitive?.content ?: ""
                    return LoginResult(mfaRequired = true, challengeToken = Sensitive.of(challenge))
                }
                403 -> {
                    // CONTRACT.md §25.2 rule 1: a 403 carrying
                    // mfa_setup_required is an OUTCOME, not a refusal. The
                    // tenant requires MFA, this account has none, and the
                    // server handed back the token to finish with.
                    //
                    // Matched on the body's own discriminant rather than the
                    // status alone: a genuine authorization refusal is also a
                    // 403, and only one of the two carries a setup_token. Read
                    // with peekBody so a non-matching 403 still reaches
                    // ErrorMapper with its body intact, both for the §2 authz
                    // mapping and so a non-JSON body stays an AuthzError rather
                    // than becoming a parse failure.
                    val setupToken = readSetupToken(response)
                    if (setupToken != null) {
                        return LoginResult(
                            mfaRequired = false,
                            mfaSetupRequired = true,
                            setupToken = setupToken,
                        )
                    }
                    throw ErrorMapper.fromHttpStatus(403, "login failed", response)
                }
                else -> throw ErrorMapper.fromHttpStatus(response.code, "login failed", response)
            }
        }
    }

    /**
     * The `setup_token` from a §25.2 rule 1 `403`, or `null` when this 403 is an
     * ordinary authorization refusal.
     *
     * Non-destructive: the response body is left exactly as received.
     */
    private fun readSetupToken(response: Response): Sensitive<String>? = runCatching {
        val wire = Json.parseToJsonElement(
            response.peekBody(MAX_POLICY_PEEK_BYTES).string(),
        ).jsonObject
        val token = wire["setup_token"]?.jsonPrimitive?.contentOrNull
        val flagged = wire["mfa_setup_required"]?.jsonPrimitive?.content?.toBoolean() ?: false
        if (flagged && !token.isNullOrEmpty()) Sensitive.of(token) else null
    }.getOrNull()

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
            val (organizationLevel, scope) = loginScopeOf(response)
            return LoginResult(
                mfaRequired = false,
                user = buildUser(),
                organizationLevel = organizationLevel,
                scope = scope,
            )
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

    // ---- OPAQUE, RFC 9807 (§23) -----------------------------------------

    /**
     * `POST /api/v1/auth/opaque/login/start` followed by `/finish` — OPAQUE
     * login, RFC 9807 (CONTRACT.md §23).
     *
     * A sibling of [login], not a replacement. It takes the same arguments and
     * returns the same [LoginResult], MFA branch included, so an application
     * can switch a tenant to OPAQUE without touching its own code.
     *
     * **What this does that [login] does not.** The password never leaves this
     * process. What crosses the wire is a blinded group element and a MAC,
     * neither useful without the account's registration record *and* the
     * tenant's OPRF seed — so a TLS-terminating proxy, an accidentally verbose
     * request log, or a heap dump on the server cannot capture a plaintext
     * password, because the server never has one. It also means a stolen record
     * database is not offline-crackable on its own, which is the
     * pre-computation resistance SRP could not offer. It does **not** protect
     * against a compromised AXIAM server.
     *
     * **One round trip, and no server-proof step.** SRP had to guess a group
     * before the server named one and restart the exchange if it guessed wrong;
     * `KE1` does not depend on the key-stretching function. And where the old
     * §23.3 rule 6 had to mandate an `M2` check in capitals — because skipping
     * it kept only half the protocol — RFC 9807's AKE authenticates the server
     * during the handshake, so opening `KE2` *is* the proof that it holds the
     * record. There is nothing left to skip.
     *
     * **Cost.** Runs the tenant's key-stretching function: Argon2id at 19 MiB
     * and t=2 by default, tens to hundreds of milliseconds of CPU plus that
     * memory, per attempt. That cost is the point — it is what makes a stolen
     * record expensive to attack even by someone holding the OPRF seed. It runs
     * on [Dispatchers.Default] rather than the caller's thread.
     *
     * **When `KE2` does not open** — a wrong password, an account that does not
     * exist, an account with no registration record, or a hostile endpoint, all
     * indistinguishable by design — nothing is sent to `login/finish`, and what
     * happens next is decided by the `mode` field of the `login/start`
     * response and by nothing else (§23.4 rule 7):
     *
     * - `optional`: this call retries over [login] with the same credentials
     *   before reporting anything, and returns that call's outcome — its
     *   [LoginResult] on success, its exception on failure. Under `optional` an
     *   account with no record is the ordinary case rather than an error: every
     *   account has none the moment an operator enables OPAQUE and acquires one
     *   only when its password is next set, so treating the failed exchange as
     *   final would lock out every user of a tenant mid-migration.
     * - `required`, an unrecognised value, or **no `mode` field at all** (a
     *   server older than the field): an [AuthError], the exchange is over, and
     *   nothing is retried over [login]. `required` answers `403
     *   opaque_required` for every principal, so the retry would put a
     *   plaintext password on the wire for nothing.
     *
     * `mode` is **not** downgrade protection and must not be presented as such:
     * a hostile server that wanted the plaintext could answer `404` and get the
     * fallback whatever it put here. What closes that is server-side —
     * `required` refusing `/auth/login` before examining any credential.
     *
     * @param password the account password, as a [CharArray] so the caller can
     *   clear it; this SDK clears every copy it makes but cannot clear the
     *   caller's.
     * @throws NetworkError if the tenant has OPAQUE disabled (the endpoint
     *   answers `404` — a property of the tenant, not of any user), if
     *   `libaxiam_opaque_ffi` is not installed, or if the server names a
     *   key-stretching function this SDK cannot ask for. Deliberately not
     *   [AuthError]: reporting a configuration gap as a credential failure
     *   would send a user off to reset a password that works, and would stop a
     *   caller falling back to [login].
     * @throws AuthError for a wrong password, an account that does not exist,
     *   and a server that does not hold the record — indistinguishable by
     *   design — under `required` or a `mode`-less response; under `optional`,
     *   only if the [login] retry also fails.
     */
    suspend fun loginOpaque(usernameOrEmail: String, password: CharArray): LoginResult {
        ensureOpen()
        onCredentialChange()

        Opaque.startLogin(password).use { exchange ->
            val started = opaqueStart(
                OPAQUE_LOGIN_START_PATH,
                opaqueWorkspaceBody {
                    put("username_or_email", usernameOrEmail)
                    put("ke1", exchange.ke1)
                },
                "login/start",
            )

            val ke2 = started["ke2"]?.jsonPrimitive?.contentOrNull
                ?: throw NetworkError("OPAQUE: login/start returned no `ke2`")

            // The key-stretching function is deliberately CPU- and memory-bound;
            // keeping it off the caller's dispatcher is the difference between a
            // slow login and a stalled event loop.
            val ke3 = try {
                withContext(Dispatchers.Default) {
                    exchange.finish(password, ke2, KsfParams.fromWire(started))
                }
            } catch (failed: AuthError) {
                // §23.4 rule 7. KE2 did not open: KE3 is never sent, and what
                // happens next depends on `mode` and on nothing else. Only
                // AuthError is caught -- a NetworkError here is a KSF this
                // build cannot perform, which no password endpoint can fix.
                if (opaqueModeIsOptional(started)) {
                    return login(usernameOrEmail, String(password))
                }
                throw failed
            }

            val body = buildJsonObject {
                put("opaque_session", started["opaque_session"]?.jsonPrimitive?.content ?: "")
                put("ke3", ke3)
            }
            postJson(OPAQUE_LOGIN_FINISH_PATH, body).use { response ->
                if (response.code != 200 && response.code != 202) {
                    throw ErrorMapper.fromHttpStatus(
                        response.code,
                        "OPAQUE login/finish failed",
                        response,
                    )
                }
                if (response.code == 202) {
                    val token = readJson(response)["challenge_token"]?.jsonPrimitive?.content ?: ""
                    return LoginResult(mfaRequired = true, challengeToken = Sensitive.of(token))
                }
                val (organizationLevel, scope) = loginScopeOf(response)
                return LoginResult(
                    mfaRequired = false,
                    user = buildUser(),
                    organizationLevel = organizationLevel,
                    scope = scope,
                )
            }
        }
    }

    /**
     * Builds a registration record for [password], to send with any request
     * that sets one: `POST /api/v1/users`, `/auth/password/change`,
     * `/auth/reset/confirm` and `/admin/bootstrap`.
     *
     * The server cannot build this — it never sees the plaintext — so it has to
     * arrive with the request or not at all.
     *
     * Unlike the `srpEnrollment` it replaces this performs network I/O: one
     * `register/start` round trip. OPAQUE's envelope is sealed under the
     * server's oblivious PRF, so there is no offline computation that produces
     * a valid record.
     *
     * Note the parameters that are gone. There is no `identity`: the SRP
     * version required the account's canonical **username**, and an email there
     * produced a verifier no login could ever satisfy, whereas a record binds
     * to a credential identifier the server chooses. And there is no group or
     * KDF, because those come from the `register/start` response — a caller
     * cannot pick a cost the server will not honour.
     *
     * @throws NetworkError if the tenant has OPAQUE disabled, if
     *   `libaxiam_opaque_ffi` is not installed, or if the server names a
     *   key-stretching function this SDK cannot ask for.
     */
    suspend fun opaqueEnrollment(password: CharArray): OpaqueEnrollment =
        enroll(password, principalTenant = null)

    /**
     * Builds a registration record for the **caller's own** new password, sealed
     * against the tenant the caller's account lives in.
     *
     * CONTRACT.md §5.2.2 rule 2. `POST /auth/password/change` and the record that
     * accompanies it are about the account, not about whatever tenant the client
     * is currently pointed at, and a record sealed against the acting tenant is
     * refused with *"the OPAQUE session was issued for a different tenant"*.
     *
     * The distinction only bites for an organization-level principal that has
     * selected another tenant to act on; for everyone else the two tenants are the
     * same value and this behaves identically to [opaqueEnrollment]. It is still
     * the method to call for a self-service password change, because which
     * principal is signed in is not something the call site usually knows.
     *
     * @throws NetworkError when no login has completed on this client yet — the
     *   principal tenant is reported by the login response, so there is nothing to
     *   seal against before then — and on the same terms as [opaqueEnrollment]
     *   otherwise.
     */
    suspend fun opaqueEnrollmentForSelf(password: CharArray): OpaqueEnrollment {
        val principal = principalTenantId
            ?: throw NetworkError(
                "OPAQUE: no principal tenant is known yet — sign in before building " +
                    "a registration record for your own password",
            )
        return enroll(password, principalTenant = principal)
    }

    /**
     * The shared body of the two enrolment methods; they differ only in the tenant
     * the record is sealed against.
     */
    private suspend fun enroll(password: CharArray, principalTenant: UUID?): OpaqueEnrollment {
        ensureOpen()

        Opaque.startRegistration(password).use { exchange ->
            val started = opaqueStart(
                OPAQUE_REGISTER_START_PATH,
                opaqueWorkspaceBody(principalTenant) { put("registration_request", exchange.request) },
                "register/start",
            )
            val record = withContext(Dispatchers.Default) {
                exchange.finish(
                    password,
                    started["registration_response"]?.jsonPrimitive?.content ?: "",
                    KsfParams.fromWire(started),
                )
            }
            return OpaqueEnrollment(
                opaqueSession = started["opaque_session"]?.jsonPrimitive?.content ?: "",
                registrationRecord = record,
            )
        }
    }

    /**
     * Whether this installation can perform OPAQUE (§23.2).
     *
     * Genuinely able to answer `false`, unlike the `srpAvailable()` it replaces
     * — which was hard-coded `true` on the JVM because `BigInteger` and
     * BouncyCastle are always there. The protocol now comes from
     * `libaxiam_opaque_ffi` via JNA, and both are optional: `net.java.dev.jna:jna`
     * is `compileOnly` here, and the shared library is a per-platform release
     * asset rather than a Maven artifact. Ask before a login rather than
     * discovering the gap mid-exchange.
     */
    fun opaqueAvailable(): Boolean = Opaque.available()

    /**
     * Whether a `login/start` response says the tenant's `opaque_mode` is
     * `optional` — the only question §23.4 rule 7 asks of the `mode` field.
     *
     * `mode` is optional on the wire and is read as a nullable string: a server
     * older than the field sends none, and absence is treated exactly as
     * `"required"`. Any value this SDK does not recognise is treated the same
     * way, so a newer or a garbled mode fails closed rather than putting a
     * plaintext password on the wire.
     */
    private fun opaqueModeIsOptional(started: JsonObject): Boolean =
        started["mode"]?.jsonPrimitive?.contentOrNull == OPAQUE_MODE_OPTIONAL

    /**
     * Sends one of the two `/start` requests and returns the parsed response.
     *
     * Shared by both OPAQUE paths so the meaning of a failure cannot drift
     * between them. A `404` is a property of the tenant ("OPAQUE is off here"),
     * not of the user and not of the credentials — so it is a [NetworkError] a
     * caller can fall back on, never an [AuthError] that would be shown as
     * "invalid password".
     */
    private suspend fun opaqueStart(path: String, body: JsonObject, what: String): JsonObject {
        postJson(path, body).use { response ->
            if (response.code == 404) {
                throw NetworkError(
                    "OPAQUE: this tenant does not offer OPAQUE " +
                        "(opaque_mode is disabled); use login() instead",
                )
            }
            if (response.code != 200) {
                throw ErrorMapper.fromHttpStatus(response.code, "OPAQUE $what failed", response)
            }
            return readJson(response)
        }
    }

    /**
     * The tenant/org fields every OPAQUE request carries, plus whatever the
     * caller adds.
     *
     * Same workspace resolution as the password login, so the two paths cannot
     * drift — and no `password` field anywhere, which is the entire point of
     * the exchange. `register/start` adds no username either: enrolment binds
     * to a credential identifier the server chooses, which is why a later
     * rename cannot invalidate a credential.
     */
    private fun opaqueWorkspaceBody(
        principalTenant: UUID? = null,
        extra: JsonObjectBuilder.() -> Unit,
    ): JsonObject =
        buildJsonObject {
            if (principalTenant == null) {
                put("tenant_slug", tenantId)
            } else {
                // §5.2.2 rule 2: name the principal tenant by id, and do NOT also
                // send the slug. A slug naming the acting tenant would out-vote
                // the id server-side, which is the exact confusion this override
                // exists to avoid.
                put("tenant_id", principalTenant.toString())
            }
            session.configuredOrgId()?.let { put("org_id", it.toString()) }
                ?: session.configuredOrgSlug()?.let { put("org_slug", it) }
            extra()
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
     * `GET /api/v1/auth/federation/providers` (§12.1, contract 1.38) — which
     * "Sign in with X" buttons to render.
     *
     * An **empty list is a success**: an unknown organization, a known one
     * with nothing configured, and a request naming no workspace at all all
     * answer that way (§12.1 note 9), so the endpoint cannot be used to
     * enumerate organization or tenant slugs.
     */
    suspend fun ssoProviders(params: SsoProvidersParams = SsoProvidersParams()): FederationProviderList =
        oidcSupport.ssoProviders(params)

    /**
     * `POST /api/v1/auth/federation/oauth2/start` (§12.1, contract 1.38) —
     * step 1 through a plain-OAuth2 upstream. Call this, rather than
     * [ssoStart], exactly when the provider's `protocol` is [PROTOCOL_OAUTH2]
     * (§12.1 note 10). PKCE here is server-side (§12.1 note 11).
     */
    suspend fun ssoStartOauth2(params: SsoStartOauth2Params): SsoStartResult =
        oidcSupport.ssoStartOauth2(params)

    /**
     * `POST /api/v1/auth/federation/oauth2/callback` (§12.1, contract 1.38) —
     * step 2 of a plain-OAuth2 login; the session arrives as `Set-Cookie`.
     */
    suspend fun ssoCompleteOauth2(params: SsoCompleteOauth2Params): SsoCompleteResult =
        oidcSupport.ssoCompleteOauth2(params)

    /**
     * `POST /api/v1/auth/federation/handoff` (§12.1, contract 1.38) — redeem
     * the single-use `axiam_handoff` code the SAML and Apple flows deliver.
     * Valid 60 s, redeemable once; a `401` is terminal and is never retried.
     */
    suspend fun ssoCompleteHandoff(params: SsoCompleteHandoffParams): SsoCompleteResult =
        oidcSupport.ssoCompleteHandoff(params)

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

    // ---- §24 WebAuthn / passkeys — the relying-party layer ---------------
    //
    // The JVM has no authenticator, so §24.6b's linked-API helper is
    // deliberately absent: rule 2 forbids emulating one in software, and a
    // "credential" held in process memory is not a second factor. What is here
    // is the half that talks to AXIAM, plus §24.6a's JSON bridge — which is
    // exactly what lets an Android app pass requestJson straight into
    // CreatePublicKeyCredentialRequest and the response straight back, without
    // this artifact linking a single Android class.

    /**
     * `POST /api/v1/auth/webauthn/register/start` (CONTRACT.md §24.1) — begin
     * enrolling a passkey for the signed-in user.
     *
     * Requires a session, and refuses **client-side with no wire call** when
     * there is none — the shape §1.1 rule 3 requires of `getUserInfo`.
     *
     * The returned options are the server's, untouched (§24.0). A `503` here
     * means the tenant's attestation policy needs FIDO metadata the server
     * cannot reach: a configuration state, not a transient one, and §24.4
     * rule 2 deliberately does not retry it.
     */
    suspend fun webauthnRegisterStart(): WebauthnChallenge {
        ensureOpen()
        requireWebauthnSession("webauthnRegisterStart")
        return webauthnStart(WEBAUTHN_REGISTER_START_PATH, JsonObject(emptyMap()))
    }

    /**
     * `POST /api/v1/auth/webauthn/register/finish` (CONTRACT.md §24.1) — hand
     * the authenticator's answer back and store the credential.
     *
     * [response] is the platform's own response JSON, **verbatim** (§24.6a
     * rule 2): `registrationResponseJson` from Android's Credential Manager, or
     * `credential.toJSON()` from a browser. It reaches the wire byte for byte,
     * because re-encoding a signed buffer is three chances to corrupt it in
     * service of nothing.
     */
    suspend fun webauthnRegisterFinish(
        stateToken: Sensitive<String>,
        credentialName: String,
        response: String,
    ): WebauthnCredential {
        ensureOpen()
        requireWebauthnSession("webauthnRegisterFinish")

        val body = webauthnFinishBody(
            stateToken,
            response,
            "webauthnRegisterFinish",
            extraFields = mapOf("credential_name" to credentialName),
        )
        postRawJson(WEBAUTHN_REGISTER_FINISH_PATH, body).use { http ->
            if (http.code != 200 && http.code != 201) {
                throw registerFinishError(http)
            }
            val wire = readJson(http)
            return WebauthnCredential(
                id = UUID.fromString(wire.str("id")),
                credentialId = wire.str("credential_id"),
                name = wire.str("name"),
                credentialType = wire.str("credential_type"),
                createdAt = wire.str("created_at"),
                lastUsedAt = wire["last_used_at"]?.jsonPrimitive?.contentOrNull,
            )
        }
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/start` (CONTRACT.md §24.1) —
     * begin the **second-factor** ceremony.
     *
     * Continues a [login] that answered `mfaRequired` with `"webauthn"` among
     * its available methods; [challengeToken] is that login's token. A
     * different flow from [webauthnDiscoverableStart], not the same one with a
     * flag (§24.2) — which is why the token is required here and absent there.
     */
    suspend fun webauthnAuthenticateStart(challengeToken: Sensitive<String>): WebauthnChallenge {
        ensureOpen()
        val body = buildJsonObject { put("challenge_token", challengeToken.expose()) }
        return webauthnStart(WEBAUTHN_AUTH_START_PATH, body)
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/finish` (CONTRACT.md §24.1).
     *
     * On success the client is signed in: the server sets the same cookie
     * triple `POST /api/v1/auth/login` sets, and the §17 decision memo is
     * cleared because the subject changed (§24.3).
     */
    suspend fun webauthnAuthenticateFinish(
        stateToken: Sensitive<String>,
        response: String,
    ): WebauthnLoginResult =
        webauthnFinish(WEBAUTHN_AUTH_FINISH_PATH, stateToken, response, "webauthnAuthenticateFinish")

    /**
     * `POST /api/v1/auth/webauthn/authenticate/discoverable/start`
     * (CONTRACT.md §24.1) — begin the usernameless ceremony.
     *
     * A **primary factor**: nothing precedes it, `allowCredentials` comes back
     * empty, and the assertion itself identifies the user. Pass `null` for
     * [workspace] to have it filled from this client's own configured identity.
     *
     * Unlike `authenticate/finish`, `discoverable/finish` fires the
     * `login.post_auth` reactor hook (§22.5) — the latter continues a login
     * already gated at its password step, and this one has no such step.
     */
    suspend fun webauthnDiscoverableStart(workspace: WebauthnWorkspace? = null): WebauthnChallenge {
        ensureOpen()
        return webauthnStart(WEBAUTHN_DISCOVERABLE_START_PATH, webauthnWorkspaceBody(workspace))
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/discoverable/finish`
     * (CONTRACT.md §24.1). Adopts credentials exactly as
     * [webauthnAuthenticateFinish] does.
     */
    suspend fun webauthnDiscoverableFinish(
        stateToken: Sensitive<String>,
        response: String,
    ): WebauthnLoginResult =
        webauthnFinish(WEBAUTHN_DISCOVERABLE_FINISH_PATH, stateToken, response, "webauthnDiscoverableFinish")

    /** Run either `*_start` call and return the options untouched. */
    private suspend fun webauthnStart(path: String, body: JsonObject): WebauthnChallenge {
        postJson(path, body).use { http ->
            if (http.code != 200) {
                throw ErrorMapper.fromHttpStatus(http.code, "webauthn start failed", http)
            }
            val wire = readJson(http)
            return WebauthnChallenge(
                challenge = wire["challenge"]?.jsonObject ?: JsonObject(emptyMap()),
                stateToken = Sensitive.of(wire.str("state_token")),
            )
        }
    }

    /** The shared tail of both authentication ceremonies. */
    private suspend fun webauthnFinish(
        path: String,
        stateToken: Sensitive<String>,
        response: String,
        operation: String,
    ): WebauthnLoginResult {
        ensureOpen()
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and
        // this call changes the subject.
        onCredentialChange()

        val body = webauthnFinishBody(stateToken, response, operation)
        postRawJson(path, body).use { http ->
            if (http.code != 200) {
                throw ErrorMapper.fromHttpStatus(http.code, "$operation failed", http)
            }
            val wire = readJson(http)
            return WebauthnLoginResult(
                accessToken = Sensitive.of(wire.str("access_token")),
                refreshToken = Sensitive.of(wire.str("refresh_token")),
                sessionId = UUID.fromString(wire.str("session_id")),
                expiresIn = wire["expires_in"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L,
            )
        }
    }

    /**
     * Build a `*_finish` body **as text**, splicing the caller's response JSON
     * in verbatim (§24.0, §24.6a rule 2).
     *
     * Parsing the string into a [JsonObject] and re-serializing would round
     * every number, drop nothing but reorder nothing predictably, and generally
     * hand the server a byte sequence the authenticator never signed. The one
     * thing this does check is that the string IS a JSON object — the SDK will
     * not POST a body it already knows the server cannot verify.
     */
    private fun webauthnFinishBody(
        stateToken: Sensitive<String>,
        response: String,
        operation: String,
        extraFields: Map<String, String> = emptyMap(),
    ): String {
        val trimmed = response.trim()
        val parsed = try {
            Json.parseToJsonElement(trimmed)
        } catch (e: Exception) {
            throw AuthError(
                "$operation: the authenticator response string is not valid JSON. Pass the " +
                    "platform's response JSON verbatim (CONTRACT.md §24.6a).",
            )
        }
        if (parsed !is JsonObject) {
            throw AuthError(
                "$operation: the authenticator response must be a JSON object " +
                    "(CONTRACT.md §24.6a).",
            )
        }
        return buildString {
            append('{')
            appendJsonString(this, "state_token", stateToken.expose())
            for ((key, value) in extraFields) {
                append(',')
                appendJsonString(this, key, value)
            }
            append(",\"response\":")
            append(trimmed)
            append('}')
        }
    }

    /**
     * §24.1: `register/...` needs a session, and the refusal is raised
     * client-side with **no wire call**.
     *
     * The signal is the cached access token rather than a separate flag: this
     * SDK has never kept one, and a second source of truth for "am I signed in"
     * is a second thing to get out of step with the jar.
     */
    private fun requireWebauthnSession(operation: String) {
        if (session.cachedAccessToken() == null) {
            throw AuthError(
                "$operation requires an authenticated session: enrol a passkey while signed in " +
                    "(CONTRACT.md §24.1).",
            )
        }
    }

    /**
     * §24.4 rule 1: the `403` from `register/finish` is the one whose *body*
     * matters.
     *
     * The generic §2 mapping would raise an authorization error reading
     * "webauthnRegisterFinish failed", which tells the person holding the key
     * nothing they can act on. The tenant's attestation policy rejected *this*
     * authenticator, and the server's message is the only place that says which
     * one would be accepted.
     */
    private fun registerFinishError(http: Response): Throwable {
        var message = "webauthnRegisterFinish failed"
        if (http.code == 403) {
            val policy = runCatching {
                Json.parseToJsonElement(http.peekBody(MAX_POLICY_PEEK_BYTES).string())
                    .jsonObject["message"]?.jsonPrimitive?.contentOrNull
            }.getOrNull()
            if (!policy.isNullOrEmpty()) message = "$message: $policy"
        }
        return ErrorMapper.fromHttpStatus(http.code, message, http)
    }

    /**
     * Fill the discoverable ceremony's workspace from this client's own
     * configuration when the caller passed none.
     *
     * Only fields that actually have a value are emitted: the server takes
     * either form at either level, and sending `null` for the ones it does not
     * have is indistinguishable from asking it to resolve nothing.
     */
    private fun webauthnWorkspaceBody(workspace: WebauthnWorkspace?): JsonObject = buildJsonObject {
        var orgId = workspace?.orgId
        var orgSlug = workspace?.orgSlug
        if (orgId == null && orgSlug == null) {
            orgId = session.configuredOrgId()
            orgSlug = session.configuredOrgSlug()
        }
        when {
            orgId != null -> put("org_id", orgId.toString())
            orgSlug != null -> put("org_slug", orgSlug)
            else -> throw AuthError(
                "webauthnDiscoverableStart needs an organization: construct the client with one, " +
                    "or pass it in the workspace argument (CONTRACT.md §24.1).",
            )
        }
        val tenantUuid = workspace?.tenantId
        if (tenantUuid != null) {
            put("tenant_id", tenantUuid.toString())
        } else {
            put("tenant_slug", workspace?.tenantSlug ?: tenantId)
        }
    }

    // ---- §25 Account lifecycle and MFA enrolment -------------------------

    /**
     * `POST /api/v1/auth/mfa/enroll` (CONTRACT.md §25.1) — start voluntary TOTP
     * enrolment for the signed-in user.
     *
     * Changes nothing about the current session. In particular it does **not**
     * clear the §17 decision memo: the subject has not changed, and discarding
     * a warm memo on an unrelated profile action costs a round trip on every
     * check that follows (§25.2 rule 3).
     */
    suspend fun mfaEnroll(): MfaEnrollment {
        ensureOpen()
        postJson(MFA_ENROLL_PATH, JsonObject(emptyMap())).use { http ->
            return readMfaEnrollment(http, "mfaEnroll")
        }
    }

    /**
     * `POST /api/v1/auth/mfa/confirm` (CONTRACT.md §25.1) — activate the factor
     * [mfaEnroll] offered. Returns whether MFA is now enabled.
     */
    suspend fun mfaConfirm(totpCode: String): Boolean {
        ensureOpen()
        val body = buildJsonObject { put("totp_code", totpCode) }
        postJson(MFA_CONFIRM_PATH, body).use { http ->
            if (http.code != 200) {
                throw ErrorMapper.fromHttpStatus(http.code, "mfaConfirm failed", http)
            }
            return readJson(http)["mfa_enabled"]?.jsonPrimitive?.content?.toBoolean() ?: false
        }
    }

    /**
     * `POST /api/v1/auth/mfa/setup/enroll` (CONTRACT.md §25.1) — start the
     * enrolment a [login] demanded.
     *
     * Reached when `login()` returns [LoginResult.mfaSetupRequired]: the tenant
     * requires MFA and this account has none. There is no session yet — the
     * setup token *is* the credential.
     */
    suspend fun mfaSetupEnroll(setupToken: Sensitive<String>): MfaEnrollment {
        ensureOpen()
        val body = buildJsonObject { put("setup_token", setupToken.expose()) }
        postJson(MFA_SETUP_ENROLL_PATH, body).use { http ->
            return readMfaEnrollment(http, "mfaSetupEnroll")
        }
    }

    /**
     * `POST /api/v1/auth/mfa/setup/confirm` (CONTRACT.md §25.1) — finish forced
     * enrolment and, with it, the login that was interrupted.
     *
     * Adopts credentials exactly as [login] does, because it *is* the
     * completion of a login (§25.2 rule 2).
     */
    suspend fun mfaSetupConfirm(setupToken: Sensitive<String>, totpCode: String): LoginResult {
        ensureOpen()
        onCredentialChange()
        val body = buildJsonObject {
            put("setup_token", setupToken.expose())
            put("totp_code", totpCode)
        }
        postJson(MFA_SETUP_CONFIRM_PATH, body).use { http ->
            if (http.code != 200) {
                throw ErrorMapper.fromHttpStatus(http.code, "mfaSetupConfirm failed", http)
            }
            val (organizationLevel, scope) = loginScopeOf(http)
            return LoginResult(
                mfaRequired = false,
                user = buildUser(),
                organizationLevel = organizationLevel,
                scope = scope,
            )
        }
    }

    /**
     * `POST /api/v1/auth/verify-email` (CONTRACT.md §25.1).
     *
     * Unauthenticated: a user whose address is unverified may have no session
     * at all. [tenantId] is a **body** field here — this is not an `/oauth2/...`
     * endpoint, so §12.1 rule 2's query-parameter convention does not reach it.
     */
    suspend fun verifyEmail(token: Sensitive<String>, tenantId: UUID) {
        ensureOpen()
        val body = buildJsonObject {
            put("token", token.expose())
            put("tenant_id", tenantId.toString())
        }
        postExpectingNoContent(VERIFY_EMAIL_PATH, body, "verifyEmail")
    }

    /**
     * `POST /api/v1/auth/resend-verification` (CONTRACT.md §25.1) — the
     * **unauthenticated** resend, for a caller with no session.
     *
     * **Returns normally whatever the outcome.** The address may not exist, may
     * already be verified, or may be over the daily limit, and this answers
     * identically in all of them, because it takes an address from an anonymous
     * caller and anything else is an oracle for which addresses have accounts
     * (§25.7).
     *
     * A caller that *is* signed in wants [resendOwnVerification], which says
     * which of those happened. Do not reach for this one because it is the name
     * you already knew.
     */
    suspend fun resendVerification(email: String, tenantId: UUID) {
        ensureOpen()
        val body = buildJsonObject {
            put("email", email)
            put("tenant_id", tenantId.toString())
        }
        postExpectingNoContent(RESEND_VERIFICATION_PATH, body, "resendVerification")
    }

    /**
     * `POST /api/v1/users/me/resend-verification` (CONTRACT.md §25.1, §25.7) —
     * resends the **signed-in caller's own** verification mail, and says what
     * happened.
     *
     * Takes no address. The server reads it off the caller's own record, and
     * this signature deliberately offers no way to name a different one: a
     * parameter here would let an authenticated session mail an arbitrary
     * address.
     *
     * Unlike [resendVerification] this reports the outcome, because the caller
     * is signed in to the account it is asking about and none of the outcomes
     * tells it anything it did not already know:
     *
     * - returns — a token was minted and the mail **enqueued**. Delivery is
     *   asynchronous and can still fail at the provider; a queue that accepts
     *   everything in front of one that rejects it looks exactly like this
     *   succeeding.
     * - [io.axiam.sdk.errors.AuthzError] (from `409`) — already verified, or the
     *   account is in a state that must not be sent a live token.
     * - [io.axiam.sdk.errors.NetworkError] (from `429`) — the daily resend limit.
     *
     * §25.7 rule 2 forbids falling back to the unauthenticated endpoint on
     * either of those, and this SDK does not: the fallback would turn both
     * failures back into a normal return and restore the bug this operation
     * exists to fix, with an extra round-trip.
     */
    suspend fun resendOwnVerification() {
        ensureOpen()
        postExpectingNoContent(
            RESEND_OWN_VERIFICATION_PATH,
            buildJsonObject { },
            "resendOwnVerification",
        )
    }

    /**
     * `POST /api/v1/auth/reset` (CONTRACT.md §25.1) — ask for a reset mail.
     *
     * **Returns normally whether or not the address exists**, and this SDK
     * exposes no way to tell the two apart. That is not an omission to improve
     * on: a client that surfaced a "no such user" state — even one inferred
     * from timing — would turn the endpoint into the account-enumeration oracle
     * its uniform response exists to prevent (§25.4).
     */
    suspend fun requestPasswordReset(request: PasswordResetRequest) {
        ensureOpen()
        val body = buildJsonObject {
            put("email", request.email)
            (request.orgSlug ?: session.configuredOrgSlug())?.let { put("org_slug", it) }
            if (request.tenantId != null) {
                put("tenant_id", request.tenantId.toString())
            } else {
                put("tenant_slug", request.tenantSlug ?: tenantId)
            }
        }
        postExpectingNoContent(RESET_PATH, body, "requestPasswordReset")
    }

    /**
     * `GET /api/v1/auth/reset/context` (CONTRACT.md §25.1) — the OPAQUE policy
     * for the account a reset token belongs to.
     *
     * Call this before [confirmPasswordReset] on any tenant that might have §23
     * enabled: the client has to build a registration record, and building one
     * needs parameters it cannot know before it has a token to ask with.
     * Sending a plaintext password to a tenant in `opaque_mode: required` is
     * refused, and refused late (§25.4 rule 1).
     *
     * A `404` means unknown, expired **or** already-consumed, deliberately
     * without distinguishing them; this SDK does not distinguish them either
     * (§25.4 rule 3).
     */
    suspend fun passwordResetContext(token: Sensitive<String>): PasswordResetContext {
        ensureOpen()
        val url = (baseUrl + RESET_CONTEXT_PATH).toHttpUrlOrNull()
            ?.newBuilder()
            // Through the URL builder, never string concatenation: a token
            // spliced onto "?token=" is percent-escaped into the PATH, which
            // 404s in a way that reads exactly like an expired token.
            ?.addQueryParameter("token", token.expose())
            ?.build()
            ?: throw NetworkError("invalid base URL for the password-reset context call")

        val request = Request.Builder().url(url).get().build()
        val http = withContext(Dispatchers.IO) {
            try {
                httpClient.newCall(request).execute()
            } catch (e: IOException) {
                throw NetworkError("passwordResetContext request failed: ${e.message}", e)
            }
        }
        http.use {
            if (it.code != 200) {
                throw ErrorMapper.fromHttpStatus(it.code, "passwordResetContext failed", it)
            }
            return PasswordResetContext(opaque = readJson(it)["opaque"] as? JsonObject)
        }
    }

    /**
     * `POST /api/v1/auth/reset/confirm` (CONTRACT.md §25.1) — set the new
     * password.
     */
    suspend fun confirmPasswordReset(confirmation: PasswordResetConfirmation) {
        ensureOpen()
        val body = buildJsonObject {
            put("token", confirmation.token.expose())
            put("new_password", confirmation.newPassword.expose())
            put("tenant_id", confirmation.tenantId.toString())
            confirmation.opaque?.let { put("opaque", it) }
        }
        postExpectingNoContent(RESET_CONFIRM_PATH, body, "confirmPasswordReset")
    }

    private fun readMfaEnrollment(http: Response, operation: String): MfaEnrollment {
        if (http.code != 200) {
            throw ErrorMapper.fromHttpStatus(http.code, "$operation failed", http)
        }
        val wire = readJson(http)
        return MfaEnrollment(
            secretBase32 = Sensitive.of(wire.str("secret_base32")),
            totpUri = Sensitive.of(wire.str("totp_uri")),
        )
    }

    private suspend fun postExpectingNoContent(path: String, body: JsonObject, operation: String) {
        postJson(path, body).use { http ->
            if (http.code != 200 && http.code != 202 && http.code != 204) {
                throw ErrorMapper.fromHttpStatus(http.code, "$operation failed", http)
            }
        }
    }

    // ---- §26 Pushed Authorization Requests (RFC 9126) --------------------

    /**
     * `POST /oauth2/par` (CONTRACT.md §26.1) — push the authorization request
     * over the back channel and get an opaque handle to redirect with.
     *
     * PAR moves the authorization request off the browser. Instead of putting
     * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the
     * user agent carries, the client POSTs them straight to AXIAM over an
     * authenticated channel and puts an opaque `request_uri` in the redirect.
     * What travels through the browser is then a random string that cannot be
     * edited into meaning something else.
     *
     * **Required for a FAPI 2.0 client**: `profile: "fapi2"` refuses a
     * registration that does not set `require_par`, so such a client cannot
     * authorize any other way (§21.1).
     */
    suspend fun oidcPar(params: OidcParParams): PushedAuthorizationRequest = oidcSupport.oidcPar(params)

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

    /**
     * The §5.2 flag and the §5.2.2/§5.2.3 scope, read off a completed login
     * response in one pass.
     *
     * One method rather than two because [readJson] consumes the response body:
     * a second `...Of(response)` pass would find an empty stream and answer
     * `false` for every login.
     *
     * @property organizationLevel absent means `false`, which is what a server
     *   older than contract 1.31 answers and the safe direction in both cases:
     *   the client then offers no cross-tenant action rather than one that would
     *   `403`. Derived server-side and response-only — this SDK never sends it.
     * @property scope `null` when the server reports none of §5.2.2/§5.2.3, which
     *   is what a server older than contract 1.34 does.
     */
    private data class LoginScope(
        val organizationLevel: Boolean,
        val scope: PrincipalScope?,
    )

    /**
     * Reads [LoginScope] off a completed login response and caches the principal
     * tenant for [opaqueEnrollmentForSelf].
     *
     * §5.2.2 rule 1's fallback is applied here rather than left to the caller: an
     * absent `principal_tenant_id` means **equal** to the acting tenant, not
     * unknown, and that is the whole point of the field.
     */
    private fun loginScopeOf(response: Response): LoginScope {
        val user = readJson(response)["user"]?.jsonObject
            ?: return LoginScope(false, null)

        val organizationLevel =
            user["organization_level"]?.jsonPrimitive?.booleanOrNull ?: false

        val acting = user.uuidOrNull("tenant_id")
        val principal = user.uuidOrNull("principal_tenant_id") ?: acting
        val principalSlug = user["principal_tenant_slug"]?.jsonPrimitive?.contentOrNull
        val orgId = user.uuidOrNull("org_id")
        // A present-but-empty list stays null: it would read as "reaches nothing",
        // the opposite of what an omitted field means here (§5.2.3).
        val reachable = (user["reachable_tenant_ids"] as? JsonArray)
            ?.mapNotNull { runCatching { UUID.fromString(it.jsonPrimitive.content) }.getOrNull() }
            ?.takeIf { it.isNotEmpty() }

        if (acting == null && principal == null && principalSlug == null &&
            orgId == null && reachable == null
        ) {
            return LoginScope(organizationLevel, null)
        }

        principalTenantId = principal
        return LoginScope(
            organizationLevel,
            PrincipalScope(acting, principal, principalSlug, orgId, reachable),
        )
    }

    /** A [UUID] from a JSON property, or `null` when absent or unparseable. */
    private fun JsonObject.uuidOrNull(name: String): UUID? =
        this[name]?.jsonPrimitive?.contentOrNull
            ?.let { runCatching { UUID.fromString(it) }.getOrNull() }

    private fun buildUser(): AxiamUser {
        val access = session.cachedAccessToken()
            ?: throw AuthError("login succeeded but no access token was set")
        val claims = SessionState.decodeUnverifiedClaims(access)
        if (claims?.sub == null || claims.tenantId == null) {
            throw AuthError("failed to decode access token claims after login")
        }
        return AxiamUser(claims.sub, claims.tenantId, claims.roles)
    }

    /**
     * POST a body that is already JSON **text**, so the caller's bytes reach
     * the wire unmodified (§24.0).
     */
    private suspend fun postRawJson(path: String, body: String): Response = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(baseUrl + path).post(body.toRequestBody(JSON_MEDIA)).build()
        try {
            httpClient.newCall(request).execute()
        } catch (e: IOException) {
            throw NetworkError("request failed: ${e.message}", e)
        }
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
        fun orgSlug(slug: String) = apply {
            // §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug. Nothing
            // can carry one, so it resolves nothing and the server answers a
            // generic refusal that says nothing about which half was wrong.
            // `tenantId` is already checked in `builder(baseUrl, tenantId)`;
            // this closes the other slug.
            if (slug.isBlank()) {
                throw AuthError(
                    "orgSlug must not be blank — omit it entirely, or name the organization (§5.1, §5.2.1)",
                )
            }
            orgSlug = slug
            orgId = null
        }

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
        private const val OPAQUE_REGISTER_START_PATH = "/api/v1/auth/opaque/register/start"
        private const val OPAQUE_LOGIN_START_PATH = "/api/v1/auth/opaque/login/start"
        private const val OPAQUE_LOGIN_FINISH_PATH = "/api/v1/auth/opaque/login/finish"

        /**
         * The one `mode` value in a `login/start` response that changes what
         * this SDK does after a failed `KE2` (§23.4 rule 7). Never `"disabled"`
         * — that tenant answers `404`.
         */
        private const val OPAQUE_MODE_OPTIONAL = "optional"

        private const val LOGOUT_PATH = "/api/v1/auth/logout"
        private const val WEBAUTHN_REGISTER_START_PATH = "/api/v1/auth/webauthn/register/start"
        private const val WEBAUTHN_REGISTER_FINISH_PATH = "/api/v1/auth/webauthn/register/finish"
        private const val WEBAUTHN_AUTH_START_PATH = "/api/v1/auth/webauthn/authenticate/start"
        private const val WEBAUTHN_AUTH_FINISH_PATH = "/api/v1/auth/webauthn/authenticate/finish"
        private const val WEBAUTHN_DISCOVERABLE_START_PATH =
            "/api/v1/auth/webauthn/authenticate/discoverable/start"
        private const val WEBAUTHN_DISCOVERABLE_FINISH_PATH =
            "/api/v1/auth/webauthn/authenticate/discoverable/finish"

        private const val MFA_ENROLL_PATH = "/api/v1/auth/mfa/enroll"
        private const val MFA_CONFIRM_PATH = "/api/v1/auth/mfa/confirm"
        private const val MFA_SETUP_ENROLL_PATH = "/api/v1/auth/mfa/setup/enroll"
        private const val MFA_SETUP_CONFIRM_PATH = "/api/v1/auth/mfa/setup/confirm"
        private const val VERIFY_EMAIL_PATH = "/api/v1/auth/verify-email"
        private const val RESEND_VERIFICATION_PATH = "/api/v1/auth/resend-verification"
        private const val RESEND_OWN_VERIFICATION_PATH = "/api/v1/users/me/resend-verification"
        private const val RESET_PATH = "/api/v1/auth/reset"
        private const val RESET_CONTEXT_PATH = "/api/v1/auth/reset/context"
        private const val RESET_CONFIRM_PATH = "/api/v1/auth/reset/confirm"

        private const val CHECK_PATH = "/api/v1/authz/check"
        private const val BATCH_CHECK_PATH = "/api/v1/authz/check/batch"

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

        /** Only the first few KB of a §24.4 rule 1 attestation-policy body are read. */
        private const val MAX_POLICY_PEEK_BYTES = 8192L

        /** Reads a required string field, or `""` when the server omitted it. */
        private fun JsonObject.str(key: String): String =
            this[key]?.jsonPrimitive?.contentOrNull ?: ""

        /** Appends `"key":"value"` with both halves properly JSON-escaped. */
        private fun appendJsonString(sink: StringBuilder, key: String, value: String) {
            sink.append(JsonPrimitive(key).toString())
            sink.append(':')
            sink.append(JsonPrimitive(value).toString())
        }

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
