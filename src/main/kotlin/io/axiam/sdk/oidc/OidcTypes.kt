package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive

// Public types for the OIDC / SSO relying-party helpers (CONTRACT.md §12.1).
//
// Naming convention used throughout — deliberate, and kept identical to the
// TypeScript/Go/Python reference ports so the family of implementations stays
// legible as one:
//
//   * Types that ARE a protocol document keep their wire spelling in
//     snake_case: [OidcConfiguration] (the OIDC Discovery 1.0 metadata
//     document) and `IdTokenClaims` (JWT claims, in OidcIdToken.kt). A caller
//     cross-references these field names against OIDC Core / RFC 8414, so
//     renaming them would be a lossy translation.
//   * Types that are an SDK-shaped RESULT use this SDK's normal camelCase
//     public-API convention: [OidcTokenSet], [IntrospectionResult],
//     [AuthorizationRequest], [SsoStartResult], [SsoCompleteResult]. These are
//     not verbatim wire objects — they carry [Sensitive]-wrapped fields and
//     derived data (`idClaims`) the wire body does not have.
//
// The five §12.5 secret fields — `access_token`, `refresh_token`, `id_token`,
// `client_secret`, `code_verifier` — are `Sensitive<String>` wherever they
// appear below. `state` and `nonce` are NOT secrets (§12.3 rule 2) and are
// plain strings.

/**
 * The OIDC Discovery 1.0 metadata document served by
 * `GET /.well-known/openid-configuration` (wire schema `OidcDiscoveryDocument`).
 * Every field is required by the server's schema.
 *
 * `issuer` is the AUTHORITATIVE issuer for ID-token validation (CONTRACT.md
 * §12.4 rule 3). It may legitimately differ from the client's own base URL
 * when AXIAM runs behind a proxy, so this SDK never rejects a document on an
 * issuer/base-URL mismatch (§12.3 rule 6). Likewise `jwks_uri` is read from
 * here rather than hardcoded.
 */
data class OidcConfiguration(
    /** The authorization server's issuer identifier — the value an ID token's `iss` claim must equal exactly. */
    val issuer: String,
    /** The authorization endpoint `oidcBegin` builds its redirect URL from. */
    val authorization_endpoint: String,
    /** The token endpoint used by `oidcExchange`, `oidcRefresh`, and `loginClientCredentials`. */
    val token_endpoint: String,
    /** The userinfo endpoint. Advertised by the server but deliberately NEVER called by this SDK (§12.3 rule 5). */
    val userinfo_endpoint: String,
    /** URI of the JWKS document whose keys verify ID-token signatures (§12.4 rule 2). */
    val jwks_uri: String,
    /** The RFC 7009 revocation endpoint used by `revoke`. */
    val revocation_endpoint: String,
    /** The RFC 7662 introspection endpoint used by `introspect`. */
    val introspection_endpoint: String,
    /** OAuth2 `response_type` values the server supports. */
    val response_types_supported: List<String>,
    /** Subject identifier types the server supports. */
    val subject_types_supported: List<String>,
    /** ID-token signing algorithms the server advertises. Informational only: §12.4 rule 1 pins verification to `EdDSA` regardless of what appears here. */
    val id_token_signing_alg_values_supported: List<String>,
    /** Scopes the server supports. */
    val scopes_supported: List<String>,
    /** Client-authentication methods the token endpoint supports (`client_secret_post`, §12.1 note 3). */
    val token_endpoint_auth_methods_supported: List<String>,
    /** Claims the server may include in an ID token. */
    val claims_supported: List<String>,
    /** Grant types the token endpoint supports. */
    val grant_types_supported: List<String>,
)

/**
 * The result of `oidcBegin` — everything the caller needs to start an
 * authorization-code + PKCE login (CONTRACT.md §12.1).
 *
 * **The caller owns this state** (§12.3 rule 1). The SDK stores nothing: it
 * keeps no copy of [state], [nonce], or [codeVerifier] in process-global state
 * or any implicit cache. Persist all three in your own HTTP session — or use
 * [MemoryOidcStateStore] together with [io.axiam.sdk.ktor.axiamOidcLogin] —
 * redirect the browser to [url], and pass [nonce] + [codeVerifier] back into
 * `oidcExchange` when the code arrives.
 *
 * @property url the fully-built authorization URL to redirect the browser to
 * @property state CSPRNG CSRF value (≥128 bits, base64url unpadded) to compare against the `state` the IdP returns. Not a secret (§12.3 rule 2)
 * @property nonce CSPRNG replay-protection value (≥128 bits) that must equal the ID token's `nonce` claim. Not a secret (§12.3 rule 2)
 * @property codeVerifier the PKCE verifier, secret for its whole lifetime (§12.5). Pass it back into `oidcExchange`
 */
data class AuthorizationRequest(
    val url: String,
    val state: String,
    val nonce: String,
    val codeVerifier: Sensitive<String>,
)

/** Arguments to `oidcBegin` (pure local computation — no network I/O). */
data class OidcBeginParams(
    /** The discovery document, as returned by `oidcDiscover`. `authorization_endpoint` is taken from it and never hardcoded (§12.1 rule 5). */
    val configuration: OidcConfiguration,
    /** The relying party's redirect URI, echoed back into `oidcExchange` unchanged. */
    val redirectUri: String,
    /** Requested scope, space-separated. `openid` is added automatically when absent (§12.1 rule 4). Defaults to `null` (→ `openid` only). */
    val scope: String? = null,
    /**
     * Extra authorization-request parameters (e.g. `prompt`, `login_hint`,
     * `ui_locales`). §12.1 rule 5 allows caller-supplied additions but forbids
     * the SDK from adding any of its own beyond the mandated eight, so
     * attempting to override one of those eight throws.
     */
    val extraParams: Map<String, String> = emptyMap(),
)

/**
 * A token set returned by the OAuth2 token endpoint (wire schema
 * `TokenResponse`), returned by `oidcExchange`, `oidcRefresh`, and
 * `loginClientCredentials`.
 *
 * [accessToken], [refreshToken], and [idToken] are [Sensitive] (§12.5): their
 * `toString()` always redacts to `"[SENSITIVE]"`.
 *
 * [idClaims] is present exactly when [idToken] is, and holds the
 * ALREADY-VALIDATED claim set (§12.4) — validation happens before this object
 * is ever constructed, so an [OidcTokenSet] in your hands is never partially
 * trusted (§12.4 rule 7).
 *
 * @property accessToken the OAuth2 access token (§12.5 secret)
 * @property tokenType the token type the server issued (`Bearer`)
 * @property expiresIn access-token lifetime in seconds from the time of the response
 * @property scope granted scope, when the server narrowed or echoed it
 * @property refreshToken the refresh token, when the grant issued one (§12.5 secret)
 * @property idToken the raw ID token, when the grant issued one (§12.5 secret)
 * @property idClaims the validated ID-token claims — present exactly when [idToken] is
 */
data class OidcTokenSet(
    val accessToken: Sensitive<String>,
    val tokenType: String,
    val expiresIn: Long,
    val scope: String? = null,
    val refreshToken: Sensitive<String>? = null,
    val idToken: Sensitive<String>? = null,
    val idClaims: IdTokenClaims? = null,
) {
    /** Redacts every §12.5 secret field; [idClaims], if present, is printed in full (it is not secret). */
    override fun toString(): String =
        "OidcTokenSet(accessToken=$accessToken, tokenType=$tokenType, expiresIn=$expiresIn, " +
            "scope=$scope, refreshToken=$refreshToken, idToken=$idToken, idClaims=$idClaims)"
}

/** Arguments to `oidcExchange` (`grant_type=authorization_code`). */
data class OidcExchangeParams(
    /** The authorization code the IdP redirected back with. */
    val code: String,
    /** The verifier from the matching [AuthorizationRequest]. Accepts the [Sensitive] wrapper or a bare string (e.g. rehydrated from a caller's own session store). */
    val codeVerifier: Sensitive<String>,
    /** The same `redirect_uri` that was sent on the authorization request. */
    val redirectUri: String,
    /** The `nonce` from the matching [AuthorizationRequest]. MANDATORY — §12.4 rule 6 is not optional for this grant. */
    val nonce: String,
    /** Tenant UUID for the token endpoint's required `tenant_id` query parameter. Defaults to the client's configured tenant when it resolves to a UUID (§12.3 rule 4). */
    val tenantId: String? = null,
    /** A pre-fetched discovery document, to avoid re-reading the (cached) one. Fetched via `oidcDiscover` when omitted. */
    val configuration: OidcConfiguration? = null,
) {
    companion object {
        /** Convenience overload accepting a bare (unwrapped) `codeVerifier`, e.g. rehydrated from a caller's own session store. */
        fun of(
            code: String,
            codeVerifier: String,
            redirectUri: String,
            nonce: String,
            tenantId: String? = null,
            configuration: OidcConfiguration? = null,
        ): OidcExchangeParams = OidcExchangeParams(code, Sensitive.of(codeVerifier), redirectUri, nonce, tenantId, configuration)
    }
}

/** Arguments to `oidcRefresh` (`grant_type=refresh_token`). */
data class OidcRefreshParams(
    /** The refresh token to redeem. */
    val refreshToken: Sensitive<String>,
    /** Optional narrowed scope to request. Omitted from the form body when absent. */
    val scope: String? = null,
    /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
    val tenantId: String? = null,
    /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
    val configuration: OidcConfiguration? = null,
) {
    companion object {
        /** Convenience overload accepting a bare (unwrapped) `refreshToken`. */
        fun of(
            refreshToken: String,
            scope: String? = null,
            tenantId: String? = null,
            configuration: OidcConfiguration? = null,
        ): OidcRefreshParams = OidcRefreshParams(Sensitive.of(refreshToken), scope, tenantId, configuration)
    }
}

/** Arguments to `loginClientCredentials` (`grant_type=client_credentials`). */
data class LoginClientCredentialsParams(
    /** Optional scope to request. This grant requests no `openid` scope and the response carries no `id_token` (§12.1). */
    val scope: String? = null,
    /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
    val tenantId: String? = null,
    /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
    val configuration: OidcConfiguration? = null,
)

/** Arguments to `introspect` (RFC 7662). Requires confidential-client credentials (§12.1 note 4). */
data class IntrospectParams(
    /** The token to introspect. */
    val token: Sensitive<String>,
    /** Optional RFC 7662 `token_type_hint` (`access_token` / `refresh_token`). */
    val tokenTypeHint: String? = null,
    /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
    val tenantId: String? = null,
    /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
    val configuration: OidcConfiguration? = null,
) {
    companion object {
        /** Convenience overload accepting a bare (unwrapped) `token`. */
        fun of(
            token: String,
            tokenTypeHint: String? = null,
            tenantId: String? = null,
            configuration: OidcConfiguration? = null,
        ): IntrospectParams = IntrospectParams(Sensitive.of(token), tokenTypeHint, tenantId, configuration)
    }
}

/** Arguments to `revoke` (RFC 7009). Requires confidential-client credentials (§12.1 note 4). */
data class RevokeParams(
    /** The token to revoke. */
    val token: Sensitive<String>,
    /** Optional RFC 7009 `token_type_hint`. */
    val tokenTypeHint: String? = null,
    /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
    val tenantId: String? = null,
    /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
    val configuration: OidcConfiguration? = null,
) {
    companion object {
        /** Convenience overload accepting a bare (unwrapped) `token`. */
        fun of(
            token: String,
            tokenTypeHint: String? = null,
            tenantId: String? = null,
            configuration: OidcConfiguration? = null,
        ): RevokeParams = RevokeParams(Sensitive.of(token), tokenTypeHint, tenantId, configuration)
    }
}

/**
 * The RFC 7662 introspection result (wire schema `IntrospectionResponse`).
 * Only [active] is guaranteed; the server omits the metadata fields for an
 * inactive token.
 */
data class IntrospectionResult(
    /** Whether the token is currently active. */
    val active: Boolean,
    /** Subject the token was issued to. */
    val sub: String? = null,
    /** Client the token was issued to. */
    val clientId: String? = null,
    /** Scope granted to the token. */
    val scope: String? = null,
    /** Token type (`Bearer`). */
    val tokenType: String? = null,
    /** Expiry time, epoch seconds. */
    val exp: Long? = null,
    /** Issued-at time, epoch seconds. */
    val iat: Long? = null,
)

/** Arguments to `ssoStart` (`POST /api/v1/auth/federation/oidc/start`). */
data class SsoStartParams(
    /** UUID of the server-side federation configuration identifying the upstream IdP. */
    val federationConfigId: String,
    /** Post-login destination, stored server-side and echoed back by `ssoComplete`. */
    val redirectUri: String,
    /** Tenant UUID. One tenant form ([tenantId] or [tenantSlug]) is required; defaults to the client's configuration (§5.1). */
    val tenantId: String? = null,
    /** Tenant slug. Alternative to [tenantId]. */
    val tenantSlug: String? = null,
    /** Organization UUID. One org form ([orgId] or [orgSlug]) is required; defaults to the client's configuration (§5.1). */
    val orgId: String? = null,
    /** Organization slug. Alternative to [orgId]. */
    val orgSlug: String? = null,
)

/**
 * The result of `ssoStart` (wire schema `OidcStartResponse`).
 *
 * There is deliberately NO nonce: on the federation path the nonce never
 * leaves the server (§12.1 note 7). Round-trip [state] into `ssoComplete`
 * unmodified — the server stores it single-use with a 10-minute TTL and
 * recovers the whole login context from it.
 *
 * @property authorizeUrl the upstream IdP authorization URL to redirect the browser to
 * @property state single-use CSRF state to round-trip back into `ssoComplete` unmodified
 * @property expiresInSecs remaining TTL of the server-side state row, in seconds (600 = 10 min)
 */
data class SsoStartResult(
    val authorizeUrl: String,
    val state: String,
    val expiresInSecs: Long,
)

/** Arguments to `ssoComplete` (`POST /api/v1/auth/federation/oidc/callback`). */
data class SsoCompleteParams(
    /** The `state` value the IdP redirected back with — must be the one `ssoStart` returned. */
    val state: String,
    /** The authorization code the IdP redirected back with. */
    val code: String,
)

/**
 * The result of `ssoComplete` (wire schema `SsoLoginSuccessResponse`).
 *
 * Carries NO token material — the session arrives as `Set-Cookie`, so the §4
 * cookie jar (already wired into [io.axiam.sdk.AxiamClient]'s shared
 * `OkHttpClient`) is what actually captures it (§12.1 note 6).
 *
 * @property userId the provisioned/linked user's UUID
 * @property sessionId the established session's UUID
 * @property expiresIn session/access-token lifetime in seconds
 * @property redirectUri the post-login destination that was stored during `ssoStart`
 */
data class SsoCompleteResult(
    val userId: String,
    val sessionId: String,
    val expiresIn: Long,
    val redirectUri: String,
)
