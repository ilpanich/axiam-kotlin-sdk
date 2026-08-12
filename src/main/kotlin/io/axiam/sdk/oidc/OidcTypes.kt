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
    /**
     * RFC 8628 device authorization endpoint, used by `deviceAuthorize` (§14.1).
     *
     * `null` when the server does not implement the device grant, or when the
     * document came from a non-AXIAM OP. Its absence is an error at call time,
     * never a cue to build the URL by concatenation.
     */
    val device_authorization_endpoint: String? = null,
    /**
     * OIDC RP-Initiated Logout 1.0 `end_session_endpoint`, used by `logoutUrl`
     * (§12.7.2 rule 1).
     *
     * `null` for the same reason, and the rule is stricter here: §12.7.2 rule 1
     * forbids synthesising this URL from the issuer. Code that concatenates
     * works against AXIAM and breaks against every other OP the same
     * application is pointed at.
     */
    val end_session_endpoint: String? = null,
    /** Whether the OP sends back-channel logout tokens. */
    val backchannel_logout_supported: Boolean = false,
    /** Whether those logout tokens carry `sid`. AXIAM always sends it. */
    val backchannel_logout_session_supported: Boolean = false,
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


// ---------------------------------------------------------------------------
// §14 Device Authorization Grant (RFC 8628)
// ---------------------------------------------------------------------------

/**
 * Arguments to `deviceAuthorize` (CONTRACT.md §14.1).
 *
 * @property scope space-separated scope to request; omitted when `null`
 * @property tenantId tenant UUID for the mandatory `tenant_id` query parameter
 * @property configuration a pre-fetched discovery document, or `null` to fetch
 */
data class DeviceAuthorizeParams(
    val scope: String? = null,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * The `DeviceAuthorizationResponse` — what the device shows its user, plus the
 * `device_code` it polls with (§14.1).
 *
 * [deviceCode] is [Sensitive] (§14.5): a bearer credential for the lifetime of
 * the grant. [userCode] deliberately is **not** — it exists to be read aloud
 * and typed by a human, and wrapping it would defeat the one thing it is for.
 * Neither may be logged; displaying [userCode] is the caller's job.
 *
 * @property deviceCode the device's polling credential (§14.5 secret)
 * @property userCode the short code the human types into the verification page
 * @property verificationUri where the human goes to enter [userCode]
 * @property verificationUriComplete the verification URI with the user code
 *   already embedded, when the server sent one — prefer it when the device can
 *   render a QR code. Never synthesised by concatenation when absent (§14.3):
 *   its format is the server's to choose
 * @property expiresIn seconds until the grant expires; polling stops here
 *   (§14.2 rule 4)
 * @property interval seconds between polls, from the response, defaulted to 5
 *   when the server omitted it (§14.2 rule 2)
 */
data class DeviceAuthorization(
    val deviceCode: Sensitive<String>,
    val userCode: String,
    val verificationUri: String,
    val verificationUriComplete: String? = null,
    val expiresIn: Int,
    val interval: Int,
)

/**
 * Arguments to `devicePoll` (§14.1).
 *
 * @property deviceCode the `deviceCode` from [DeviceAuthorization]
 * @property tenantId tenant UUID for the `tenant_id` query parameter
 * @property configuration a pre-fetched discovery document, or `null`
 */
data class DevicePollParams(
    val deviceCode: Sensitive<String>,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * Arguments to `deviceLogin` (§14.3).
 *
 * @property scope space-separated scope to request
 * @property tenantId tenant UUID for the `tenant_id` query parameter
 * @property configuration a pre-fetched discovery document, or `null`
 * @property onUserCode called with the [DeviceAuthorization] **before the
 *   first poll** (§14.3 rule 2), so the caller can display the code. A
 *   `suspend` function, so a device that must await a paint or a redraw can —
 *   polling does not begin until it returns. The SDK never prints the code:
 *   what the device does with it is the application's decision
 */
data class DeviceLoginParams(
    val scope: String? = null,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
    val onUserCode: suspend (DeviceAuthorization) -> Unit,
)

// ---------------------------------------------------------------------------
// §15 Token Exchange (RFC 8693)
// ---------------------------------------------------------------------------

/**
 * Arguments to `tokenExchange` (CONTRACT.md §15.1).
 *
 * A parameter object rather than positional arguments, because four optional
 * strings in positional order is a bug waiting to be written (§15.1).
 *
 * @property subjectToken the token being exchanged (§15.5 secret)
 * @property actorToken the acting party, when this is a **delegation** (§15.2
 *   rule 1). Its absence selects **impersonation** — a different operation with
 *   different risk. The SDK never fills this in for you
 * @property scopes scopes to request; omitted from the body when `null` or empty
 * @property audience the service the issued token is for
 * @property resource RFC 8707 synonym of [audience]; the server refuses the
 *   pair when they disagree
 * @property tenantId tenant UUID for the `tenant_id` query parameter
 * @property configuration a pre-fetched discovery document, or `null`
 */
data class TokenExchangeParams(
    val subjectToken: Sensitive<String>,
    val actorToken: Sensitive<String>? = null,
    val scopes: List<String>? = null,
    val audience: String? = null,
    val resource: String? = null,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * The result of an exchange (wire schema `TokenExchangeResponse`, §15.1).
 *
 * **There is no `refreshToken` property, and that is deliberate** (§15.2
 * rule 4). RFC 8693 issues none, so the type cannot represent one: an
 * application that wants a fresh exchanged token re-runs the exchange. This
 * result also never enters the §9 single-flight refresh guard — there is
 * nothing to refresh.
 *
 * @property accessToken the issued token (§15.5 secret)
 * @property issuedTokenType what the server actually issued. Mandatory in
 *   RFC 8693 §2.2.1 and surfaced rather than dropped (§15.2 rule 6), so a
 *   client that asked for one type and got another can tell
 * @property tokenType the token type (`Bearer`)
 * @property expiresIn lifetime in seconds — never longer than the subject
 *   token's remaining life
 * @property scope **the granted scope, which may be narrower than requested**
 *   even on success (§15.2 rule 7); read it rather than assuming the request
 *   was honoured verbatim
 */
data class ExchangedToken(
    val accessToken: Sensitive<String>,
    val issuedTokenType: String,
    val tokenType: String,
    val expiresIn: Long,
    val scope: String? = null,
)

// ---------------------------------------------------------------------------
// §12.7 Logout helpers
// ---------------------------------------------------------------------------

/**
 * Arguments to `logoutUrl` (CONTRACT.md §12.7.2).
 *
 * @property idToken a previously-issued ID token, placed in `id_token_hint` —
 *   the only *authenticated* statement of which session is being ended
 * @property postLogoutRedirectUri where the OP should send the browser
 *   afterwards. Honoured only on exact match against the client's registered
 *   allow-list — a server-side check the SDK deliberately does not duplicate
 *   (§12.7.2 rule 3)
 * @property state an opaque value echoed back on the redirect. Generated and
 *   checked by the caller (§12.7.2 rule 2), never by the SDK
 * @property configuration a pre-fetched discovery document, or `null`
 */
data class LogoutUrlParams(
    val idToken: Sensitive<String>,
    val postLogoutRedirectUri: String? = null,
    val state: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * What a verified back-channel logout token names (§12.7.3).
 *
 * Deliberately **not** a bare `Boolean`: the RP has to know *which* session to
 * end, and a verifier that only says "valid" would force the caller to
 * re-parse the token themselves, with none of the checks this type is proof of.
 *
 * @property sid the session that ended. **When non-`null`, end only this
 *   session** — falling back to "every session for [sub]" is over-reach the
 *   AXIAM server itself refuses to make
 * @property sub the subject whose session ended
 * @property jti replay identifier. **The RP dedups on this, not the SDK.**
 *   Back-channel delivery is at-least-once with retry, so a valid token
 *   legitimately arrives twice; the SDK has no durable store and an in-memory
 *   guard would silently drop a real second logout after a restart. Surfaced,
 *   never consumed
 */
data class VerifiedLogoutToken(
    val sid: String? = null,
    val sub: String? = null,
    val jti: String,
)

// ---------------------------------------------------------------------------
// §20 UMA 2.0 — Protection API and ticket grant
// ---------------------------------------------------------------------------

/**
 * A UMA resource set — an AXIAM resource seen through the Protection API
 * (CONTRACT.md §20.1).
 *
 * [id] is **the AXIAM resource id**, not a parallel identifier: the same UUID
 * is directly usable as the [RequestedPermission.resourceId] of a later ticket
 * request, and as the resource id anywhere else in this SDK.
 *
 * @property id assigned by the server on registration; `null` on the way in
 * @property name human-readable name, shown in the admin UI
 * @property type free-form resource type; defaults server-side to
 *   `uma_resource` when `null`, so a resource server that omits it does not
 *   produce a row that sorts oddly next to hand-made ones
 * @property resourceScopes the scope names a resource server may ask for on
 *   this resource. **Replaced wholesale by an update, never merged**
 *   (§20.2 rule 8) — this SDK does not read the current scopes and fold them
 *   into an update payload as a convenience, because that would make removing
 *   a scope impossible through it
 */
data class ResourceSet(
    val name: String,
    val id: String? = null,
    val type: String? = null,
    val resourceScopes: List<String> = emptyList(),
)

/**
 * One `(resource, scopes)` pair a resource server requires (§20.1).
 *
 * @property resourceId the AXIAM resource id — the same UUID the Protection
 *   API returned as `_id`
 * @property resourceScopes scope names, each of which the resource must
 *   already declare; matched exactly, with no prefix or wildcard semantics in
 *   either direction
 */
data class RequestedPermission(
    val resourceId: String,
    val resourceScopes: List<String>,
)

/**
 * One entry of an RPT's `permissions` claim (§20.1).
 *
 * **A record of a decision already made, not a live authorization answer**
 * (§20.2 rule 7). These are the pairs the engine allowed when the RPT was
 * minted; a grant revoked afterwards does not empty a live RPT. Do not cache
 * them beyond the token's own expiry — which is why that expiry is short.
 *
 * @property resourceId the resource the engine allowed
 * @property resourceScopes the scopes it allowed on that resource
 * @property exp absolute expiry, seconds since the epoch
 */
data class RptPermission(
    val resourceId: String,
    val resourceScopes: List<String>,
    val exp: Long,
)

/**
 * The result of the UMA ticket grant (§20.1).
 *
 * **There is no `refreshToken` property, and that is deliberate**
 * (§20.2 rule 5). The grant issues none, so an RPT cannot outlive the ticket
 * that authorised it; an application that wants a fresh one re-runs the grant.
 * This result never enters the §9 single-flight refresh guard — there is
 * nothing to refresh.
 *
 * @property accessToken the RPT itself (§20.6 secret)
 * @property tokenType always `Bearer`
 * @property expiresIn `min(claimToken remaining, server ceiling, 300 s)`
 */
data class RequestingPartyToken(
    val accessToken: Sensitive<String>,
    val tokenType: String,
    val expiresIn: Long,
)

/**
 * Arguments to `umaExchangeTicket` (§20.1).
 *
 * @property ticket the permission ticket, from `umaRequestTicket` or a parsed
 *   challenge
 * @property claimToken the requesting party's access token. **Required**,
 *   though UMA 2.0 §3.3.1 marks it optional: v1 implements neither incremental
 *   authorization nor claims-gathering, so this is the only channel that names
 *   a requesting party (§20.2 rule 2)
 * @property tenantId tenant UUID for the `tenant_id` query parameter
 * @property configuration a pre-fetched discovery document
 */
data class UmaExchangeTicketParams(
    val ticket: Sensitive<String>,
    val claimToken: Sensitive<String>,
    val tenantId: String? = null,
    val configuration: OidcConfiguration? = null,
)

/**
 * A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2, §20.3).
 *
 * @property realm the protection realm the resource server named
 * @property asUri the authorization server the resource server nominates.
 *   **Not automatically trusted** — see [umaParseChallenge]
 * @property ticket the ticket to exchange — a bearer credential for its
 *   60-second life
 */
data class UmaChallenge(
    val realm: String? = null,
    val asUri: String? = null,
    val ticket: Sensitive<String>? = null,
)

/**
 * Parse a `WWW-Authenticate: UMA …` header value (CONTRACT.md §20.3).
 *
 * **This deliberately does not exchange the ticket.** Parsing a challenge and
 * acting on it are separate decisions: the `as_uri` names an authorization
 * server the caller has not necessarily chosen to trust, and auto-exchanging
 * would send the requesting party's `claimToken` to whatever host answered the
 * 403. The caller decides.
 *
 * @return the parsed challenge, or `null` when the header is not a UMA
 *   challenge
 */
public fun umaParseChallenge(header: String): UmaChallenge? {
    val trimmed = header.trim()
    if (!trimmed.startsWith("UMA")) return null
    val rest = trimmed.substring(3)
    // "UMA" alone is a valid, if useless, challenge; anything else must be
    // separated by whitespace so `UMAX realm="…"` is not read as UMA.
    if (rest.isNotEmpty() && !rest[0].isWhitespace()) return null

    var realm: String? = null
    var asUri: String? = null
    var ticket: Sensitive<String>? = null
    for (part in rest.split(",")) {
        val eq = part.indexOf('=')
        if (eq < 0) continue
        val key = part.substring(0, eq).trim()
        val value = part.substring(eq + 1).trim().removeSurrounding("\"")
        when (key) {
            "realm" -> realm = value
            "as_uri" -> asUri = value
            "ticket" -> ticket = Sensitive.of(value)
            // Unknown parameters are ignored rather than rejected: UMA 2.0
            // permits a server to add its own, and refusing the whole
            // challenge over one would lose the ticket with it.
            else -> Unit
        }
    }
    return UmaChallenge(realm, asUri, ticket)
}

/**
 * Format a `WWW-Authenticate: UMA` header value (§20.3, emit half).
 *
 * The resource-server side: having obtained a ticket from `umaRequestTicket`,
 * tell the caller where to redeem it.
 */
public fun umaChallengeHeader(realm: String, asUri: String, ticket: Sensitive<String>): String =
    """UMA realm="$realm", as_uri="$asUri", ticket="${ticket.expose()}""""
