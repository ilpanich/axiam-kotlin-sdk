# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OIDC / SSO relying-party helpers (CONTRACT.md §12, contract 1.4): the nine canonical
  operations as `suspend` functions directly on `AxiamClient` — `oidcDiscover`, `oidcBegin`
  (deliberately NOT `suspend`: pure local computation, no network I/O), `oidcExchange`,
  `oidcRefresh`, `loginClientCredentials`, `introspect`, `revoke`, `ssoStart`, `ssoComplete`. No
  `*Async` twins, matching the contract's Kotlin naming column.
- New `io.axiam.sdk.oidc` package: `OidcConfiguration`, `AuthorizationRequest`, `OidcTokenSet`,
  `IdTokenClaims`, `IntrospectionResult`, `SsoStartResult`, `SsoCompleteResult`, and the
  per-operation parameter types; `OidcStateStore` + an in-memory `MemoryOidcStateStore`
  reference implementation (10-minute TTL, single-use `consume`, no background thread).
- PKCE/CSPRNG primitives (`java.security.SecureRandom` + `MessageDigest`, S256-only, RFC 7636
  Appendix B verified) and the full §12.4 ID-token validation checklist (algorithm pinning,
  JWKS signature verification via an extended `JwksVerifier`, issuer/audience/time/nonce),
  raising `AuthError` with one of the seven stable reason codes
  (`invalid_alg`/`unknown_kid`/`invalid_signature`/`invalid_issuer`/`invalid_audience`/
  `token_expired`/`nonce_mismatch`) on any failure — the whole token set is discarded, never
  partially trusted.
- `OAuthProtocolError`, a subclass of the existing `AuthError` (not a fourth peer error type,
  so `catch (e: AuthError)` keeps matching it), for an `OAuth2ErrorResponse` body from
  `/oauth2/token` (400) or `/oauth2/introspect`/`/oauth2/revoke` (401); message is exactly
  `"<error>: <error_description>"`. `AuthError` itself gained an additive, optional `reason`
  field for the §12.4 codes above — fully backward compatible with every existing construction
  site.
- `AxiamClient.Builder.oidcClientId(...)`, `.oidcClientSecret(...)`, `.oidcDiscoveryTtlMillis(...)`,
  and `.oidcClockSkewSeconds(...)` — the relying party's OAuth2 identity is configured at
  construction time (needed by §12.4 rule 4 audience matching), never as a per-call argument.
- Ktor glue: `Route.axiamOidcLogin(client, redirectUri, ...)` installing a login-redirect and
  callback route pair, `compileOnly`-safe exactly like the existing `AxiamAuthentication`
  plugin — the SDK core compiles and passes tests with Ktor entirely absent.
- `examples/oidc-login/OidcLoginExample.kt` and a README section documenting all nine
  operations and the caller-owns-login-state rule (§12.3 rule 1).
- No new runtime dependency: PKCE/CSPRNG uses the JDK standard library; JWKS/ID-token
  verification reuses the existing `nimbus-jose-jwt` dependency.

### Fixed

- **Single-flight refresh: a cancelled caller could strand the rest of its burst and, in a
  narrow race, poison the guard permanently (CONTRACT.md §9 rule 6, contract 1.6).** Both
  refresh coalescers (`AxiamClient.refresh()`'s `RefreshGuard`, §1; `oidcRefresh`'s dedicated
  guard, §12) ran the wire call *in the coroutine of whichever caller happened to be elected
  leader*, and published that leader's own `CancellationException` into the shared `Deferred`.
  Consequences, all fixed:
  - Cancelling the leader's caller (`withTimeout`, a cancelled parent scope, a client
    disconnect) made every *other* caller coalesced into that refresh resume with a foreign
    `CancellationException` — silently cancelling coroutines that were never cancelled, and
    uncatchable as `AxiamException`. Because OkHttp's `Call.execute()` is a blocking,
    non-interruptible call, the refresh had in fact already **succeeded on the wire** and the
    server had already rotated the single-use `refresh_token`: the burst threw away a valid
    rotated token and left the session unrecoverable (§9 rule 2 — "all N callers receive that
    one call's outcome" — was not met under cancellation).
  - The slot was vacated by an unconditional `finally { mutex.withLock { slot = null } }`.
    Acquiring a `Mutex` is a *cancellable* suspension point, so a cancelled leader that found
    the mutex contended threw before clearing, parking a settled outcome in the slot forever;
    every later caller was then handed that previous burst's outcome with no wire call ever
    happening again (§9 rule 6c/6d).
  Both guards — plus the §12.1 discovery fetch, which had the same shape — now share one
  documented coalescer, `internal SingleFlight`: the work block runs in the guard's own
  `SupervisorJob` scope so no caller's `Job` owns the shared attempt, the outcome is carried as
  a `Result` by a `Deferred` that is only ever completed *successfully* (so no caller can ever
  be handed another coroutine's cancellation), and the vacate is identity-checked and
  `NonCancellable`. Publish-before-vacate ordering (6a) and "no retry on failure" (§9.3,
  original throwable instance, unwrapped) are unchanged. Cancelling any single caller now
  cancels only that caller's `await`.
- `Sensitive.expose()` widened from `internal` to `public` (CONTRACT.md §7 rule 3, contract
  1.5): CONTRACT.md §12 hands `accessToken`/`refreshToken`/`idToken` on `OidcTokenSet` to the
  calling application in the `/oauth2/token` response body, not via a `Set-Cookie` the SDK
  captures on the caller's behalf, so a §12 caller had no supported way to read the tokens it
  was handed. Additive and non-breaking: `toString()` redaction is unaffected, and there is
  still exactly one accessor and no implicit reachability path.

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Kotlin SDK 91.3% → 99.1% + enforce Kover gate (Phase D2) (#6)

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info

## [Unreleased]

### Changed

- Adopt CONTRACT.md 1.3: the new gRPC-only `getUserInfo` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract/proto copies are re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha14.

## [1.0.0-alpha14] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha13.

## [1.0.0-alpha13] - 2026-07-19

### Fixed

- Close & forward OSSRH staging repo to Central Portal

## [1.0.0-alpha12] - 2026-07-19

### Changed

- Add Kotlin examples and sync CONTRACT §5.1 org context (#3)

### Fixed

- Deploy via OSSRH Staging API compat endpoint, not Portal upload URL

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

## [Unreleased]

### Added

- Initial greenfield Kotlin client SDK for AXIAM (`io.github.ilpanich:axiam-sdk-kotlin`).
  Conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).
- Coroutine (`suspend`) REST client (`AxiamClient`, built via
  `AxiamClient.builder(baseUrl, tenantId)`): `login`, `verifyMfa`, `refresh`, `logout`,
  `checkAccess`, `can`, `batchCheck` — canonical camelCase names, no `*Async` twins (§1). A
  tenant identifier is required at construction (§5); there is no default tenant.
- §2 error taxonomy as a sealed `AxiamException` hierarchy (`AuthError`, `AuthzError`,
  `NetworkError`), with HTTP-status mapping and header-redacting summaries; no raw token in any
  message.
- §3 CSRF capture-and-echo on state-changing requests and §5 `X-Tenant-ID` on every request,
  via an OkHttp application interceptor with host isolation.
- §4 per-client cookie jar (`JavaNetCookieJar` over a private `CookieManager`).
- §6 strict TLS with a `customCa(pem)` escape hatch (system trust store composed with a PEM CA;
  no verification-bypass surface exists) and §6.1 mTLS client certificates
  (`clientCertificate(certPem, keyPem)`) installed as an OkHttp `KeyManager`; the private key is
  held behind `Sensitive`.
- §7 `Sensitive<T>` wrapper (`toString()` → `"[SENSITIVE]"`, not a `data class`) around token
  material and the mTLS private key.
- §9 single-flight refresh guard (`kotlinx.coroutines.Mutex` + a shared `CompletableDeferred`);
  N concurrent 401s trigger exactly one refresh.
- EdDSA/Ed25519 JWKS session verification via nimbus-jose-jwt (algorithm-pinned, 300s cache, no
  expiry check in the verifier) with an org-wide tenant carry-forward assertion.
- §10 / §11 Ktor integration: the `AxiamAuthentication` plugin injecting `AxiamUser`, the
  `requireAuth` / `requireAccess` / `requireRole` helpers, an annotation-driven `enforce`, and
  the framework-free `@AxiamRequireAuth` / `@AxiamRequireAccess` / `@AxiamRequireRole`
  annotations. Ktor is an optional (`compileOnly`) dependency — the core compiles without it.
  Spring Boot users reuse the Java SDK's Spring interceptor.
- Gradle (Kotlin DSL) build with Dokka javadoc jar, Kover coverage, and a GPG-signed Sonatype
  Central Portal `publish` task; CI (`sdk-ci-kotlin.yml`, `coverage.yml`) with a TLS-bypass grep
  gate, a committed-private-key scan, a `verify-tag-on-main` gate, and Coveralls upload.

### Deferred (follow-ups, not in this release)

- gRPC transport (the contract's gRPC error/mTLS/single-flight surfaces).
- §8 AMQP HMAC message consumption — the contract does not require AMQP of the Kotlin SDK.
