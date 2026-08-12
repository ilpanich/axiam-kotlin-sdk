# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New suspending methods on
  `AxiamClient`: `umaRegisterResource` / `umaReadResource` / `umaUpdateResource` /
  `umaDeleteResource` / `umaListResources`, `umaRequestTicket`, `umaExchangeTicket`, plus the
  top-level `umaParseChallenge` / `umaChallengeHeader` helpers and the `ResourceSet` /
  `RequestedPermission` / `RptPermission` / `RequestingPartyToken` / `UmaChallenge` types.

  Two behaviours are load-bearing rather than incidental, and both are asserted by counting
  requests. **`umaExchangeTicket` never retries** — the one documented exception to the §16
  retry policy, because a ticket is consumed before the request is evaluated, so a retry
  cannot succeed and under concurrency is exactly the second redemption that
  ilpanich/axiam#302's measured residual describes. And **`umaParseChallenge` does not
  exchange the ticket it parsed**: the `as_uri` names an authorization server the caller has
  not chosen to trust.

  The PAT is an explicit first argument on every Protection API call rather than being taken
  from the client's session, because that session is usually a *user* session and a ticket
  binds to a `client_id`.

  `access_denied` on the ticket grant arrives as **403** (UMA 2.0 §3.3.6), unlike RFC 8628's,
  which is a 400. It is mapped to `OAuthProtocolError` by a mapper local to this grant rather
  than by widening the shared 400/401 rows — an ordinary REST 403 still maps to `AuthzError`.

- **§16 bounded read-only retry policy** (`internal/Retry.kt`), wired into `checkAccess`/`can`/
  `batchCheck`: 3 attempts, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`,
  `Retry-After` honored as a floor. This SDK had no §16 policy before — only §9.3's
  refresh-then-retry-once, a different mechanism — so §11.2 rule 5's requirement had gone
  unmet since it was written. `CancellationException` is re-thrown rather than retried:
  a cancelled scope is the caller's decision, not the server's failure.
- **§18 `close()` semantics** — idempotent via `compareAndSet`, clears the memo, and
  use-after-close throws `NetworkError` rather than silently reconnecting. It does **not** log
  out and never reaches the network.
- **§19 telemetry hooks** — `Builder.telemetryHook(...)`, the **sealed** `TelemetryEvent`
  hierarchy and `examples/telemetry-hook`. A throwing hook cannot fail the operation that
  fired it (except `CancellationException`, which must propagate), and no event payload can
  carry a token. One request pair per *attempt*.
- **§17 decision memo — opt-in, off by default** — `Builder.decisionMemoTtl(...)`, clamped to
  5 s, safe for concurrent use. Allows and denies memoized identically, failures never
  memoized, cleared on any credential change. **Reads-your-own-writes is not guaranteed.**
- `Builder.retryDisabled()` (§16.6). No builder method for the attempt cap, base or delay cap.
- `NetworkError.retryAfter`, a parsed `kotlin.time.Duration` rather than the raw header text,
  so the class's redaction discipline is untouched.

### Changed

- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).
- **Test update:** `AuthzTest."500 maps to NetworkError and redacts non-allowlisted headers"`
  now enqueues three 500s rather than one. That is a direct consequence of §16 — the call now
  makes three attempts, and the assertion is about the error the caller finally sees.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#16)
- Device (mTLS) tokens now carry aud=axiam:m2m (#15)
- Service accounts can use login_client_credentials (#14)
- Reject a failed token in the Ktor plugin (§15.3.3) (#13)
- Close the coverage margin with real value-semantics tests (§12.6.4) (#12)

### Fixed

- Reject plaintext base URL, pin discovery jwks_uri origin, add webhook verifier

## [Unreleased]

### Security — BREAKING (behavioural)

- **The Ktor plugin now rejects a token that fails verification (§15.3.3).**
  `AxiamAuthentication` swallowed the `AuthError` and left the user attribute
  absent, deferring the decision to the per-route helpers. A route that forgot
  `requireAuth()` therefore ran **unauthenticated** for a caller who had
  presented an expired, foreign-tenant or forged token — fail-open by omission.
  The Java and C# SDKs make the same leave-it-absent choice deliberately, but
  they sit behind Spring Security and ASP.NET Core authorization respectively;
  Ktor has no equivalent layer behind this plugin, so nothing else caught it.

  A presented-but-invalid credential now yields `401` from the plugin itself.
  **A call carrying no token at all is unaffected** — that is not a failed
  authentication, and public routes must keep working. The distinction is the
  point: reject a bad credential, ignore an absent one.

  Verified by falsification: reverting the plugin fails the two new
  invalid-token tests while the public-route test keeps passing.

### Added

- **Webhook value-semantics and header-parsing tests (§12.6.4).** Coverage sat
  at 98.19% against a 98% floor — a 0.19-point margin, so the next unrelated
  addition would have tripped the gate. The untested surface was
  `WebhookEvent`'s hand-written `equals`/`hashCode`/`toString` and the remaining
  fail-closed branches of the signature-header parser, which is worth testing on
  its own merits rather than as coverage padding: `WebhookEvent` holds a
  `ByteArray`, so a compiler-generated `equals` would compare it by **reference**
  and two events carrying identical bytes would compare unequal. The new tests
  pin content-based equality, the hash-code contract, that `toString` reports the
  body's size rather than the body (a delivery body may carry sensitive data),
  and that a duplicate `t=`, a non-numeric `t=` and an odd-length `v1=` each fail
  closed. Coverage is now 98.94%.

### Changed — BREAKING

- **`AxiamClient.verifySession` now applies the full CONTRACT.md §10.1 "minimum
  local-verification set", which tightens what it accepts.** Two rules change acceptance for
  tokens that used to pass:

  1. **An absent `exp` is now rejected.** The check was `if (exp != null && exp.time <= now)`, so
     a token carrying **no** `exp` claim skipped the comparison entirely and was accepted with no
     expiry ever applied — the `SEC-080` defect, found independently in a sibling SDK. An absent
     `exp` is a *permanent* credential, not a token without an expiry constraint.
  2. **`nbf` is now honoured.** It was not read at all; a token whose not-before instant is in
     the future was accepted. It is now rejected.

  **A token minted by the AXIAM server is unaffected** — it always carries `exp` and never a
  future `nbf`. The break is real for a guard fed tokens from *another* signer that shares the
  organization JWKS: such a guard may start rejecting tokens it used to accept. That is the
  intent of the change. The Ktor plugin (`AxiamAuthentication`) inherits the tightening, since it
  injects its identity via `verifySession`.

- **`JwksVerifier.verify` is renamed `JwksVerifier.verifySignatureOnlyUnchecked`.** It is the raw
  signature primitive §10.1 permits, and its name now says at the call site that it checks no
  claims at all — not `exp`, not `nbf`, not `tenant_id`, not `iss`, not `aud`. It MUST NOT be
  used as a guard; `AxiamClient.verifySession` is the guard entry point and routes through it.

- **`JwksVerifier.assertTenant` now fails closed when the configured tenant is blank**, rather
  than comparing against an empty expectation (§10.1 rule 4: "no configured tenant to compare
  against MUST fail closed"). `AxiamClient.builder` already rejects a blank `tenantId`, so this
  affects only direct callers of the assertion.

### Added

- **`iss` and `aud` verification, conditional on configuration (§10.1 rules 5 and 6).** New
  builder options `expectedIssuer(...)` and `expectedAudience(...)`, both optional and unset by
  default: unset means the claim is not checked, exactly as §10.1 specifies. When one is set,
  `verifySession` rejects a token whose claim is absent or does not match — an absent claim is
  never treated as "nothing to check". A resource server guarding a user-facing API SHOULD set
  `expectedAudience("axiam:user")`.
- **`JwksVerifier.CLOCK_SKEW_SECONDS` (§10.1 rule 7)** — the single named, bounded 60 s leeway
  applied to the `exp` and `nbf` comparisons. It is a constant, not an inline literal, and
  deliberately has no setter: the contract forbids an operator raising it to an unbounded value.
- **`JwksVerifier.assertLocalClaims(...)`** — §10.1 rules 2-7 over an already-signature-verified
  claim set, the companion to `verifySignatureOnlyUnchecked` (rule 1). Together the two are the
  whole guard; neither is sufficient alone.
- Algorithm pinning in the §10 path now reads `alg` from the **raw** header before
  `SignedJWT.parse`, matching the §12.4 id-token path. An `alg: none` token is therefore refused
  on its algorithm (nimbus would otherwise surface it as a generic parse error), and neither it
  nor an HS-signed token bearing an EdDSA `kid` reaches the JWKS.
- The full §10.1 negative-test set (`LocalVerificationSetTest`): expired; no `exp`; non-numeric
  `exp`; future `nbf`; different tenant; no `tenant_id`; `alg: none`; an HS-signed token bearing
  an EdDSA key id; and issuer/audience mismatch and absent-claim cases. The `alg: none` and
  HS-confusion cases additionally assert that the JWKS endpoint was never contacted, pinning
  "rejected without consulting a key".
- Vendored `CONTRACT.md` re-synced to add §10.1.

- Webhook signature verification (CONTRACT.md §13, `T-145`): `io.axiam.sdk.webhook.AxiamWebhooks.verify(...)`
  verifies AXIAM's signed-timestamp webhook scheme (`X-Axiam-Signature: t=<unix>,v1=<hex>` =
  HMAC-SHA256 over `"<timestamp>.<raw_body>"`) against the raw request body bytes, with a
  two-sided freshness window (default 300 s, `now` injection seam for tests) and a
  constant-time comparison (`MessageDigest.isEqual`) over the decoded MAC bytes. Returns a
  sealed `WebhookVerifyResult` (`Success(WebhookEvent)` / `Failure(WebhookVerifyError)`) rather
  than throwing; every `WebhookVerifyError` message is fixed and generic — the expected
  signature and the secret are never surfaced. `X-Axiam-Event`/`X-Axiam-Delivery` are accepted
  as optional parameters and echoed onto `WebhookEvent` for the receiver's own dedup handling.
  New `io.axiam.sdk.webhook` package: `AxiamWebhooks`, `WebhookEvent`, `WebhookVerifyResult`,
  `WebhookVerifyError`. Vendored `CONTRACT.md` re-synced to add §13.

### Security

- **SEC-073 [MEDIUM]** — `AxiamClient.builder(...)` now rejects a plaintext `http://` `baseUrl`
  at construction time (`AuthError`), with a loopback exception (`localhost`/`127.0.0.1`/`::1`)
  for local development — matching the Rust SDK's `ensure_secure_scheme`. Previously a
  misconfigured `http://` base URL was accepted silently, so login credentials, the bearer
  session cookie, CSRF token, and tenant header could be sent in cleartext with no error.
- **SEC-075 [LOW/MEDIUM]** — the OIDC discovery document's `jwks_uri` is now constrained to the
  configured base URL's origin: it must be an absolute `https` URL with the same host and port
  as `baseUrl`, or the SDK falls back to the conventional `{baseUrl}/oauth2/jwks` instead of
  following it. Matches the PHP SDK's `isSameOriginHttps` fix for the same `SDK-19` class.
  Previously a compromised/misconfigured discovery response could point EdDSA key resolution at
  an attacker-chosen host.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT.md §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- §9 rule 6 — never let a caller's cancellation own the shared refresh
- Widen Sensitive.expose() to public (F-03, CONTRACT §7 rule 3)

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
