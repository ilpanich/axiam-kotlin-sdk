# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour `mode` after a failed KE2 (CONTRACT §23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md at 1.29 and openapi.json at alpha40

## [Unreleased]

### Added

- `mode` in the `POST /api/v1/auth/opaque/login/start` response is now read: an optional string
  carrying the tenant's `opaque_mode` (`optional` or `required`), absent on a server older than
  the field.

### Changed

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- Re-vendor CONTRACT.md at 1.29 and openapi.json at 1.0.0-alpha40.
- **CONTRACT §23.4 rule 7 — a failed `KE2` no longer always ends the login.** `loginOpaque` still
  never sends `KE3` after the OPAQUE AKE check fails, but what it does next is now decided by
  `mode` and by nothing else: under `optional` it retries over `POST /api/v1/auth/login` with the
  same credentials and returns that call's outcome (its `LoginResult`, or its exception), because
  an account with no registration record is the ordinary mid-migration case and treating the
  failed exchange as final locks out every user of the tenant; under `required`, an unrecognised
  value, or **no `mode` field at all**, it raises `AuthError` as before and never touches
  `/auth/login`. `mode` is not downgrade protection — a hostile server wanting the plaintext could
  answer `404` — and is not documented as such.
- `404` handling is unchanged: a tenant with OPAQUE disabled is still the distinguishable
  `NetworkError`, not a credential failure.

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Changed

- Re-vendor CONTRACT.md at 1.28
- Add WebAuthn, account lifecycle and PAR (CONTRACT §24–§26)

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807), CONTRACT §23

### Changed

- Link to the AXIAM platform documentation site
- Re-vendor openapi.json at alpha32 (#37)

### Fixed

- Build the KSF before spending the exchange's state handle

## [Unreleased]

### Added

- CONTRACT.md §24 — WebAuthn / passkeys relying-party layer
  (`io.axiam.sdk.webauthn`): the six wire operations, the two distinct
  authentication ceremonies, and §24.6a's JSON bridge. `WebauthnChallenge.requestJson`
  is what an Android app hands to `CreatePublicKeyCredentialRequest`, and
  `registrationResponseJson` goes straight back into `webauthnRegisterFinish` —
  so the same plain-JVM artifact serves a desktop or server JVM and an Android
  app unchanged, with no AAR and no Android dependency. `WebauthnFailure`
  classifies a caught platform exception into the five §24.6b rule 5 outcomes
  without linking `androidx.credentials`.

  §24.6b's linked-API helper is deliberately absent: the JVM has no
  authenticator, and rule 2 forbids emulating one in software.
- CONTRACT.md §25 — account lifecycle and MFA enrolment
  (`io.axiam.sdk.account`): voluntary and forced TOTP enrolment, email
  verification, and the password-reset triple including the `reset/context`
  call a tenant with §23 enabled requires before a new password can be built.
- CONTRACT.md §26 — Pushed Authorization Requests, RFC 9126 (`oidcPar`,
  `OidcParParams`, `PushedAuthorizationRequest`). Required for a FAPI 2.0
  client, which cannot authorize any other way (§21.1).
- `examples/webauthn-passkeys`, `examples/account-lifecycle` and
  `examples/par-login`, with `./gradlew run*Example` tasks for each.

### Changed

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `LoginResult` gained `mfaSetupRequired` and `setupToken` for §25.2 rule 1's
  third login outcome. Both default, so every existing construction still
  compiles and reads `false`. Callers that branch only on `mfaRequired` should
  still add the new branch — a tenant that turns on required MFA will start
  returning it, and ignoring it reports a successful login that has no session.
- `OidcConfiguration` gained `pushed_authorization_request_endpoint`, defaulted
  to `null` and parsed from discovery.
- Re-vendored `CONTRACT.md` and `openapi.json` at contract 1.28.

### Added

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `loginOpaque`,
  `opaqueEnrollment` and `opaqueAvailable` on `AxiamClient`, plus the new
  `io.axiam.sdk.opaque` package.
- `examples/opaque-login`, run with `./gradlew runOpaqueLoginExample`.
- `net.java.dev.jna:jna` as a **`compileOnly`** dependency, the same posture
  this SDK already takes for Ktor and the RabbitMQ client. It binds
  `libaxiam_opaque_ffi`; a consumer whose tenant does not use OPAQUE does not
  receive it and does not need it. OPAQUE users add it themselves.

### Changed

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.
- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is a JNA binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam release page rather than on
  Maven Central. Put it on `java.library.path` or set
  `-Daxiam.opaque.library=` / `AXIAM_OPAQUE_LIBRARY`.
- **BREAKING** — `opaqueAvailable()` can genuinely return `false`, where
  `srpAvailable()` was hard-coded `true` on the JVM. Both JNA and the shared
  library are optional and independently absent-able. Code that ignored
  `srpAvailable()` must not ignore this one.
- `opaqueEnrollment` performs network I/O, where `srpEnrollment` did not:
  OPAQUE's envelope is sealed under the server's oblivious PRF, so there is no
  offline computation that produces a valid record. It also drops the
  `identity`, `group` and KDF parameters — a record binds to a credential
  identifier the server chooses, and the key-stretching parameters are the
  server's. As a consequence, **renaming a user no longer invalidates their
  credential**.
- Failure taxonomy for the OPAQUE path: a tenant with OPAQUE disabled, an absent
  library, and a key-stretching function this build cannot perform are all
  `NetworkError` (a caller can fall back, or an operator can act); everything
  else is `AuthError` and must NOT be retried over `login()` (§23.4 rule 7).

### Removed

- **BREAKING** — SRP-6a. `loginSrp`, `srpEnrollment`, `srpAvailable`, the whole
  `io.axiam.sdk.srp` package, `srp-test-vectors.json` and `examples/srp-login`
  are all gone. AXIAM's server-side SRP endpoints are removed in the same
  release, so keeping the client would leave methods that only ever return 404.
- **BREAKING** — `org.bouncycastle:bcprov-jdk18on` is no longer a dependency. It
  was here for the SRP client's Argon2id and nothing else in `src/main` imported
  it. Applications relying on it transitively must declare it themselves.

### Fixed

- OPAQUE: a refused key-stretching function no longer strands the exchange's
  native state handle. `finish()` spent the handle before building the KSF, so
  an unrecognised function or an out-of-band cost left it out of its one-shot
  slot and unreachable by `close()` or the `Cleaner` — a leaked Rust allocation
  once per login attempt against a misconfigured tenant. The KSF is now built
  first, so a refusal leaves the exchange intact: it is released normally, and a
  caller who fixes the parameters can retry.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#34)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#33)

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative reactor handler binding — reactorHandlers { }

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the §22 reactor runtime (R2.5) (#30)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#27)
- SubjectTokenType is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §20.3 — emit a UMA challenge from the §11 guard (#21)
- §20 — UMA 2.0 Protection API and ticket grant
- Report a clamped decision-memo TTL (contract 1.9, §19.2 rule 6)
- §16 retry, §17 memo, §18 close(), §19 telemetry (D5)
- Device grant, token exchange, logout helpers; re-vendor (D6)
- **CONTRACT.md §22 — the reactor runtime (`io.axiam.sdk.reactor`).** A reactor is an
  external process subscribed to named hook events on the AMQP bus, answering
  allow / deny / mutate inside a timeout the server declared. `reactorServe(options)`
  consumes the **server-declared** queue, verifies each event under §8 v2 (key
  version, MAC, freshness, nonce, in that order) before the handler sees it, and
  signs the reply with the same tenant subkey.

  **This closes half of Kotlin's §8 gap rather than working around it.** §22.10 is
  explicit that a reactor runtime *is* an AMQP consumer and that there is no
  reactor-shaped subset of §8 that would let one arrive without the other, so the
  §8 v2 verification set (HKDF-derived tenant subkey via
  `ReactorProtocol.deriveTenantKey`, constant-time `HMAC-SHA256`, the `key_version`
  floor of 2, the ±300 s two-sided freshness window, a bounded nonce seen-set) and
  §8b's transport rules arrive with it. `reactorConnectionFactory` **enforces** §8b:
  `amqps://` only, a supplied CA bundle for a privately-issued broker certificate,
  hostname verification with no switch to disable it, half a client identity
  failing closed, and no plaintext fallback. §8's other two message types
  (`AuthzRequest`, `AuditEventMessage`) remain out of scope.

  The canonicalization difference that costs a day if it is not stated: a reactor
  body is signed with `hmac_signature` **present and set to `null`**, where §8's own
  two message types omit it. `ReactorProtocol` is the only place that rule lives,
  and `ReactorVectorTest` proves it byte-for-byte against the server-generated
  §22.13 vectors — canonical bytes, MAC, the omission of `reason`/`patch` when
  absent and of `require_mfa` when false, the `nonce_binding` pair, the
  `correlation_replay` refusal, the stale/future pair, and the topology strings.
  Both fixtures ship on the test classpath under the same master key, tenant and
  derived subkey, so one loader serves both and the §8-vs-§22 difference is a test
  rather than a paragraph to remember.

  Four rules are structural rather than documented. The runtime declares no
  exchange, queue or binding — `ReactorTransport` has no method that could, and a
  proxy-recorded `Channel` proves the bundled RabbitMQ transport never reaches past
  it; a handler that throws produces **no reply** rather than a synthesized
  `allow`, so the operator's `failure_policy` still decides; a patch is sent
  **unfiltered**, because dropping a forbidden key would leave the author believing
  it was set; and a reply is abandoned rather than published after `timeout_ms` has
  elapsed. `ReactorDecision` is a sealed hierarchy in which `allow` cannot carry a
  patch and `mutate` cannot be empty, and `ReactorListener` returns `Unit`, so a
  listener cannot publish a reply at all.

  §22.7 is honoured as the MUST NOT it is: `authz.check`, `authz.check_batch` and
  `token.introspect` are absent from `ReactorEvents.REGISTRY` and from every
  constant this SDK exposes, asserted against the list rather than a comment, and
  no interceptor equivalent is offered for them anywhere.

  Interacts with the existing surfaces as they already work: `close()` is
  §18-deterministic (cancel, drain, idempotent), §19 emits one
  `RequestStart`/`RequestEnd` pair per dispatch with the event name as the path
  template, the signing key is wrapped in `Sensitive` per §22.12 and asserted absent
  from every log line, and §16 retry deliberately does **not** apply to a reply — a
  correlation is single-use, so a resend could only add load to a server that has
  already moved on.

  `com.rabbitmq:amqp-client` is a **`compileOnly`** dependency, exactly as Ktor is:
  the core compiles and runs without it, and a consumer who writes no reactor never
  carries it. Adds `examples/reactor` (a token enricher plus a login screen) and a
  README chapter.

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `JwksVerifier.verifyTokenBinding(claims, PresentedProofs)` applies the full
  ten-row rule against a certificate thumbprint, a verified DPoP key thumbprint,
  or **both**. A `cnf` naming both methods is a **conjunction** — satisfying only
  the more convenient one is not compliance — and a `cnf` naming nothing this SDK
  can check (including an *empty* one, which is how proto3 delivers an empty
  `CnfClaim`) is refused rather than read as unbound. `verifyCertificateBinding`
  remains for certificate-only transports and now **refuses** a DPoP-bound or
  both-bound token rather than ignoring the half it cannot check.

  New `DpopVerifier` implements all ten §21.7.2 checks and returns the proof
  key's RFC 7638 thumbprint, so a value passed to `PresentedProofs` could only
  have come from a proof that verified. `DpopVerifier.InMemoryJtiStore` covers
  check 8 for a single JVM; the `JtiStore` argument is required, not optional,
  because there is no safe default that skips replay tracking.

  Two design points: the JWS verifier is chosen from the embedded key's own type
  so an HMAC verifier is never reachable (the test runs the real
  public-key-as-HMAC-secret forgery), and the `jti` is claimed **last**, so a
  stream of invalid proofs cannot burn `jti` values out of the store and deny
  service to valid ones.

  Not a breaking change: an unbound token is still accepted with no certificate
  and no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwksVerifier.verifyCertificateBinding(claims, presentedThumbprint)` — the rule.
  - `JwksVerifier.certificateThumbprintS256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url,
    **unpadded**, SHA-256 over the DER certificate (`X509Certificate.encoded`).

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `assertLocalClaims` deliberately does **not** apply rule 9: it has no transport to ask
  for a peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.
- **§15.7 external-IdP subject tokens (X4).** `tokenExchange` can now exchange a token minted by a
  trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what
  the resolved AXIAM user may actually do. No new operation: the same method, plus
  `TokenExchangeParams.subjectTokenType` and the new `JWT_TOKEN_TYPE` constant
  alongside the existing `ACCESS_TOKEN_TYPE`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and a
  wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted by
  a test. (This shipped as `String? = null` with an `…:access_token` default; contract 1.13 made
  it non-null and required — see *Changed* above.)

  The property sits second in `TokenExchangeParams`, next to the `subjectToken` it describes and
  matching the other SDKs.

  Also asserted: an `actorToken` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as a
  different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* — reaches
  the caller intact; and nothing re-exchanges an exchanged token, which both server paths refuse
  because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12 plus
  §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's `/oauth2/*`
  error rows dispatching on the `error` field at any status, and the `TokenExchangeTrust` schemas
  behind the X4 provider configuration.

- **§20.3 challenge emission from the §11 guard.** `AxiamAuthConfig.umaChallenge` takes a
  `UmaChallenger` (realm, `as_uri`, PAT, client); with one configured, a `requireAccess` denial
  mints a permission ticket for the action that was refused and returns it as
  `WWW-Authenticate: UMA` alongside the unchanged 403 body.

  It is **opt-in** because emitting a challenge means minting a credential: a guard that did it
  by default would turn every unauthorized request into a Protection API call, which is a
  denial-of-service amplifier pointed at your own authorization server. An allow mints nothing.
  And a **minting failure is not an escalation** — an expired PAT or an unreachable Protection
  API still yields the plain 403, never a 503 and never an allow. Both are asserted by counting
  Protection API calls. The requested scope is the AXIAM *action*, so the ticket asks for
  exactly the authority just refused and the engine's deny rules keep applying to whatever RPT
  comes back.

  Paired with the new `examples/uma-resource-server` and `examples/uma-client` (and their
  `runUmaResourceServerExample` / `runUmaClientExample` tasks), which run both halves —
  including the trust decision §20.3 keeps in the caller's hands rather than auto-exchanging
  against whatever host a 403 named.

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

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#29)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#26)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams.subjectTokenType` is now required**, and its
  type narrows from `String?` to `String` with no default.

  It shipped as `String? = null`, defaulting to `ACCESS_TOKEN_TYPE` — which satisfied §15.7's
  "never inspect the subject token" while leaving the rule it serves unenforced: an optional
  property with a default *is* a default the SDK applies whenever the caller says nothing. §15.1
  now makes it required.

  **`ACCESS_TOKEN_TYPE` and `JWT_TOKEN_TYPE` are now public top-level constants** in
  `io.axiam.sdk.oidc`, rather than members of the `internal` `OidcSupport`. They were
  unreachable from outside the module — survivable while the type was optional and defaulted,
  and not once naming it is mandatory: a caller could not have named it at all without retyping
  the URN. `OidcSupport`'s copies now delegate to them, so there is one source of truth. This
  was caught by `compileExamplesKotlin`, which the example could not compile against.

  **Dropping the nullability is the point rather than a side effect.** A property that can hold
  "no answer" forces the SDK to have one ready, and any answer it picks is the guess §15.7
  forbids. `String` cannot represent "the caller declined to say", so the compiler carries the
  rule: omitting the argument does not compile.

  **Migration** — one line, naming what you were previously getting by silence:

  ```kotlin
  val exchanged = client.tokenExchange(
      TokenExchangeParams(
          subjectToken = Sensitive.of(userToken),
          subjectTokenType = ACCESS_TOKEN_TYPE, // <- add this
          scopes = listOf("orders:read"),
      ),
  )
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only legal
  value when X4 landed. For a caller who actually held a refresh token, the old default traded
  the `invalid_request` that names the type for a generic `invalid_grant`.
- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).
- **Test update:** `AuthzTest."500 maps to NetworkError and redacts non-allowlisted headers"`
  now enqueues three 500s rather than one. That is a direct consequence of §16 — the call now
  makes three attempts, and the assertion is about the error the caller finally sees.

### Fixed

- R5.7 remediation — F-13, F-14 (F-03 already fixed) (#28)
- Make the token-type constants public
- **F-13: the §12.4 rule 7 (all-or-nothing discard) test only asserted that `oidcExchange`
  throws, not that the same response's sentinel access/refresh token is absent from the
  outcome or the exception.** `OidcCoverageGapsTest`'s clock-skew test now uses a
  `"should-never-be-returned"` sentinel and positively asserts it appears in neither
  `AuthError.message` nor `AuthError.toString()`, matching the five sibling SDKs that
  already did.
- **F-14: `OidcSupport.executeRequest()` (the transport seam every §12 wire call goes
  through) now documents, in a doc comment, the structural invariant that keeps a `401`
  from `/oauth2/*` out of the §9 single-flight refresh guard — no OkHttp `Authenticator`
  or response interceptor reacts to a `401` on this `httpClient`.** The prior regression
  test polled the mock server's request queue with a fixed 200ms timeout; it is replaced
  with a deterministic dispatcher-registered call counter for `POST /api/v1/auth/refresh`,
  so `OidcIntrospectRevokeTest` now asserts `refreshCallCount == 0` rather than draining a
  queue against a timeout.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set
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

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#16)
- Device (mTLS) tokens now carry aud=axiam:m2m (#15)
- Service accounts can use login_client_credentials (#14)
- Reject a failed token in the Ktor plugin (§15.3.3) (#13)
- Close the coverage margin with real value-semantics tests (§12.6.4) (#12)

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

### Fixed

- Reject plaintext base URL, pin discovery jwks_uri origin, add webhook verifier

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

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT.md §12)
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

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- §9 rule 6 — never let a caller's cancellation own the shared refresh
- Widen Sensitive.expose() to public (F-03, CONTRACT §7 rule 3)
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

### Changed

- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

### Deferred (follow-ups, not in this release)

- gRPC transport (the contract's gRPC error/mTLS/single-flight surfaces).
- §8 AMQP HMAC message consumption — the contract does not require AMQP of the Kotlin SDK.
