# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
