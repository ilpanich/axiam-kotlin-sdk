# axiam-sdk-kotlin

[![CI](https://github.com/ilpanich/axiam-kotlin-sdk/actions/workflows/sdk-ci-kotlin.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-kotlin-sdk/actions/workflows/sdk-ci-kotlin.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-kotlin-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-kotlin-sdk?branch=main)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.ilpanich/axiam-sdk-kotlin.svg)](https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk-kotlin)
[![javadoc](https://javadoc.io/badge2/io.github.ilpanich/axiam-sdk-kotlin/javadoc.svg)](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk-kotlin)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Kotlin client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

Source: [ilpanich/axiam-kotlin-sdk](https://github.com/ilpanich/axiam-kotlin-sdk)

## Package identity

- **Maven coordinates:** `io.github.ilpanich:axiam-sdk-kotlin`
- **GroupId:** `io.github.ilpanich`
- **ArtifactId:** `axiam-sdk-kotlin`
- **Registry:** Maven Central (Sonatype Central Portal) _(reserved, not yet published)_
- **API docs:** [javadoc.io](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk-kotlin) — served from the Dokka `-javadoc.jar`
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§7, §9–§12 (including §6.1 mTLS).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract. AXIAM is
multi-tenant: a tenant identifier is a **required** constructor argument (§5) — there is no
default tenant.

### Scope of this SDK (v1)

- **In scope:** the REST surface — authentication (`login`, `verifyMfa`, `refresh`, `logout`),
  authorization (`checkAccess`, `can`, `batchCheck`), the §2 error taxonomy, §3 CSRF
  forwarding, §4 per-client cookie jar, §5 tenant header, §6 strict TLS + §6.1 mTLS client
  certificates, §7 `Sensitive`, §9 single-flight refresh, JWKS (EdDSA/Ed25519) session
  verification, the §10/§11 Ktor route guard + declarative-authorization helpers, and the
  §12 OIDC/SSO relying-party helpers (see "OIDC / SSO relying-party helpers" below).
- **Deferred follow-ups (not in v1):** the gRPC transport — including the gRPC-only
  `getUserInfo` operation (CONTRACT §1.1, contract 1.3) — and §8 AMQP HMAC consumption. The
  contract does not require AMQP of the Kotlin SDK; gRPC (and with it `getUserInfo`) is a
  planned addition. Per CONTRACT §1.1, this SDK does **not** substitute the REST
  `/oauth2/userinfo` endpoint for the gRPC operation.

## Getting started

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha18")
    // Optional — only if you use the Ktor route guard / §11 helpers:
    implementation("io.ktor:ktor-server-core:2.3.12")
}
```

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk-kotlin</artifactId>
  <version>1.0.0-alpha18</version>
</dependency>
```

## Quickstart

Every operation is a `suspend` function (coroutines) — the canonical name IS the suspend form
(§1); there are no `*Async` twins. Use `runBlocking` for a blocking call site.

```kotlin
import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import kotlinx.coroutines.runBlocking

runBlocking {
    // §5.1: login/refresh require organization context in addition to the
    // tenant (a tenant slug is only unique within an org) — supply it with
    // .orgSlug("acme") (or .orgId(UUID)), else login fails with HTTP 400
    // "must provide org_id or org_slug".
    AxiamClient.builder("https://axiam.example.com", tenantId = "acme")
        .orgSlug("acme")
        .build()
        .use { client ->
            // Authentication
            val result = client.login("alice@example.com", "s3cret")
            if (result.mfaRequired) {
                client.verifyMfa(result.challengeToken!!, totpCode = "123456")
            }

            // Authorization — argument order is always (action, resource[, scope])
            if (client.can("documents:read", resourceId = "3f2c…")) {
                println("allowed")
            }

            val results = client.batchCheck(
                listOf(
                    io.axiam.sdk.AccessCheck("documents:read", "doc-1"),
                    io.axiam.sdk.AccessCheck("documents:delete", "doc-1"),
                ),
            )

            client.logout()
        }
}
```

Access, refresh, and MFA-challenge tokens are wrapped in `Sensitive<T>`, whose `toString()`
is always `"[SENSITIVE]"` — tokens never leak into logs, error messages, or stack traces (§7).

## TLS and mTLS

Strict server certificate verification is **always on** (§6). There is no `insecure()` /
`skipTlsVerification()` surface anywhere in this SDK. The only escape hatch is a custom CA
added to (never replacing) the system trust store:

```kotlin
AxiamClient.builder(baseUrl, "acme")
    .customCa(File("dev-ca.pem").readBytes())   // PEM only
    .build()
```

For IoT / service-account **mutual TLS** (§6.1), present a client identity certificate (a PEM
cert chain plus a PEM PKCS#8 private key). It is applied to the client's transport and the
private key is held behind `Sensitive` — never logged or exposed:

```kotlin
AxiamClient.builder(baseUrl, "acme")
    .clientCertificate(
        certPem = File("device.crt").readBytes(),
        keyPem = File("device.key").readBytes(),   // PKCS#8 PEM
    )
    .build()
```

## Framework integration (§10 / §11)

For **Ktor**, install the `AxiamAuthentication` plugin with a client; it verifies the incoming
session (EdDSA/JWKS, tenant scoping, expiry) and injects an `AxiamUser`. The §11 helpers
(`requireAuth`, `requireAccess`, `requireRole`) and the annotation-driven `enforce` compose on
top of it:

```kotlin
import io.axiam.sdk.ktor.*

install(AxiamAuthentication) { client = axiamClient }

routing {
    get("/documents/{id}") {
        val user = call.requireAccess("documents:read", call.parameters["id"]!!) ?: return@get
        call.respondText("hello ${user.userId}")
    }
}
```

The framework-free annotations `@AxiamRequireAuth`, `@AxiamRequireAccess(action, …)`, and
`@AxiamRequireRole(…)` are also provided (`io.axiam.sdk.annotations`). **Spring Boot** users can
reuse the Java SDK's `AxiamAuthorizationInterceptor` (`io.github.ilpanich:axiam-sdk`), which
enforces the same annotation vocabulary.

## OIDC / SSO relying-party helpers (§12)

Nine canonical operations (CONTRACT.md §12) let this SDK offer "Login with AXIAM"
(authorization-code + PKCE), service-account machine-to-machine login, token
introspection/revocation, and the upstream-IdP federation pair — all as `suspend`
functions directly on `AxiamClient` (no separate client type, no `*Async` twins):

| Operation | Wire call | Notes |
| --- | --- | --- |
| `oidcDiscover()` | `GET /.well-known/openid-configuration` | Cached ≥5 min, single-flight, per-client-instance |
| `oidcBegin(params)` | *(none — pure local computation)* | **Not `suspend`**: no network I/O (§12.1). Builds `state`/`nonce`/PKCE `codeVerifier` |
| `oidcExchange(params)` | `POST /oauth2/token` (`authorization_code`) | Validates the `id_token` in full (§12.4) before returning |
| `oidcRefresh(params)` | `POST /oauth2/token` (`refresh_token`) | Own single-flight guard (§9); distinct from `refresh()` |
| `loginClientCredentials(params?)` | `POST /oauth2/token` (`client_credentials`) | No `openid` scope, no `id_token` |
| `introspect(params)` | `POST /oauth2/introspect` | Requires confidential-client credentials |
| `revoke(params)` | `POST /oauth2/revoke` | Idempotent: any `200` (including for an unknown token) is success |
| `ssoStart(params)` | `POST /api/v1/auth/federation/oidc/start` | Upstream-IdP SSO step 1 — no JWT required |
| `ssoComplete(params)` | `POST /api/v1/auth/federation/oidc/callback` | Step 2 — session arrives as `Set-Cookie` via the §4 cookie jar |

Configure the relying party's `client_id`/`client_secret` **at construction time** (needed by
`oidcExchange`'s §12.4 rule 4 audience check, so it can never disagree with a per-call value):

```kotlin
val client = AxiamClient.builder(baseUrl, tenantId = "22222222-2222-2222-2222-222222222222")
    .oidcClientId("my-app")
    .oidcClientSecret("secret")   // omit for a public client
    .build()
```

### The caller owns all login state (§12.3 rule 1)

`oidcBegin` and `oidcExchange` are **stateless**: the SDK stores no copy of `state`, `nonce`, or
`codeVerifier` anywhere. Persist the three values returned by `oidcBegin` in your own session
between the login redirect and the callback, and pass `nonce`/`codeVerifier` back into
`oidcExchange` explicitly:

```kotlin
val configuration = client.oidcDiscover()
val request = client.oidcBegin(
    OidcBeginParams(configuration = configuration, redirectUri = redirectUri, scope = "openid profile"),
)
// …persist request.state / request.nonce / request.codeVerifier, then redirect the browser…
res.redirect(request.url)

// …on the callback, having checked the returned `state` matches…
val tokens = client.oidcExchange(
    OidcExchangeParams(
        code = code,
        codeVerifier = request.codeVerifier,
        redirectUri = redirectUri,
        nonce = request.nonce,
    ),
)
println(tokens.idClaims?.sub)   // the validated ID-token subject (§12.4)
```

`OidcStateStore` / `MemoryOidcStateStore` (`io.axiam.sdk.oidc`) are an **optional** reference
implementation of that same pattern (10-minute TTL, single-use `consume`) for a redirect flow
split across two separate HTTP requests — the Ktor glue below uses one internally.

### Ktor "Login with AXIAM" glue

```kotlin
import io.axiam.sdk.ktor.axiamOidcLogin

routing {
    axiamOidcLogin(
        client = axiamClient,
        redirectUri = "https://app.example.com/auth/callback",
        onSuccess = { tokens, entry -> /* establish YOUR OWN session here */ },
    )
}
```

Installs a `GET /login` (redirect to the IdP) and a `GET /callback` (exchanges the code) pair,
using an in-memory `OidcStateStore` by default. Kept `compileOnly`-safe exactly like
`AxiamAuthentication` — the core §12 operations above compile and run with Ktor absent from a
consumer's classpath; only importing `io.axiam.sdk.ktor.*` requires adding `ktor-server-core`.

### Error taxonomy additions (§12.3 rule 3)

An RFC 6749 `OAuth2ErrorResponse` body (e.g. `invalid_grant`) surfaces as `OAuthProtocolError`
— a **subclass of `AuthError`**, so existing `catch (e: AuthError)` handling keeps matching it —
exposing `error`/`errorDescription` with `message` exactly `"<error>: <error_description>"`. A
§12.4 ID-token validation failure raises a plain `AuthError` whose `reason` carries one of the
seven stable codes: `invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`,
`invalid_audience`, `token_expired`, `nonce_mismatch`.

The five §12.5 secret fields — `accessToken`, `refreshToken`, `idToken`, `oidcClientSecret`, and
`AuthorizationRequest.codeVerifier` — are `Sensitive<String>`, exactly like every other token
material in this SDK (§7); `state` and `nonce` are not secrets and are plain strings.

See [`examples/oidc-login/OidcLoginExample.kt`](examples/oidc-login/OidcLoginExample.kt) for a
complete, framework-free walk-through of all nine operations.

## Building from source

```bash
./gradlew build            # compile + test
./gradlew test koverXmlReport   # tests + coverage report (build/reports/kover/report.xml)
./gradlew dokkaJavadocJar  # API docs jar
```

Targets JVM 17. CI runs on JDK 17 via `gradle/actions/setup-gradle`.
