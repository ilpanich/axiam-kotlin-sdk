# axiam-sdk-kotlin

[![CI](https://github.com/ilpanich/axiam-kotlin-sdk/actions/workflows/sdk-ci-kotlin.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-kotlin-sdk/actions/workflows/sdk-ci-kotlin.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-kotlin-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-kotlin-sdk?branch=main)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.ilpanich/axiam-sdk-kotlin.svg)](https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk-kotlin)
[![javadoc](https://javadoc.io/badge2/io.github.ilpanich/axiam-sdk-kotlin/javadoc.svg)](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk-kotlin)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Kotlin client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

Source: [ilpanich/axiam-kotlin-sdk](https://github.com/ilpanich/axiam-kotlin-sdk)

## Package identity

- **Maven coordinates:** `io.github.ilpanich:axiam-sdk-kotlin`
- **GroupId:** `io.github.ilpanich`
- **ArtifactId:** `axiam-sdk-kotlin`
- **Registry:** Maven Central (Sonatype Central Portal) _(reserved, not yet published)_
- **API docs:** [javadoc.io](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk-kotlin) — served from the Dokka `-javadoc.jar`
- **License:** Apache-2.0
- **Kotlin:** 2.1.0 minimum · **JVM:** 17 minimum — see [Supported Kotlin and JVM versions](#supported-kotlin-and-jvm-versions)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§7, §9–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23,
§24, §25, §26, §27 (including §6.1 mTLS).

§12.7, §14, §15, §20, §22, §23, §24, §25, §26 and §27 are named rather than folded into the range
because they landed after this SDK already stated its coverage: widening the range silently would
turn a statement that was true when written into a different claim without anyone editing it.

**§27 is the Management API** — all 147 operations across 24 namespaces, with the §27.6 declarative
layer. See [Management API](#management-api-27) below.

**§24.6b — the linked-API ceremony helper — is deliberately absent, and this is not a capability
gap.** See [WebAuthn / passkeys](#webauthn--passkeys-ioaxiamsdkwebauthn-24) below: Android's
Credential Manager is a JSON string in and a JSON string out, so §24.6a's bridge is what makes this
plain-JVM artifact fully usable from an Android app — no AAR, no Android Gradle Plugin, no second
published coordinate.

**§8 is a narrower gap than it was.** The §22 reactor runtime *is* an AMQP consumer — §22.10 says so
in as many words — so shipping it meant implementing §8's v2 verification set (HKDF-derived tenant
subkey, `HMAC-SHA256` over the canonical bytes compared in constant time, the `key_version` floor of
2, the ±300 s two-sided freshness window, the nonce seen-set) and §8b's transport rules
(`amqps://` only, a supplied CA bundle, no verification-skip switch, no plaintext fallback) for the
reactor exchange. What remains out of scope is §8's *other* two message types, `AuthzRequest` and
`AuditEventMessage`, and the async-authz and audit-ingestion surfaces built on them — which is why
the range is still written with a gap at §8 rather than as §1–§13.

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract. AXIAM is
multi-tenant: a tenant identifier is a **required** constructor argument (§5) — there is no
default tenant.

### Scope of this SDK (v1)

- **In scope:** the REST surface — authentication (`login`, `verifyMfa`, `refresh`, `logout`),
  authorization (`checkAccess`, `can`, `batchCheck`), the §2 error taxonomy, §3 CSRF
  forwarding, §4 per-client cookie jar, §5 tenant header, §6 strict TLS + §6.1 mTLS client
  certificates, §7 `Sensitive`, §9 single-flight refresh, JWKS (EdDSA/Ed25519) session
  verification, the §10/§11 Ktor route guard + declarative-authorization helpers, the
  §12 OIDC/SSO relying-party helpers (see "OIDC / SSO relying-party helpers" below), and the
  §13 webhook-signature verifier (see "Webhook signature verification" below), the §24 WebAuthn
  relying-party layer with its §24.6a JSON bridge, the §25 account-lifecycle and MFA-enrolment
  operations, and §26 Pushed Authorization Requests. Plus, on the AMQP side, the §22 reactor
  runtime (see "Reactors" below) and the §8 v2 / §8b primitives it carries.
- **Deferred follow-ups (not in v1):** the gRPC transport — including the gRPC-only
  `getUserInfo` operation (CONTRACT §1.1, contract 1.3) — and §8's `AuthzRequest` /
  `AuditEventMessage` consumers (async authorization and audit ingestion). The contract does not
  list Kotlin among the SDKs that speak those; gRPC (and with it `getUserInfo`) is a planned
  addition. Per CONTRACT §1.1, this SDK does **not** substitute the REST `/oauth2/userinfo`
  endpoint for the gRPC operation.

## Getting started

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-beta04")
    // Optional — only if you use the Ktor route guard / §11 helpers:
    implementation("io.ktor:ktor-server-core:2.3.12")
}
```

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk-kotlin</artifactId>
  <version>1.0.0-beta04</version>
</dependency>
```

## Supported Kotlin and JVM versions

This SDK has **two** version axes, and floor + newest applies to each:

| Axis | Floor | Newest tested | What the floor means |
|---|---|---|---|
| **JVM** | 17 | 25 | `jvmTarget` — the bytecode level in every class file. An older JVM fails with `UnsupportedClassVersionError` at class-load. |
| **Kotlin** | 2.1.0 | 2.4.10 | The compiler the artifact is *published* with. An older consumer compiler cannot read the SDK's `@Metadata`. |

Both are exported as `io.axiam.sdk.SupportedVersions`.

**Each floor enforces itself downward; neither enforces itself upward.** That
asymmetry is the whole reason this section exists. JVM 17 bytecode loads on
JDK 25 whether or not anybody ever ran it there, and 2.1-compiled metadata is
read by a 2.4 compiler whether or not anybody ever compiled against it. Both
upper claims are unproven unless something builds them — so the gating matrix in
`sdk-ci-kotlin.yml` runs two legs, each pinning one end of *both* axes:

| Leg | JDK | Kotlin |
|---|---|---|
| floor | 17 | 2.1.0 |
| newest | 25 | 2.4.10 |

### Why the published Kotlin stays at 2.1.0

Kotlin metadata is forward-compatible: a library compiled with 2.1 is readable
by any later compiler. Compiling the *published* artifact with 2.4 would not
widen support, it would **narrow** it — every consumer still on 2.1, 2.2 or 2.3
would be locked out. So the published compiler stays at the floor and the newest
leg proves the forward direction still holds. That is the same shape as the JVM
axis: build at the floor, prove it works at the newest.

Both ends are Gradle properties, so either leg is reproducible locally:

```bash
./gradlew test                                              # floor
./gradlew test -PkotlinVersion=2.4.10 -PtestJavaVersion=25  # newest
```

### Why the tests fork a separate JVM

`-PtestJavaVersion` selects a **toolchain launcher for the test JVM only** —
Gradle itself keeps running on JDK 17.

That separation is not incidental. Gradle 8.10.2 cannot run on Java 25 at all;
it aborts with a bare, unrecognised `25.0.4` before configuring anything. So
simply pointing `JAVA_HOME` at 25 does not test the SDK on Java 25 — it kills
the build. And the claim being made here was never about Gradle's own runtime:
it is that the SDK's **JVM 17 bytecode runs on a modern JVM**, which is a
statement about the process the tests execute in. A toolchain launcher says
exactly that and nothing more.

`VersionPolicyTest` asserts the fork actually happened, comparing the JVM it is
running on against the version the build requested. A toolchain that silently
fell back to Gradle's JVM would otherwise leave the leg green while testing
nothing it was added to test.

Kotlin 2.2 and 2.3 and JDKs 18–24 sit between two green legs. See
[`examples/version-compatibility`](./examples/version-compatibility) for a
runnable preflight, and `VersionPolicyTest` for the gate that fails the build
when `jvmTarget`, `gradle.properties`, the CI matrix and `SupportedVersions`
stop agreeing.

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
session (the full §10.1 set below) and injects an `AxiamUser`. The §11 helpers
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

### What the guard checks (§10.1 minimum local-verification set)

`AxiamClient.verifySession` — the entry point the Ktor plugin uses — applies **all seven** rules.
A signature check alone is not a guard.

| # | Claim | Rule |
| --- | --- | --- |
| 1 | signature | Against the org JWKS (`GET /oauth2/jwks`, cached 300s), with `alg` pinned to **EdDSA before key lookup** — `alg: none` and HS-family confusion never reach a key. |
| 2 | `exp` | **Required.** Absent or non-numeric ⇒ reject. An absent `exp` is a permanent credential, not "no expiry constraint". |
| 3 | `nbf` | Honoured when present; a future `nbf` rejects. Absent `nbf` is fine. |
| 4 | `tenant_id` | **Required** and matched against the configured tenant. |
| 5 | `iss` | Checked only when `expectedIssuer(...)` was configured on the builder. |
| 6 | `aud` | Checked only when `expectedAudience(...)` was configured on the builder. |
| 7 | clock skew | One named 60s constant, `JwksVerifier.CLOCK_SKEW_SECONDS`, on rules 2 and 3. Not settable. |

Every rule fails **closed** — a required claim that is absent, unparseable, or of the wrong JSON
type rejects the token.

```kotlin
val guardClient = AxiamClient.builder(baseUrl, tenantId = "22222222-…-uuid")
    .expectedIssuer("https://axiam.example.com")   // optional; unset ⇒ `iss` not checked
    .expectedAudience("axiam:user")                // optional; unset ⇒ `aud` not checked
    .build()
```

`JwksVerifier.verifySignatureOnlyUnchecked(...)` is the raw signature primitive §10.1 permits for
integrators writing their own policy. As its name says, it checks **no** claims — it is not a
guard, and the SDK's own guards never stop there.

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

## UMA 2.0 — protecting resources whose owner isn't the caller (§20)

For a resource server holding data that belongs to *users*: instead of answering an
unauthorized request with a bare 403, tell the caller where to go and get authority.

Registration and the ticket grant are suspending methods on `AxiamClient`
(`umaRegisterResource` / `umaReadResource` / `umaUpdateResource` / `umaDeleteResource` /
`umaListResources`, `umaRequestTicket`, `umaExchangeTicket`). Every Protection API call takes
the **PAT** as an explicit first argument — a client-credentials token carrying
`uma_protection` (§20.2 rule 1) rather than the client's ambient session, because that session
is usually a *user* session and a minted ticket binds to a `client_id`.

The registered id **is** the AXIAM resource id, so UMA scopes are AXIAM actions: the same
grants — deny rules included — govern an RPT-carrying request and an ordinary one.

### Emitting the challenge from the §11 guard

Configure a `UmaChallenger` on the plugin and a `requireAccess` denial carries the ticket with
it:

```kotlin
install(AxiamAuthentication) {
    client = axiam
    umaChallenge = UmaChallenger("invoices", configuration.issuer, pat, axiam)
}
// A denied requireAccess(...) now answers 403 with
//   WWW-Authenticate: UMA realm="invoices", as_uri="…", ticket="…"
```

Opt-in, deliberately: minting on every denial by default would put a Protection API call — and
a live credential — behind every unauthorized request, which is a denial-of-service amplifier
pointed at your own authorization server. And a minting failure still denies plainly, never a
503 and never an allow. The requested scope is the AXIAM **action**, so the ticket asks for
exactly the authority just refused.

### Consuming it

`umaParseChallenge(header)` parses and *stops there*. It does not exchange the ticket, because
the `as_uri` it names was chosen by the server that just refused you; auto-redeeming would send
the requesting party's token wherever a 403 pointed. The trust decision is the caller's:

```kotlin
val challenge = umaParseChallenge(response.headers["WWW-Authenticate"] ?: "")
val ticket = challenge?.ticket
if (ticket != null && trustworthy(challenge.asUri)) {
    val rpt = client.umaExchangeTicket(UmaExchangeTicketParams(ticket, userToken))
}
```

`umaExchangeTicket` sends **one** request and never retries — the documented exception to the
§16 retry policy, because a ticket is consumed before the request is evaluated, so a retry
cannot succeed and under concurrency is exactly the double redemption to avoid. On failure,
obtain a *new* ticket.

Both halves run in [`examples/uma-resource-server`](examples/uma-resource-server) and
[`examples/uma-client`](examples/uma-client).

## Device authorization grant (§14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a headless commissioning
tool.

```kotlin
val tokens = client.deviceLogin(
    DeviceLoginParams(
        onUserCode = { authorization ->
            // Called BEFORE the first poll, and awaited — a device rendering a QR code may
            // need a paint first. Display it however the device can; the SDK never prints it.
            println("visit ${authorization.verificationUri} and enter ${authorization.userCode}")
        },
    ),
)
```

`deviceAuthorize` and `devicePoll` are also public, for an application driving its own loop. The
polling rules are where implementations go wrong:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one round and returns
  to the original interval will be told to slow down again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus nobody answered —
  the only information the device can act on.
- **Polling stops at `expiresIn`**, even if the server has not yet said `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the user has already
  approved.

`deviceCode` is `Sensitive`; `userCode` deliberately is not — it exists to be read aloud, and
wrapping it would defeat the one thing it is for. `deviceAuthorize` sends no `client_secret` and
does not refuse a client built without one. The inter-poll wait is `delay`, so cancelling the
calling coroutine cancels the login promptly rather than after the current interval.

Per §14.3 rule 4, `deviceLogin` **returns** the token set; this SDK does not adopt it, matching its
`loginClientCredentials` posture. See
[`examples/device-login/DeviceLoginExample.kt`](examples/device-login/DeviceLoginExample.kt).

## Token exchange (§15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one before calling the
next service.

```kotlin
val exchanged = client.tokenExchange(
    TokenExchangeParams(
        subjectToken = Sensitive.of(userToken),
        subjectTokenType = ACCESS_TOKEN_TYPE, // required (§15.1)
        scopes = listOf("orders:read"),
        audience = "orders-service",
    ),
)
```

Most of what this method does is refuse to be helpful:

- **No default `actorToken`.** Leaving it `null` asks for *impersonation*; the SDK will not quietly
  substitute the client's own session token and turn that into a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than silently narrowing
  precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such property. Re-run the exchange.
- **No adoption.** A MUST NOT, where `loginClientCredentials` adoption is a MAY.

See [`examples/token-exchange/TokenExchangeExample.kt`](examples/token-exchange/TokenExchangeExample.kt).

### External-IdP subject tokens (§15.7)

The same method exchanges a token minted by a **trusted external IdP** — a partner's Entra, Okta
or Keycloak — for an AXIAM token scoped to what the resolved AXIAM user may actually do. There is
no separate operation:

```kotlin
val exchanged = client.tokenExchange(
    TokenExchangeParams(
        subjectToken = Sensitive.of(partnerToken),
        subjectTokenType = JWT_TOKEN_TYPE, // required; named, never guessed
        scopes = listOf("read:orders"),
        audience = "https://orders.internal",
    ),
)
```

- **`subjectTokenType` is yours to state, and is required** (§15.1). The SDK never decodes the
  subject token to pick it, and never overrides what you named. It is non-null with no default —
  omitting it does not compile, because a default would be the SDK choosing for you.
- **No actor token.** Delegation across a trust boundary is unsupported in v1; sending one is
  `invalid_request`, which the SDK will not work around by dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose `errorDescription` is `the subject
  token's issuer is not configured for token exchange` means *fix the AXIAM trust configuration*.
  Every other `invalid_grant` means *fix your token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the partner issuer; never
  strip it, and never read it as an authorization input. It also cannot be exchanged again —
  exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## Logout — RP-initiated and back-channel (§12.7)

`logoutUrl` builds the redirect; `verifyLogoutToken` validates a token the OP **pushed** to your
back-channel endpoint.

```kotlin
val url = client.logoutUrl(LogoutUrlParams(idToken = Sensitive.of(storedIdToken)))

// …and at your registered backchannel_logout_uri:
val verified = client.verifyLogoutToken(logoutToken)
verified.sid?.let { endSession(it) }   // that session ONLY
```

The verifier is where the security weight sits — the input arrives unsolicited and instructs you to
terminate a session. It checks the signature (same JWKS path and same EdDSA/`kid` discipline as
§12.4), `iss`, `aud`, that `events` carries the back-channel-logout key (**the only thing separating
a logout token from an ID token**), that `nonce` is *absent* (its presence is how an ID token gets
replayed as one), that something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare `Boolean`: you have to know *which* session to end.
**Dedup on `jti` yourself** — delivery is at-least-once, so a valid token legitimately arrives twice;
the SDK has no durable store and an in-memory guard would silently drop a real second logout after a
restart.

See [`examples/logout/LogoutExample.kt`](examples/logout/LogoutExample.kt).

## Decision reason codes (§11 rule 9)

`AccessResult.reasonCode` distinguishes `no_grant` ("ask an admin for access") from
`denied_by_rule` ("an admin has already decided") — opposite instructions to the person on the other
end, which is why the contract forbids collapsing them into a bare `false`. `ReasonCode` holds the
three defined values as constants rather than an enum, so an unrecognised code is surfaced verbatim
and never changes `allowed`; `null` means the server did not send one.

## Webhook signature verification (§13)

`io.axiam.sdk.webhook.AxiamWebhooks.verify(...)` verifies the signed-timestamp scheme AXIAM uses
for every webhook delivery (`X-Axiam-Signature: t=<unix>,v1=<hex>` = HMAC-SHA256 over
`"<timestamp>.<raw_body>"`), with a two-sided freshness window (default 300 s) and a
constant-time comparison (`MessageDigest.isEqual`) over the decoded MAC bytes. It returns a
sealed `WebhookVerifyResult` — `Success(WebhookEvent)` or `Failure(WebhookVerifyError)` — never
throws on a bad signature, and never surfaces the expected MAC or the secret in an error message.

**Pass the exact raw request body bytes.** Re-serializing a parsed JSON object changes key order
and/or whitespace and breaks the MAC — read the body as bytes/text before any JSON parsing, and
hand THAT to `verify`.

```kotlin
import io.axiam.sdk.Sensitive
import io.axiam.sdk.webhook.AxiamWebhooks
import io.axiam.sdk.webhook.WebhookVerifyResult

// Ktor example: rawBody is the untouched ByteArray this route received.
fun handleWebhook(rawBody: ByteArray, signatureHeader: String) {
    val webhookSecret = Sensitive.of(System.getenv("AXIAM_WEBHOOK_SECRET"))
    when (val result = AxiamWebhooks.verify(webhookSecret, signatureHeader, rawBody)) {
        is WebhookVerifyResult.Success -> {
            // result.event.deliveryId is the X-Axiam-Delivery header — the
            // at-least-once dedup key. A retry replays a validly-signed body
            // inside the freshness window, so keep a short-lived seen-set of
            // delivery ids if double-processing must be avoided.
            println("verified ${result.event.eventType} (delivery=${result.event.deliveryId})")
        }
        is WebhookVerifyResult.Failure -> {
            // result.error is one of MalformedHeader / SignatureMismatch /
            // StaleTimestamp / FutureTimestamp — reject the delivery (e.g. 400).
            println("rejected: ${result.error}")
        }
    }
}
```

## Reactors — AMQP extension actors (`io.axiam.sdk.reactor`, §22)

A **reactor** is your process, subscribed to named hook events on the AXIAM AMQP bus, answering
allow / deny / mutate inside a timeout the server declared. It is AXIAM's answer to Zitadel Actions
and Keycloak SPIs, and the difference is the whole design: those load third-party code *into* the
authorization server, and this keeps it outside, reachable only through a signed reply schema the
server validates before it believes a word of it.

```kotlin
val connection = reactorConnectionFactory(
    uri = "amqps://broker.internal:5671",     // §8b: amqps only, enforced not documented
    customCaPem = File(caPath).readBytes(),   // an in-cluster broker is not publicly issued
).newConnection()

val options = ReactorServeOptions(
    transport = RabbitMqReactorTransport(connection.createChannel()),
    tenantId = tenantId,
    signingKey = Sensitive.of(subkeyBytes),   // §22.12 — a credential, never logged
    reactorId = reactorId,                    // the queue is the server's; we only consume it
    handler = ReactorHandler { event ->
        when (event.event) {
            ReactorEvents.TOKEN_PRE_ISSUE ->
                ReactorDecision.mutate(mapOf("ext.department" to "engineering"))
            ReactorEvents.LOGIN_POST_AUTH ->
                if (embargoed(event)) ReactorDecision.deny("embargoed region")
                else ReactorDecision.allow()
            else -> ReactorDecision.allow()
        }
    },
)

reactorServe(options).use { server ->
    println("serving ${server.queue}")
    Thread.currentThread().join()
}
```

### Binding handlers per event (§22.14)

The `when` above is the shape every multi-event reactor grows, and its `else` branch —
`ReactorDecision.allow()` — answers on behalf of code that never ran. That is the defect
§22.10 rule 2 forbids the *runtime* from committing, relocated into your file where the rule
does not reach it: an operator who set `fail_closed` on the registration has it defeated there.

`reactorHandlers { }` is §22.14's declarative form for Kotlin:

```kotlin
val options = ReactorServeOptions(
    transport = RabbitMqReactorTransport(connection.createChannel()),
    tenantId = tenantId,
    signingKey = Sensitive.of(subkeyBytes),
    reactorId = reactorId,
    handler = reactorHandlers {
        on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.mutate(mapOf("ext.department" to "engineering")) }
        on(ReactorEvents.LOGIN_POST_AUTH) { event -> screen(event) }
    },
)
```

- **A misspelled event is refused when you bind it** — `on(...)` accepts only §22.5 registry
  names, which is also how it refuses the three hot-path operations §22.7 excludes: they are
  in no registry row. The message names the registry, never the exclusions.
- **An unbound event abstains** — the composed handler throws
  `UnboundReactorEventException`, and `ReactorServer` publishes **nothing** for a handler
  that threw, so the registration's `failure_policy` decides (§22.8) exactly as it decides a
  timeout. Never a synthesized `allow`.
- Binding the same event twice throws rather than silently overwriting, and
  `reactorHandlerEvents { … }` feeds `ReactorEvents.defaultFailurePolicyFor` so you can see
  what an unreachable reactor costs before you go live.

A type-safe builder rather than the `@OnReactorEvent` annotation the Java SDK ships, and the
reason is worth stating: a Kotlin handler is a `suspend` function, and collecting annotated
`suspend` members needs `kotlin-reflect` on every consumer's runtime classpath to invoke
through the hidden `Continuation` parameter. A builder is Kotlin's own declarative
mechanism, costs no dependency, and — because the lambda is checked against
`suspend (ReactorEvent) -> ReactorDecision` at compile time — catches a wrong-shaped handler
earlier than reflection ever could.

It is pure sugar: what it returns is exactly the `ReactorHandler` `reactorServe` already
takes. It opens nothing, verifies nothing, signs nothing, does not filter a patch, and a
handler's own throwable reaches the runtime unchanged so nothing is published.

Register the reactor first — the queue it consumes is declared by the **server**, from a
`POST /api/v1/reactors` registration. See [`examples/reactor`](examples/reactor) for a runnable one
that enriches a token and screens a login.

The handler is a `suspend` function, so it can call the rest of this SDK — a fraud lookup, a
`checkAccess` — without a thread being blocked by hand.

### Both directions are signed

The server signs the event with the tenant's HKDF-derived AMQP subkey; this SDK signs the reply with
**the same** subkey. An unsigned or stale reply is not a weak reply — the server discards it as
though the reactor had never answered, and the registration's `failure_policy` takes over.

Everything is §8 v2 verbatim (same key derivation — `ReactorProtocol.deriveTenantKey` if you hold the
master key rather than fetching the subkey from the management API — same constant-time
HMAC-SHA256, same ±300 s window applied in **both** directions, same `key_version` floor of 2) with
**one** difference, and it is the one that costs an implementer a day if it is not stated: a reactor
body is signed with `hmac_signature` **present and set to `null`**, where §8's own two message types
omit it. `ReactorProtocol` is the only place that rule lives, and it is proven byte-for-byte against
the server-generated §22.13 vectors — including the omission rules for `reason`, `patch` and
`require_mfa` (a reply serializing `"require_mfa": false` rather than omitting it produces a
different MAC).

Before your handler runs, the runtime rejects `key_version < 2`, verifies the MAC, checks freshness
in **both** directions, and checks the nonce. A runtime that hands an unverified payload to user
code has already lost.

### Transport (§8b)

`reactorConnectionFactory(uri, customCaPem, clientCertPem, clientKeyPem)` builds the broker
connection factory, and it **enforces** §8b rather than documenting it: an `amqp://` URI is refused
rather than downgraded, hostname verification is on with no switch anywhere to turn it off, a
private CA is supported because an in-cluster broker's certificate is not publicly issued, and half
a client identity (a certificate without its key, or the mirror case) fails closed rather than
connecting without the mutual half. There is no plaintext fallback: a failed `amqps://` connection
is an error to surface, not a condition to work around.

The RabbitMQ Java client is a **`compileOnly`** dependency of this SDK, exactly as Ktor is — the
core compiles and runs without it, and a consumer who writes no reactor never carries it. Reactor
authors add `com.rabbitmq:amqp-client` themselves. `ReactorTransport` is the seam if you use a
different client: five verbs, and deliberately no `declare` or `bind` among them.

### Five events, and what each may change

| Event | Mutable fields (the complete allow-list) | Default failure policy |
|---|---|---|
| `token.pre_issue` | **`ext.` namespace only** | `fail_open` |
| `login.post_auth` | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `user.pre_update` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `grant.pre_assign` | — (veto only) | `fail_closed` |

An entry ending in `.` is a namespace prefix and needs at least one character after the dot:
`ext.department` and `ext.a.b.c` are in, and `ext.`, `ext`, `extra`, `external_id` and
`evil.ext.department` are not. No standard claim is reachable from `token.pre_issue`, because none
of them begins with `ext.` — a **correctly signed** reply setting `sub` is refused exactly as a
forged one is.

A registration naming no `failure_policy` inherits the **strictest** default among its events, in
either array order (`ReactorEvents.defaultFailurePolicyFor`). A reactor registered for both
`token.pre_issue` and `login.post_auth` can veto a login, so it gets `fail_closed`.

### `authz.check` is not hookable, and never will be

`authz.check`, `authz.check_batch` and `token.introspect` are **absent** from
`ReactorEvents.REGISTRY` and from every constant this SDK exposes — asserted by a test against the
list, not documented by a comment. The reason is arithmetic, not policy: a reactor round trip is
milliseconds and the check path's budget is microseconds. Hooking it would not produce a slower
check, it would produce a different product.

This SDK also offers no interceptor, middleware hook or callback presenting itself as the reactor
equivalent for those operations. An application that needs external input on an authorization
decision writes a **deny grant**, which the engine evaluates in the hot path at hot-path cost.

### What the runtime will not do for you

- **It will not declare topology.** `ReactorTransport` has no declare or bind method at all, so this
  is a property of the type rather than a discipline — a reactor that can bind is a reactor that can
  bind itself to `*.token.pre_issue` and read another tenant's issuance events. `reactorId` names
  your own queue and no other.
- **It will not synthesize an `allow` for a handler that threw.** Throwing publishes *nothing*, and
  the operator's `failure_policy` decides what that costs. Answering `allow` on your behalf would
  defeat a `fail_closed` setting from inside the library.
- **It will not filter your patch.** A forbidden key goes on the wire as written and the server
  refuses the whole patch. Trimming it silently would leave you believing a field was set when it
  was dropped. (`ReactorEventSpec.patchFieldAllowed` is there so you can check a key *before*
  writing the handler — never to filter one afterwards.)
- **It will not reply late.** When your handler returns after `event.timeoutMs` has elapsed, the
  reply is abandoned — the server stopped listening, and publishing anyway only adds load. Consult
  `event.remaining(now)` and shed load rather than push on.
- **It will not retry a reply (§16).** A correlation is single-use and a late reply is discarded;
  the recovery mechanism for an unanswered dispatch is the server-side `failure_policy`, not a
  resend. Connection recovery is the RabbitMQ client's, left on.

`close()` is §18-deterministic: it cancels the consumer so no new delivery starts, drains what is in
flight up to `shutdownGrace`, and is idempotent. §19 telemetry emits one `RequestStart`/`RequestEnd`
pair per dispatch with the event name as the path template — a closed set of five values, so it
cannot become a cardinality bomb.

### Listeners

`mode: "listen"` is fire-and-forget observation: the server never waits and never reads a reply.
Pass `listener = ReactorListener { ... }` instead of `handler` — it returns `Unit`, so a listener
*cannot* publish a reply rather than merely being told not to. Write it idempotently: a redelivery
after a broker hiccup is normal.

### Logging

The signing key is a credential and is wrapped in `Sensitive` — never logged at any level, never in
a reconnect diagnostic. The `payload`, `patch`, `reason` and `decision` are **not** secrets and stay
readable (a handler that cannot inspect the event cannot decide anything), but they are tenant
business data: this SDK never logs the payload, and neither should you at `info` level. The `nonce`,
`correlation_id` and `hmac_signature` are not secrets and may be logged for correlation.
Diagnostics go to a `ReactorLog` you supply — a one-method sink, because this SDK does not pick a
logging framework for its consumers.

## OPAQUE (`io.axiam.sdk.opaque`, §23)

`loginOpaque` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **registration record** sealed under a tenant-wide oblivious PRF
seed, and what travels is a blinded group element and a MAC, neither useful
without both.

```kotlin
val password = readPassword()
try {
    val result = client.loginOpaque("alice", password.copyOf())
} finally {
    password.fill(' ')
}
```

It takes the same arguments as `login` and returns the same `LoginResult`, MFA
branch included, so switching a tenant to OPAQUE needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and the
enrolment call, is in [`examples/opaque-login`](examples/opaque-login).

Unlike the SRP-6a it replaces, there is no separate server-proof step and
nothing has been dropped: RFC 9807's AKE authenticates the server during the
handshake, so opening `KE2` **is** the proof that it holds the record. The old
contract had to mandate an `M2` check in capitals because skipping it kept only
half the protocol; there is now nothing to skip.

### The protocol is not implemented here

CONTRACT.md §23.1 forbids an SDK from writing its own OPAQUE. SRP-6a was
arithmetic every language can express, which is why `io.axiam.sdk.srp` existed at
~500 lines of modular exponentiation. OPAQUE is not: it needs an oblivious PRF,
`hash_to_curve`, `expand_message_xmd`, an envelope construction and a
three-message AKE, and eleven independent implementations of that is eleven
chances to be subtly and silently wrong in a way that still interoperates until
it does not.

`io.axiam.sdk.opaque` therefore contains **no cryptography**. It is a JNA binding
to `libaxiam_opaque_ffi`, the same implementation the AXIAM server links, plus
the ownership bookkeeping a binding has to get right.

### Installing

Two things are needed, and both are deliberately optional:

1. **JNA** — declared `compileOnly` here, exactly as Ktor and the RabbitMQ client
   are, so it does not reach your classpath unless you ask for it. A
   REST/gRPC/AMQP consumer whose tenant does not use OPAQUE should not be made to
   carry a native-access library. Add it explicitly to use OPAQUE:

   ```kotlin
   implementation("net.java.dev.jna:jna:5.19.1")
   ```

2. **The shared library** — a Rust `cdylib` published as a per-platform asset on
   the [axiam release page](https://github.com/ilpanich/axiam/releases), not an
   artifact on Maven Central. Put it on `java.library.path`, or point at it:

   ```bash
   java -Daxiam.opaque.library=/opt/axiam/libaxiam_opaque_ffi.so ...
   # or: export AXIAM_OPAQUE_LIBRARY=/opt/axiam/libaxiam_opaque_ffi.so
   ```

This SDK targets JVM 17, where the FFM API (`java.lang.foreign`) does not exist
at all. Raising the target to 22 to avoid one optional dependency would be the
larger break by a wide margin.

Ask before you need it:

```kotlin
val result = if (client.opaqueAvailable()) {
    client.loginOpaque(user, password.copyOf())
} else {
    client.login(user, String(password))
}
```

Unlike the `srpAvailable()` it replaces — hard-coded `true` on the JVM because
`BigInteger` and BouncyCastle are always there — this can genuinely answer
`false`. It reports rather than throwing, so an application chooses the password
path up front instead of discovering the gap mid-exchange.

> **Note for existing users:** `org.bouncycastle:bcprov-jdk18on` is no longer a
> dependency. It was here for the SRP client's Argon2id and nothing else in
> `src/main` imported it, so keeping an ~8 MB provider on every consumer's
> classpath for a code path that no longer exists would be a dependency nobody
> could explain a year from now. Add it back yourself if your application was
> relying on it transitively.

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the
  substantive gain over SRP: cracking a record also requires the tenant's OPRF
  seed, which is AES-256-GCM encrypted at rest under a key the database does not
  hold.

It does **not** protect against a compromised AXIAM server, and this SDK does not
claim it does.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `login` | `loginOpaque` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AuthzError` | works |

Which exception you get is most of what this SDK owns on this path:

| condition | exception | why |
|---|---|---|
| tenant has OPAQUE disabled | `NetworkError` | a property of the tenant, not of any user — fall back to `login` |
| shared library or JNA absent | `NetworkError` | a deployment fact, raised before any request is sent |
| server named a KSF this build cannot perform | `NetworkError` | a configuration problem; substituting one would surface as a wrong password |
| `/start` response missing `ke2` | `NetworkError` | malformed response |
| envelope did not open / `KE2` did not verify | `AuthError` | the **whole** of the credential check — under `optional`, only if the `login` retry also fails |
| tenant refuses password login (`login`) | `AuthzError` | the credentials were never examined |

That `AuthError` covers both halves of the mutual authentication: a wrong
password, an account that does not exist, an account with no registration
record, and a server that does not hold the record are indistinguishable by
design. **Nothing is sent to `login/finish` in that case** (§23.4 rule 7).

What happens after that is decided by the `mode` field the `login/start`
response carries — the tenant's `opaque_mode` — and by nothing else:

| `mode` | after a failed `KE2` |
|---|---|
| `optional` | `loginOpaque` retries over `login()` itself, with the same credentials, and returns that call's outcome — its `LoginResult`, or its exception |
| `required` | `AuthError`; nothing is retried |
| unrecognised, or **absent** (a server older than the field) | as `required` — it fails closed |

The retry under `optional` is not a courtesy: every account has no registration
record the moment an operator enables OPAQUE and acquires one only when its
password is next set, so an SDK that treated the failed exchange as final would
lock out every user of a tenant mid-migration — the exact state `optional` exists
to serve. Under `required` the retry would be refused anyway (`403
opaque_required` for every principal) and would put a plaintext password on the
wire for nothing.

`mode` is **not** downgrade protection, and this SDK does not present it as such:
a hostile server that wanted the plaintext could answer `404` and get a fallback
whatever it put there. What closes that is server-side — `required` refusing
`/auth/login` before it examines any credential.

`required` refuses **every** principal in the tenant, not only the enrolled ones.
Splitting the response on whether an account has a record would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a record needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a
password has to carry one. `opaqueEnrollment` produces the `opaque` object for
`POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```kotlin
val enrolment = client.opaqueEnrollment(newPassword)
requestBody["opaque"] = enrolment.toJson()
```

Note the parameters that are gone. There is no `identity`: the SRP version
required the account's canonical **username**, an email there produced a verifier
no login could ever satisfy — and renaming a user invalidated their verifier
outright. A record binds to a credential identifier the server chooses, so
neither is true any more. There is no `group` or `SrpKdfParams` either: those
come from the `register/start` response, so a caller cannot pick a cost the
server will not honour.

Unlike `srpEnrollment` this is a genuinely suspending call that performs network
I/O — one `register/start` round trip. The envelope is sealed under the server's
oblivious PRF, so there is no offline computation that produces a valid record.

### Cost

`loginOpaque` runs the tenant's key-stretching function: Argon2id at 19 MiB and
t=2 by default, which is tens to hundreds of milliseconds of CPU plus that
memory, per login attempt. That cost is the point — it is what makes a stolen
record expensive to attack even by someone holding the OPRF seed. Both
`loginOpaque` and `opaqueEnrollment` run it on `Dispatchers.Default` rather than
the caller's dispatcher, which is the difference between a slow login and a
stalled event loop. Size that pool and your request timeouts accordingly; it is
not a cost `login` has.

### Cryptographic parameters

The ciphersuite is `OPAQUE-3DH` over **ristretto255** with **SHA-512**,
HKDF-SHA-512 and HMAC-SHA-512, fixed AXIAM-wide. It is not negotiated and not
read from the server: a client that accepted a suite from the endpoint it is
authenticating would be accepting a downgrade.

The key-stretching function *is* the server's to name, per exchange, and is
honoured as given rather than cached or defaulted — a credential enrolled under
one cost keeps working after a tenant raises its policy. `argon2id` and `scrypt`
are accepted; anything else is refused rather than substituted. Costs outside the
bands this SDK will act on (`memory_kib` 8 MiB–1 GiB, `iterations` 1–10,
`parallelism` 1–16, `log_n` 14–20, `r`/`p` 1–16) are refused too: a server is
trusted to name its own policy, not to name a cost that would wedge every device
an account owns.

### Zeroization

`loginOpaque` and `opaqueEnrollment` take the password as a `CharArray` so the
caller can clear it, and clear every copy they make of it — including the UTF-8
bytes handed across the ABI. They cannot clear the caller's array; do that
yourself, in a `finally`. If your password arrives as a `String` (from a JSON
body, say), it is already immutable and already copied; the `CharArray` signature
is honest about where this SDK's reach ends rather than implying a guarantee it
cannot keep.

The password crosses the ABI as **UTF-8**, explicitly, never through JNA's
`String` mapping — which uses the platform charset unless `jna.encoding` says
otherwise. A password that encoded differently under a different default locale
would derive a randomized password no AXIAM server agrees with, and would surface
as a wrong password on that machine only.

## WebAuthn / passkeys (`io.axiam.sdk.webauthn`, §24)

Six wire operations, two ceremonies, and one thing this SDK deliberately does not do.

```kotlin
// Enrolment — requires a session (§24.1), refused client-side without one.
val challenge = client.webauthnRegisterStart()
val credential = client.webauthnRegisterFinish(
    challenge.stateToken,
    credentialName = "Pixel 9",
    response = platformResponseJson,     // verbatim
)

// Sign-in with no username at all — the authenticator picks the account.
val signIn = client.webauthnDiscoverableStart()
val result = client.webauthnDiscoverableFinish(signIn.stateToken, assertionJson)
```

**The server chooses every option and verifies every response; this SDK passes both through
byte-for-byte** (§24.0). `WebauthnChallenge.challenge` is a raw `JsonObject`, not a modelled type:
no defaulting, no validation-that-rejects, no re-encoding. On the way back the `*Finish` body is
assembled as **text**, splicing the caller's response string in unmodified — parsing and
re-serializing it would hand the server a byte sequence the authenticator never signed.

### Android, via the §24.6a JSON bridge

`axiam-kotlin-sdk` is a plain `kotlin("jvm")` library and it stays one. An Android artifact would
mean the Android Gradle Plugin, AAR packaging, an Android SDK in CI and a second published
coordinate — a large change to the shape of the deliverable, taken to wrap an API that is already a
string in and a string out. So the same jar serves a desktop or server JVM and an Android app
unchanged:

```kotlin
// build.gradle.kts — the SDK is an ordinary JVM dependency
implementation("io.github.ilpanich:axiam-kotlin-sdk:<version>")
implementation("androidx.credentials:credentials:1.3.0")
implementation("androidx.credentials:credentials-play-services-auth:1.3.0")

// Enrolment
val challenge = client.webauthnRegisterStart()

val response = CredentialManager.create(context).createCredential(
    context,
    CreatePublicKeyCredentialRequest(requestJson = challenge.requestJson),
) as CreatePublicKeyCredentialResponse

client.webauthnRegisterFinish(
    challenge.stateToken,
    credentialName = "Pixel 9",
    response = response.registrationResponseJson,
)

// Sign-in
val signIn = client.webauthnDiscoverableStart()

val credential = CredentialManager.create(context).getCredential(
    context,
    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(signIn.requestJson))),
).credential as PublicKeyCredential

client.webauthnDiscoverableFinish(signIn.stateToken, credential.authenticationResponseJson)
```

`requestJson` is the inner options object — the `publicKey` wrapper belongs to the DOM's
`CredentialCreationOptions`, and the platform JSON APIs do not want it. Nothing is destructured,
nothing is re-encoded, and the SDK links no Android class.

Passing something that is not JSON, or is not a JSON object, raises `AuthError` client-side with no
wire call: the SDK will not POST a body it already knows the server cannot verify.

### The two authentication ceremonies are different flows (§24.2)

`webauthnAuthenticateStart`/`Finish` is a **second factor** — it continues a `login()` that answered
`mfaRequired` with `"webauthn"` among its methods, and the challenge token names the user so the
server can send an `allowCredentials` list. `webauthnDiscoverableStart`/`Finish` is a **primary
factor**: nothing precedes it, `allowCredentials` is empty, and the assertion itself identifies the
user. They are not one operation with an optional token — merging them reproduces a bug the server
already fixed, which is why the token is a required argument on one and absent from the other.

One difference a reactor author will ask about: `discoverable/finish` fires the `login.post_auth`
hook event (§22.5) and `authenticate/finish` does not. The latter continues a login already gated at
its password step; the former has no such step to have been gated at.

### Saying something useful when a ceremony fails (§24.6b rule 5)

Every platform reports a ceremony failure as one opaque type whose only machine-readable part is a
name. `WebauthnFailure.classify` turns that into five outcomes — and takes either the name or the
throwable, so an Android caller can hand it a `CreateCredentialException` directly without this
artifact linking `androidx.credentials`:

```kotlin
try {
    CredentialManager.create(context).createCredential(context, request)
} catch (e: CreateCredentialException) {
    when (WebauthnFailure.classify(e)) {
        WebauthnFailure.ALREADY_REGISTERED -> offerADifferentDevice()
        else -> showRetry(WebauthnFailure.classify(e).message)
    }
}
```

`ALREADY_REGISTERED` is the exclusion list doing its job, and the only classification whose remedy
is "use a different device" rather than "try again". `CANCELLED` covers **both** an explicit refusal
and a silent timeout — the spec deliberately refuses to distinguish them, because telling a website
which one happened leaks whether an authenticator was present — so its copy does not accuse anyone
of cancelling.

### Two error rows that are not the §2 defaults (§24.4)

- A **403 from `register/finish`** is the tenant's *attestation policy* rejecting this particular
  authenticator. The server's message is the only place that says which one would be accepted, so it
  is lifted into the `AuthzError`'s message rather than discarded. Show it.
- A **503 from `register/start`** means the policy needs FIDO metadata the server cannot reach. That
  is a configuration state, not a transient one, and it is **not retried** — the second documented
  exception to §16 after §20's.

Session cookies: as of contract 1.28 both `*Finish` authentication calls set the `axiam_access` /
`axiam_refresh` / `axiam_csrf` triple alongside the token body, so a completed ceremony leaves the
client signed in for every cookie-driven call that follows (§24.3).

Worked end to end in [`examples/webauthn-passkeys`](examples/webauthn-passkeys)
(`./gradlew runWebauthnPasskeysExample`).

## Account lifecycle and MFA enrolment (`io.axiam.sdk.account`, §25)

Nine operations covering the things a user does to their own account — none of which is
administration, and all of which were previously reachable only by hand-rolling HTTP.

```kotlin
val result = client.login("alice@example.com", password)

if (result.mfaSetupRequired) {
    // The third outcome. The tenant requires MFA, this account has none, and
    // the server handed back a setup token to finish with. There is no session
    // yet — the token IS the credential.
    val setupToken = result.setupToken!!
    val enrollment = client.mfaSetupEnroll(setupToken)
    renderQr(enrollment.totpUri.expose())
    client.mfaSetupConfirm(setupToken, code)     // completes the LOGIN
}
```

`LoginResult` gained two properties with defaults rather than changing shape, so every pre-1.28
construction still compiles and still reads `false`. **Handle the new outcome anyway.** A tenant
that turns on required MFA will start returning it, and a client that only branches on `mfaRequired`
reports a successful login that has no session.

`mfaSetupConfirm` adopts credentials exactly as `login()` does, because it *is* the completion of a
login (§25.2 rule 2). `mfaEnroll`/`mfaConfirm` are the voluntary pair, from inside an existing
session, and they do **not** clear the §17 decision memo — the subject has not changed, and
discarding a warm memo on an unrelated profile action costs a round trip on every check that
follows.

Both halves of an `MfaEnrollment` are `Sensitive`, and the second one matters: the `otpauth://` URI
*contains* the secret (§25.3). Wrapping the bare secret and then logging the URI leaks the same
bytes.

### Password reset, and the two things it will not tell you

```kotlin
client.requestPasswordReset(PasswordResetRequest("alice@example.com"))
// returns Unit, whether or not that address has an account

val context = client.passwordResetContext(token)
if (context.opaque != null) {
    // This tenant runs §23. Build a registration record from these parameters;
    // a plaintext password would be refused, and refused late (§25.4 rule 1).
}
client.confirmPasswordReset(PasswordResetConfirmation(token, newPassword, tenantId))
```

`requestPasswordReset` returns nothing and throws nothing on an unknown address, and this SDK
exposes no way to tell the two cases apart. That is not an omission to improve on: a client that
surfaced a "no such user" state — even one inferred from timing — would turn the endpoint into the
account-enumeration oracle its uniform response exists to prevent. Likewise a `404` from
`passwordResetContext` means unknown, expired **or** already-consumed, and the SDK does not
distinguish them either (§25.4 rule 3).

`verifyEmail` and `resendVerification` are unauthenticated — a user whose address is unverified may
have no session at all — and carry the tenant as a **body** field, since §12.1 rule 2's
`?tenant_id=` convention is scoped to the `/oauth2` endpoints.

### Two resends, and picking the wrong one is silent (§25.7)

```kotlin
client.resendVerification(email, tenantId)   // anonymous caller
client.resendOwnVerification()               // signed-in caller
```

Use the second whenever you have a session.

`resendVerification` takes an address from an *unauthenticated* caller, so it returns normally
whatever happens — unknown address, already verified, over the daily limit. That constancy is the
point: anything else is an oracle for which addresses have accounts.

`resendOwnVerification` is for a caller signed in to the account it is asking about. It takes **no
address at all** (the server reads it off your own record, and a parameter would let a session mail
an arbitrary one) and it says what happened:

```kotlin
try {
    client.resendOwnVerification()       // minted and enqueued
} catch (e: ConflictError) {
    // 409 — already verified, or this account may not be sent one
} catch (e: NetworkError) {
    // 429 — the daily resend limit
}
```

A profile page that called the *first* one reports success while doing nothing, which is the bug
this pair exists to separate. This SDK does not fall back from the second to the first on either
failure — that would turn both back into a normal return with an extra round-trip. And returning
means *enqueued*: delivery is asynchronous and can still fail at the provider.

### Organization-level principals (§5.2)

A completed `LoginResult` also reports whether the account is an **organization-level** principal —
one whose record lives in its organization's reserved tenant, so its global grants apply in every
tenant of that organization:

```kotlin
val result = client.login(email, password)
if (result.organizationLevel) {
    // Acts on any tenant of its organization by sending a different
    // X-Tenant-ID on the next request. No re-login: it already is a
    // principal of every tenant there.
}
```

Check it *before* offering a tenant switch. An ordinary tenant principal is a principal of exactly
one tenant, and changing the header for one of those produces a `403` — so a UI that offers the
switch to everyone has turned a distinction the server made into a failure the user discovers.
`false` against a server older than contract 1.31, which is the safe reading of absent.

#### Signing one in (§5.2.1)

The reserved tenant has a fixed slug, `organization`, the same in every deployment — so signing in
as an organization-level principal needs no new surface, only the ordinary factory:

```kotlin
val client = AxiamClient.builder("https://iam.example.com", "organization")
    .orgSlug("globex")
    .build()
val result = client.login("root@example.com", password)
```

Prefer that form. The server also reads a login body naming *no* tenant as "the organization's own
scope", but §5 rule 2 still requires a tenant on the `X-Tenant-ID` header of every request after the
login, so the client needs one either way.

What §5.2.1 forbids is the third possibility: an empty-string slug. Nothing can carry one, so
`tenant_slug: ""` resolves nothing — and on `/auth/opaque/login/start` it fails on the workspace
*before* the tenant's OPAQUE mode is read, so the `404` that means "OPAQUE is not offered here"
never arrives and this SDK has no fallback to take. Sign-in then fails even against a tenant with
OPAQUE disabled. `builder(baseUrl, tenantId)` already rejected a blank tenant; `orgSlug` now
rejects one too.

Worked end to end in [`examples/account-lifecycle`](examples/account-lifecycle)
(`./gradlew runAccountLifecycleExample`).

## Pushed Authorization Requests (§26, RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`, `redirect_uri`,
`state` and the PKCE challenge into a URL the user agent carries, the client POSTs them straight to
AXIAM over an authenticated back channel and puts an opaque `request_uri` in the redirect.

```kotlin
val config = client.oidcDiscover()
if (config.pushed_authorization_request_endpoint == null) {
    // §26 is optional; fall back to the plain oidcBegin redirect.
}

val begun = client.oidcBegin(OidcBeginParams(config, redirectUri, scope = "openid profile"))
val pushed = client.oidcPar(OidcParParams(begun, redirectUri, config, scope = "openid profile"))

redirect(pushed.url)   // exactly ?client_id=…&request_uri=…
```

Three things worth knowing:

- **The server answers `201`,** not `200` — RFC 9126 §2.2 specifies *Created*. A success predicate
  written `== 200` treats every successful push as a failure.
- **The redirect URL carries exactly two parameters.** The server refuses a request that mixes a
  `request_uri` with inline authorization parameters rather than merging them; merging is where
  parameter confusion lives (§26.2 rule 2). Any query the discovered `authorization_endpoint`
  already carried is dropped.
- **`oidcBegin` still owns `state`, `nonce` and the PKCE pair.** There is no second generator
  (§26.2 rule 1), and `PushedAuthorizationRequest` carries all three straight through to the
  exchange.

The push is **not retried** on a 5xx or a transport failure: it is a POST that creates server state,
so it falls outside §16.2's read-only eligibility exactly as `oidcExchange` does. The safe recovery
is a fresh push, which costs one round trip and cannot double-consume anything. The `requestUri` is
`Sensitive` because between the push and the redirect it is a bearer handle to a fully-formed
authorization request (§26.5).

A **FAPI 2.0 client has no alternative**: `profile: "fapi2"` refuses a registration that does not
set `require_par`, so such a client cannot authorize any other way (§21.1).

Worked end to end in [`examples/par-login`](examples/par-login) (`./gradlew runParLoginExample`).

## Management API (§27)

The administrative surface: 147 operations across 24 namespaces — users, groups, roles,
permissions, resources, scopes, service accounts, certificates, CA certificates, PGP keys, webhooks,
OAuth2 clients, federation, notification rules, e-mail config, settings, SCIM tokens, reactors,
WebAuthn policy, audit, privacy, organizations, tenants and platform.

The namespace handles sit **directly on the client** as properties — `client.serviceAccounts
.rotateSecret(id)`, the form §27.3's Kotlin row shows — and the same 24 handles are also reachable
behind one accessor, `client.management()` (§27.2 rule 4), which reads better where a call site is
already dense with §1 methods. The two forms are **equivalent**: the direct properties delegate to
`management()`, so rule 4's "where an SDK offers both, the two MUST return equivalent handles" holds
structurally rather than by two code paths agreeing, and the suite asserts it by comparing the
method, path and query each actually puts on the wire.

It is **generated** from the vendored `management-registry.json` and `openapi.json` by
`scripts/gen_management.py`, and the generated output is committed. A CI job re-runs the generator
with `--check` on every pull request, so the committed surface and the vendored contract cannot
drift apart.

```kotlin
AxiamClient.builder(baseUrl, "acme").orgSlug("acme").build().use { client ->
    client.login(admin, password)

    // A namespace handle is a view over this client's session, not a
    // connection. Acquiring one performs no I/O (§27.2).
    val page = client.users.list(PageRequest.of(25))

    // Or reach the same handles behind one accessor.
    val same = client.management().users().list(PageRequest.of(25))

    // page.total is the size of the WHOLE set, not of this page (§27.4 rule 4).
    println("${page.items.size} of ${page.total}")

    // listAll walks to exhaustion, stopping on an empty page even if the
    // server's total disagrees.
    val roles = client.roles.listAll()

    // The server filters, before offset/limit, so total counts MATCHES.
    val found = client.users.list(PageRequest.matching(25, "ada"))
}
```

Eight things worth knowing:

- **The client's org and tenant are implicit.** A route with `{org_id}` or `{tenant_id}` in it takes
  them from the client (§27.4 rule 3). The handles that carry such routes — and only those — expose
  `.inOrg(id)` / `.forTenant(id)` to name a different one for a single call; each returns a new
  handle and leaves the original alone. Where `{tenant_id}` names the tenant being *administered*
  rather than the calling context — `tenants`, and the signing CAs under `caCertificates` — it is an
  ordinary argument instead, and `client.resolvedTenantId()` is what you pass it.
- **A sparse update sends only what you name.** Bodies whose properties are all optional default
  every one of them to `null`, and the request writer is configured with `encodeDefaults = false`,
  so a property you never named is absent from the JSON rather than sent as `null` — which the
  server reads as "clear this" (§27.4 rule 5). There is no builder because Kotlin does not need one.
  Replacement bodies have no defaults: their constructor takes every property, so forgetting one is
  a compile error.
- **Three statuses are classified, and each keeps the parent §2 gave it.** `NotFoundError` (404) and
  `ConflictError` (409) are `AuthzError`s; `ValidationError` (400/422) is a `NetworkError`. Existing
  `catch` blocks keep working; code that wants the distinction can ask for it (§27.4 rule 7).
  `ValidationError.fields` carries the server's per-field detail when it sent any.

  404 sorts under `AuthzError` because on a multi-tenant surface "does not exist" and "is not yours"
  are *deliberately* the same answer — a server that distinguished them would let a probing caller
  enumerate another tenant's objects. 409 stays there because §2 already put it there.
- **Only GETs are retried.** A create that times out is reported, never repeated — one retried
  `POST` is two roles (§27.4 rule 8).
- **One-time secrets are `Sensitive`.** A generated private key, a fresh client secret, a SCIM
  provisioning token: returned by exactly one call and never again, redacted from `toString()`, and
  reachable only through the explicit `expose()` (§27.5). Write it down before doing anything else
  that could fail. A `Sensitive` is `@Contextual`, so serializing a §27 model with your own `Json`
  throws rather than quietly emitting either the secret or a placeholder the server would reject.
- **A management call with no session never reaches the network.** It fails locally with an
  `AuthError` naming the missing session (§27.4 rule 1).
- **`search` is on the page request, and the server does the filtering** (§27.4 rule 4).
  `PageRequest.matching(25, "ada")` puts the term where `offset` and `limit` already live, and that
  is what makes `listAll` carry it across the whole walk — a walk that filtered its first request
  and not the rest would return the matches followed by the unfiltered tail. `total` counts matches
  rather than rows, because the server applies the term before paging. A blank or whitespace-only
  term is the same request as none, so a box that fires on every keystroke does not ask a different
  question once it has been cleared; and the server's length cap is deliberately not copied here,
  because a client-side truncation the server would not have made is a silently different query.
- **Three properties arrived with contract 1.31, and each `null` means something specific**
  (§27.11). `Tenant.kind` is `null` on a row written before organization scope existed — read it as
  `standard`. `MtlsTrustAnchorResponse.trustedAnchors` is `null` when nothing was reloaded, which is
  *not* zero: "the listener trusts no CAs" and "there was no listener to ask" are different states,
  and only one is a problem. `Certificate.boundServiceAccountId` is resolved by
  `certificates().list()` and `null` on `get`; the SDK does not issue a second request to fill it in.

  Generated enums also gained an `UNKNOWN` constant, decoded through a hand-rolled `KSerializer`.
  kotlinx.serialization's own enum serializer *throws* on a value outside the constants, which fails
  the whole response — taking down every record on the page over one field of one of them. A `when`
  over these constants now needs an `UNKNOWN` branch. `UNKNOWN.wire` is the empty string, which no
  server value is: carrying an unrecognised value back into an update is refused by the server
  rather than silently written as a spelling it never used.

Worked end to end in [`examples/management-basics`](examples/management-basics).

### Declarative manifests (§27.6)

`client.management().manifest()` takes a description of the tenant you want and reconciles toward
it.

```kotlin
val manifest = ManagementManifest.builder()
    .resource("docs", "documents", "collection")
    .scope("docs", "draft", "draft", "Unpublished work")
    .permission("read", "document:read", "Read a document")
    .role("editor", "Editor", "Edits documents")
    .grant("editor", "read", null, "draft")
    .group("staff", "Staff", "Everyone", "editor")
    .build()

val plan = client.management().manifest().plan(manifest)   // reads only
if (!plan.isConverged) {
    val report = client.management().manifest().apply(manifest)
}
```

- **`plan` writes nothing.** Every request it makes is a read, so it is safe to run against
  production to find out what an `apply` would do.
- **Ordering is derived, not declared.** Resources before their scopes, permissions before the
  grants that name them, roles before the assignments; the builder checks back-references as they
  are made, so a grant naming a role that no `role(...)` call has declared is refused at `build()` —
  before any request, and reporting every problem at once rather than the first.
- **Omission is never deletion.** A manifest states what should exist. A role it does not mention is
  a role it has no opinion about (§27.6 rule 4).
- **`apply` stops at the first failure and does not roll back** (§27.6 rule 7). Everything before
  the failure stands; everything after it is reported as `NOT_ATTEMPTED`. An automatic rollback
  would be a second unreviewed batch of writes issued at exactly the moment the tenant is in an
  unknown state.
- **Applying twice is applying once.** A converged tenant plans nothing and takes no writes.

Worked end to end in [`examples/management-manifest`](examples/management-manifest), and combined
with §6.1 mTLS for a full device provisioning lifecycle in
[`examples/device-mtls-provisioning`](examples/device-mtls-provisioning).

## Building from source

```bash
./gradlew build            # compile + test
./gradlew test koverXmlReport   # tests + coverage report (build/reports/kover/report.xml)
./gradlew dokkaJavadocJar  # API docs jar
```

Targets JVM 17. CI runs on JDK 17 via `gradle/actions/setup-gradle`.

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks — `checkAccess` (both overloads), `can`, `batchCheck` — retry
transient failures under the contract's normative table: **3 attempts** (1 initial + 2
retries), 200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`), and
`Retry-After` honored as a **floor**.

This SDK had no §16 policy before — only §9.3's refresh-then-retry-once, which is a different
mechanism. §11.2 rule 5 had been requiring one since it was written.

Only failures that could plausibly succeed on a second attempt are retried: transport errors,
`408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and surfaces after
exactly one attempt. Nothing that changes server state is ever retried, and **coroutine
cancellation is never retried or swallowed** — it propagates immediately, because a cancelled
scope is the caller's decision rather than the server's failure.

```kotlin
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
val client = AxiamClient.builder(baseUrl, tenantId).retryDisabled().build()
```

There is deliberately no builder method for the attempt cap, base delay or delay cap: §16.1
forbids raising them, and eleven SDKs agreeing on one table is the point.

### Deterministic shutdown (§18)

`close()` releases the client's local resources. It is idempotent — `compareAndSet` means even
a concurrent double-close does the work once — and any call afterwards throws `NetworkError`
naming the cause rather than silently reconnecting.

**`close()` does not log out.** It never reaches the network. The server-side session
deliberately outlives the client object — that is what lets a process restart and resume — so
a `close()` that logged out would silently end every user's session on each deploy. Call
`logout()` first if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this module depending on any metrics library:

```kotlin
val client = AxiamClient.builder(baseUrl, tenantId)
    .telemetryHook { event ->
        when (event) {
            is TelemetryEvent.RequestEnd ->
                histogram.record(event.duration.inWholeMilliseconds, /* labels */)
            is TelemetryEvent.Retry -> counter.increment(/* labels */)
            else -> Unit
        }
    }
    .build()
```

- **A hook that throws cannot fail the operation that fired it.** One exception: a
  `CancellationException` is re-thrown rather than swallowed — absorbing it would break
  structured concurrency, which is a correctness bug rather than a metrics one.
- **No event payload can carry a token.** `TelemetryEvent` is a **sealed** hierarchy with
  fixed property lists — no code outside the SDK can add a variant.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `RequestStart`/`RequestEnd` pair is emitted **per attempt**, so you can count real wire
calls. See [`examples/telemetry-hook`](examples/telemetry-hook).

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `checkAccess` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```kotlin
val client = AxiamClient.builder(baseUrl, tenantId)
    .decisionMemoTtl(Duration.ofSeconds(5))
    .build()
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. If that is your workload, leave
> this off.

The TTL is clamped to 5 seconds rather than rejected. Allows and denies are memoized
identically — asymmetric caching would leak which outcome occurred through latency. Failures
are never memoized: caching a transport error as a deny would turn a blip into a TTL-long
outage. The memo is cleared on `login`, `verifyMfa`, `refresh` and `logout`, since entries are
keyed by subject rather than by session. It is safe for concurrent use.
