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

This SDK conforms to CONTRACT.md §1–§7, §9–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23
(including §6.1 mTLS).

§12.7, §14, §15, §20, §22 and §23 are named rather than folded into the range because they landed after
this SDK already stated its coverage: widening the range silently would turn a statement that was
true when written into a different claim without anyone editing it.

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
  §13 webhook-signature verifier (see "Webhook signature verification" below). Plus, on the AMQP
  side, the §22 reactor runtime (see "Reactors" below) and the §8 v2 / §8b primitives it carries.
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
    implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha31")
    // Optional — only if you use the Ktor route guard / §11 helpers:
    implementation("io.ktor:ktor-server-core:2.3.12")
}
```

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk-kotlin</artifactId>
  <version>1.0.0-alpha31</version>
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
| envelope did not open / `KE2` did not verify | `AuthError` | the **whole** of the credential check |
| tenant refuses password login (`login`) | `AuthzError` | the credentials were never examined |

That `AuthError` covers both halves of the mutual authentication: a wrong
password, an account that does not exist, and a server that does not hold the
record are indistinguishable by design. **Nothing is sent to `login/finish` in
that case** (§23.4 rule 7), and you must not retry over `login()` — that hands
the plaintext to an endpoint that just failed to prove it holds the record.

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
