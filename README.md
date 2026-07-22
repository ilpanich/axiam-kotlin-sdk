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

This SDK conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract. AXIAM is
multi-tenant: a tenant identifier is a **required** constructor argument (§5) — there is no
default tenant.

### Scope of this SDK (v1)

- **In scope:** the REST surface — authentication (`login`, `verifyMfa`, `refresh`, `logout`),
  authorization (`checkAccess`, `can`, `batchCheck`), the §2 error taxonomy, §3 CSRF
  forwarding, §4 per-client cookie jar, §5 tenant header, §6 strict TLS + §6.1 mTLS client
  certificates, §7 `Sensitive`, §9 single-flight refresh, JWKS (EdDSA/Ed25519) session
  verification, and the §10/§11 Ktor route guard + declarative-authorization helpers.
- **Deferred follow-ups (not in v1):** the gRPC transport — including the gRPC-only
  `getUserInfo` operation (CONTRACT §1.1, contract 1.3) — and §8 AMQP HMAC consumption. The
  contract does not require AMQP of the Kotlin SDK; gRPC (and with it `getUserInfo`) is a
  planned addition. Per CONTRACT §1.1, this SDK does **not** substitute the REST
  `/oauth2/userinfo` endpoint for the gRPC operation.

## Getting started

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha16")
    // Optional — only if you use the Ktor route guard / §11 helpers:
    implementation("io.ktor:ktor-server-core:2.3.12")
}
```

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk-kotlin</artifactId>
  <version>1.0.0-alpha16</version>
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

## Building from source

```bash
./gradlew build            # compile + test
./gradlew test koverXmlReport   # tests + coverage report (build/reports/kover/report.xml)
./gradlew dokkaJavadocJar  # API docs jar
```

Targets JVM 17. CI runs on JDK 17 via `gradle/actions/setup-gradle`.
