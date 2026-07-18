# AXIAM Kotlin SDK — examples

Self-contained, compiling samples for the AXIAM Kotlin SDK. They import **only**
public entry points (`io.axiam.sdk.*`, never `io.axiam.sdk.internal.*`) and read
all connection details from the environment, with safe defaults.

| Example | File | Shows |
| --- | --- | --- |
| Login + MFA | [`login-mfa/LoginMfaExample.kt`](login-mfa/LoginMfaExample.kt) | The two-phase `login()` / `verifyMfa()` flow (CONTRACT.md §1, §5, §5.1) |
| REST authz | [`rest-authz/RestAuthzExample.kt`](rest-authz/RestAuthzExample.kt) | `can()`, `checkAccess()`, and order-preserving `batchCheck()` (§1) |

## Organization context (§5.1)

`login` and `refresh` require **organization context in addition to the tenant** —
a tenant slug is only unique within an organization. Both examples construct the
client with a tenant slug **and** an org slug:

```kotlin
AxiamClient.builder(baseUrl, tenantSlug).orgSlug(orgSlug).build()
```

Omitting the org identifier makes the server reject login with
`400 Bad Request — "must provide org_id or org_slug"`. Use `.orgId(UUID)` instead
of `.orgSlug(...)` if you have the organization UUID.

## Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `AXIAM_BASE_URL` | `https://localhost:8443` | AXIAM server base URL |
| `AXIAM_TENANT_SLUG` | `acme` | Tenant slug (§5) |
| `AXIAM_ORG_SLUG` | `acme` | Organization slug (§5.1) |
| `AXIAM_EMAIL` | `user@example.com` | Login username/email |
| `AXIAM_PASSWORD` | `changeme` | Login password |
| `AXIAM_TOTP_CODE` | `000000` | TOTP code (login-mfa only) |

The defaults let the examples **compile and start** offline; running them
end-to-end needs a reachable AXIAM server at `AXIAM_BASE_URL`.

## Build & run

The examples live in a dedicated `examples` Gradle source set that compiles
against the SDK's main output (so they can never drift from the public API).

```bash
# Compile-check the examples (also runs as part of `./gradlew check`)
./gradlew compileExamplesKotlin

# Run against a live server
AXIAM_BASE_URL=https://localhost:8443 \
AXIAM_TENANT_SLUG=acme AXIAM_ORG_SLUG=acme \
AXIAM_EMAIL=you@example.com AXIAM_PASSWORD=secret \
  ./gradlew runLoginMfaExample

AXIAM_BASE_URL=https://localhost:8443 \
AXIAM_TENANT_SLUG=acme AXIAM_ORG_SLUG=acme \
AXIAM_EMAIL=you@example.com AXIAM_PASSWORD=secret \
  ./gradlew runRestAuthzExample
```

Every SDK auth/authz operation is a `suspend` function (§1); each example's
`main` wraps the calls in `runBlocking`.
