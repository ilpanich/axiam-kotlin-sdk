# Releasing this SDK

Publishing is triggered by pushing a `vX.Y.Z` tag. This document covers the
part that is not in the workflow file: what has to be true of this
repository's settings, and on what clock.

## Why this SDK is the awkward one

Nine of the eleven AXIAM SDKs publish with no long-lived registry credential —
Trusted Publishing (OIDC) on crates.io, npm, PyPI and nuget.org, a webhook on
Packagist, and a plain git tag for Go, Swift, C and C++. **Maven Central is the
exception.** The Central Publisher Portal authenticates a deployment with a
user token: a username/password pair, base64-encoded, sent as a bearer. There
is no OIDC exchange and no per-repository scoping.

The two OIDC surfaces Central *does* have are easy to mistake for one. Account
sign-in can use GitHub OIDC, and Sigstore signature validation (available on
the Portal since 2025-01) uses the workflow's OIDC identity to sign. Neither
authorises an upload. The full research is in the AXIAM server repository:
[`claude_dev/maven-central-publishing-decision.md`](https://github.com/ilpanich/axiam/blob/main/claude_dev/maven-central-publishing-decision.md).

So the credential stays, and what follows is what bounds it.

## Repository settings the workflow cannot express

The publish job declares `environment: maven-central`. That is only half the
control; the other half is configured on the environment itself, in this
repository's settings:

1. **The secrets are environment secrets, not repository secrets.**
   `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY` and
   `GPG_PASSPHRASE` must belong to the `maven-central` environment. A
   repository secret is readable by any job in any workflow that asks for it;
   an environment secret is readable only by a job that names the environment,
   and naming it triggers the two rules below.
2. **Required reviewers: at least one.** A publish then waits for a human, so
   pushing a tag stops being the last irreversible step.
3. **Deployment tag rule: `v*` only.** With the `verify-tag-on-main` gate in
   the workflow, a run that is not a release tag cut from `main` cannot reach
   the credential at all.

## Rotation

A credential that cannot be scoped or given an expiry is replaced on a clock
instead.

| Secret | Cadence | Notes |
|---|---|---|
| Portal user token | **Quarterly**, and immediately on suspected exposure or a maintainer change | Generate a replacement at `central.sonatype.com/usertoken`; generating one revokes the old. Failure mode is loud — the next publish 401s. |
| GPG signing key | On its own schedule, not this one | A new key has to reach the keyservers Central checks before it is useful; rotating it in a hurry breaks releases rather than securing them. |

| Last rotated | By |
|---|---|
| _(record each rotation here)_ | |

## Verifying a published artifact

Every jar this workflow publishes carries a GitHub build-provenance
attestation — a statement the Portal token cannot forge, because it is signed
with the workflow's OIDC identity rather than with the credential that
performed the upload:

```sh
gh attestation verify axiam-sdk-<version>.jar --repo ilpanich/axiam-kotlin-sdk
```

## Still open

Sigstore signature bundles (`.sigstore.json`) alongside the PGP signatures are
the closest thing Central offers to trusted publishing, and are **not yet
configured here**. They need a build-file change on the release path
(Gradle (`./gradlew publish`)), which is exactly the kind of change that should
not ship without a validation run against a throwaway version. Tracked as the
remaining half of H-1 in the server repository's beta03 hardening plan.
