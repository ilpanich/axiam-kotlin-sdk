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

Two independent statements of origin ship with every release, and neither can
be produced by the Portal token that performed the upload. Both are signed with
the release workflow's OIDC identity.

**1. The GitHub build-provenance attestation**, held by GitHub:

```sh
gh attestation verify axiam-sdk-kotlin-<version>.jar --repo ilpanich/axiam-kotlin-sdk
```

**2. The Sigstore bundle**, served by Maven Central itself. Every published
file — the jar, the sources jar, the Dokka javadoc jar, the POM, the Gradle
module metadata — has a `.sigstore.json` next to its `.asc`:

```sh
base=https://repo1.maven.org/maven2/io/github/ilpanich/axiam-sdk-kotlin/<version>
curl -sO "$base/axiam-sdk-kotlin-<version>.jar"
curl -sO "$base/axiam-sdk-kotlin-<version>.jar.sigstore.json"

cosign verify-blob \
  --bundle axiam-sdk-kotlin-<version>.jar.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/ilpanich/axiam-kotlin-sdk/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  axiam-sdk-kotlin-<version>.jar
```

The two differ in where they live, which is the point of having both: the
attestation is a GitHub API call away and disappears if you only ever talk to
Maven Central; the bundle travels with the artifact in the repository a
consumer already fetches from.

### What the Sigstore bundle costs, and what it needs

Nothing, and nothing. Fulcio (the certificate authority) and Rekor (the
transparency log) are the Sigstore **public good instance**, free to use and
requiring no account, no registration and no stored key: the signing
certificate is issued against the workflow's GitHub OIDC claim and expires ten
minutes later. There is no third credential to rotate — the rotation table
above stays at two rows.

The only thing it needs from the repository is `id-token: write` on the jobs
that sign, which the publish job already had for the attestation.

### How it is wired

- `build.gradle.kts` declares `dev.sigstore.sign` with `apply false`, and
  applies it only when `-Psigstore.enabled=true` is passed. A keyless signature
  means nothing without a workflow identity behind it, and without one
  sigstore-java falls back to a browser flow — so a laptop
  `./gradlew publishToMavenLocal` must not attempt one.
- The publish job passes `-Psigstore.enabled=true` to `./gradlew publish`. The
  bundles are added to the `maven` publication as derived artifacts, so they
  are PUT to the OSSRH Staging API alongside everything else and forwarded to
  the Portal by the existing close-and-forward step.
- The plugin removes the `.sigstore.json.asc` files Gradle's `signing` plugin
  would otherwise produce. Central wants a signature per artifact, not a
  signature of a signature.

### The gate that replaced the throwaway-version run

This change lands on the release path, where a mistake is invisible until the
next tag and then breaks it. The `sigstore-sign-gate` PR job is what makes that
acceptable: on every same-repository pull request it performs a **real** keyless
signing of the real publication — Actions OIDC, a Fulcio certificate, a Rekor
entry, a `.sigstore.json` per file — with an ephemeral GPG key alongside it, so
the interaction between the two signers is exercised too. It then asserts that
every published file has both a `.asc` and a `.sigstore.json`, and that no
`.sigstore.json.asc` was produced.

Nothing leaves the runner: it publishes to the runner's own `~/.m2`, and the
job holds no `CENTRAL_TOKEN_*` secret to reach the staging API with.

It is skipped on pull requests from forks, whose token cannot mint an OIDC
token whatever the job's `permissions:` say.

If the Portal ever starts *rejecting* rather than warning on an invalid
Sigstore signature — Sonatype has said it intends to — this gate is what
catches it a pull request early rather than at a tag.
