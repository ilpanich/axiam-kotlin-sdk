package io.axiam.sdk.examples.loginmfa

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.LoginResult
import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates the two-phase `login()` / `verifyMfa()` flow (CONTRACT.md §1,
 * §5, §5.1), importing ONLY public SDK entry points (`io.axiam.sdk.AxiamClient`
 * and friends — never `io.axiam.sdk.internal.*`).
 *
 * Constructs an [AxiamClient] with a non-optional `tenantId` (§5 — there is no
 * default tenant) AND organization context (§5.1 — a tenant slug is only unique
 * within an organization), calls [AxiamClient.login], and branches on
 * [LoginResult.mfaRequired]: when the server returns an MFA challenge (HTTP 202)
 * instead of a completed session, it calls [AxiamClient.verifyMfa] with the
 * `Sensitive`-wrapped challenge token and a TOTP code to complete the flow.
 *
 * Every operation is a `suspend` function (§1); this `main` wraps them in
 * `runBlocking`. It is illustrative/compilable against the SDK's public API and
 * requires a reachable AXIAM server matching the configured base URL to run
 * end-to-end.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_TENANT_SLUG=... AXIAM_ORG_SLUG=... \
 * AXIAM_EMAIL=... AXIAM_PASSWORD=... \
 *   ./gradlew runLoginMfaExample
 * ```
 */
object LoginMfaExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        val tenantSlug = env("AXIAM_TENANT_SLUG", "acme")
        val orgSlug = env("AXIAM_ORG_SLUG", "acme")
        val email = env("AXIAM_EMAIL", "user@example.com")
        val password = env("AXIAM_PASSWORD", "changeme")
        val totpCode = env("AXIAM_TOTP_CODE", "000000")

        // §5: tenantSlug is a required, positional builder argument — a blank
        // value throws AuthError, never a silent default. §5.1: login/refresh
        // also require organization context — supply it via .orgSlug(...) (or
        // .orgId(UUID)), else login fails at runtime with HTTP 400
        // "must provide org_id or org_slug". TLS is always strict (§6). `use`
        // releases the client's OkHttp connection pool/dispatcher (AutoCloseable).
        AxiamClient.builder(baseUrl, tenantSlug).orgSlug(orgSlug).build().use { client ->
            val result: LoginResult = try {
                client.login(email, password)
            } catch (e: AuthError) {
                System.err.println("login failed: ${e.message}")
                return@runBlocking
            }

            if (result.mfaRequired) {
                println("MFA required — completing the two-phase flow")
                // challengeToken is present exactly when mfaRequired is true (§1).
                val challengeToken = result.challengeToken!!
                val completed = client.verifyMfa(challengeToken, totpCode)
                val user = completed.user!!
                println(
                    "MFA verified — userId: ${user.userId}, " +
                        "tenantId: ${user.tenantId}, roles: ${user.roles}",
                )
            } else {
                val user = result.user!!
                println(
                    "Login complete (no MFA) — userId: ${user.userId}, " +
                        "tenantId: ${user.tenantId}, roles: ${user.roles}",
                )
            }
        }
    }

    private fun env(key: String, fallback: String): String {
        val v = System.getenv(key)
        return if (v.isNullOrBlank()) fallback else v
    }
}
