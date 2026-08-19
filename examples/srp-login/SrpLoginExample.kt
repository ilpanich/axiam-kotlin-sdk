package io.axiam.sdk.examples.srplogin

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.srp.SrpKdfParams
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates the SRP-6a login path (CONTRACT.md §23), importing ONLY public
 * SDK entry points.
 *
 * SRP proves the password to the server without the password — or anything from
 * which it can be cheaply recovered — ever crossing the wire. What the server
 * receives is `A` and a proof, neither of which is useful without the account's
 * verifier, so a TLS-terminating proxy, an accidentally verbose request log or
 * a heap dump cannot capture a plaintext password. It does **not** protect
 * against a compromised AXIAM server.
 *
 * Three things this example is built to show:
 *
 *  1. [AxiamClient.loginSrp] returns the SAME `LoginResult` as
 *     [AxiamClient.login], MFA branch included, so the result handling below is
 *     identical to `examples/login-mfa`.
 *  2. A tenant with `srp_mode: disabled` answers the challenge endpoint with
 *     `404`, which reaches the caller as [NetworkError] and NOT as a credential
 *     failure — so falling back to `login()` is correct and safe.
 *  3. A tenant with `srp_mode: required` answers `/auth/login` with
 *     `403 srp_required`, which is an [AuthzError]. A user whose password is
 *     perfectly good must never be shown "invalid username or password".
 *
 * Illustrative and compile-checked against the public API; running it
 * end-to-end requires a reachable AXIAM server with SRP enabled for the tenant.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_TENANT_SLUG=... AXIAM_USERNAME=... AXIAM_PASSWORD=... \
 *   ./gradlew runSrpLoginExample
 * ```
 */
object SrpLoginExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = System.getenv("AXIAM_BASE_URL") ?: "https://localhost:8443"
        val tenantSlug = System.getenv("AXIAM_TENANT_SLUG") ?: "acme"
        val orgSlug = System.getenv("AXIAM_ORG_SLUG") ?: "acme"
        val username = System.getenv("AXIAM_USERNAME") ?: "alice"
        // A CharArray rather than a String so it can be cleared. The SDK clears
        // every copy it makes; it cannot clear the caller's.
        val password = (System.getenv("AXIAM_PASSWORD") ?: "hunter2").toCharArray()

        AxiamClient.builder(baseUrl, tenantSlug).orgSlug(orgSlug).build().use { client ->
            // On the JVM this is always true. It exists because PHP — the one
            // language with no native bignum — genuinely answers false, and
            // §23.1 puts the probe in every SDK's vocabulary so portable code
            // can ask.
            if (!client.srpAvailable()) {
                System.err.println("this SDK build cannot perform SRP")
                return@runBlocking
            }

            var result = try {
                client.loginSrp(username, password.copyOf())
            } catch (e: NetworkError) {
                // A tenant that has not enabled SRP is not a failed login. Fall
                // back rather than reporting a credential problem the user does
                // not have.
                println("SRP unavailable on this tenant (${e.message}) — falling back to password login")
                try {
                    client.login(username, String(password))
                } catch (denied: AuthzError) {
                    // srp_mode: required. The credentials were never examined.
                    System.err.println("this tenant refuses password login: ${denied.message}")
                    return@runBlocking
                }
            }

            if (result.mfaRequired) {
                // Identical to the non-SRP path — that is the point of §23.1's
                // same-result-type requirement.
                val code = System.getenv("AXIAM_TOTP_CODE")
                if (code.isNullOrEmpty()) {
                    System.err.println("MFA required; set AXIAM_TOTP_CODE")
                    return@runBlocking
                }
                result = client.verifyMfa(result.challengeToken!!, code)
            }

            println("authenticated as ${result.user!!.userId}")

            // Enrolment, for any request that SETS a password. The server
            // cannot compute a verifier — it never sees the plaintext — so it
            // has to arrive with the request or not at all. Read the tenant's
            // parameters from GET /api/v1/auth/me (or the reset context) rather
            // than hard-coding them: the server dictates the costs per
            // exchange, and a verifier enrolled under different costs stays
            // valid.
            val newPassword = System.getenv("AXIAM_NEW_PASSWORD")
            if (!newPassword.isNullOrEmpty()) {
                val enrolment = client.srpEnrollment(
                    // The account's USERNAME, which is the canonical identity
                    // the challenge endpoint hands back. An email here produces
                    // a verifier no login can ever satisfy.
                    identity = username,
                    password = newPassword.toCharArray(),
                    params = SrpKdfParams(SrpKdfParams.ARGON2ID, 0),
                )
                // Send this as the `srp` member of the change-password body.
                // Never log it: salt and verifier are §23.3 rule 12 material.
                println("enrolment ready: group=${enrolment.group} kdf=${enrolment.kdf}")
            }
        }
        password.fill(' ')
    }
}
