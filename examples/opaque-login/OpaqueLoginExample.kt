package io.axiam.sdk.examples.opaquelogin

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates the OPAQUE (RFC 9807) login path (CONTRACT.md §23), importing
 * ONLY public SDK entry points.
 *
 * OPAQUE proves the password to the server without the password — or anything
 * from which it can be cheaply recovered — ever crossing the wire. What the
 * server receives is a blinded group element and a MAC, neither useful without
 * the account's registration record *and* the tenant's OPRF seed. So a
 * TLS-terminating proxy, an accidentally verbose request log or a heap dump
 * cannot capture a plaintext password, and a stolen record database is not
 * offline-crackable on its own — the pre-computation resistance the SRP-6a this
 * replaces could not offer. It does **not** protect against a compromised AXIAM
 * server.
 *
 * Four things this example is built to show:
 *
 *  1. [AxiamClient.opaqueAvailable] is asked FIRST, and genuinely answers
 *     `false` when it should: the protocol comes from `libaxiam_opaque_ffi`
 *     through JNA, and both are optional.
 *  2. [AxiamClient.loginOpaque] returns the SAME `LoginResult` as
 *     [AxiamClient.login], MFA branch included, so the result handling below is
 *     identical to `examples/login-mfa`.
 *  3. A tenant with `opaque_mode: disabled` answers the start endpoint with
 *     `404`, which reaches the caller as [NetworkError] and NOT as a credential
 *     failure — so falling back to `login()` is correct and safe. An
 *     [AuthError] is the opposite case and must NOT be retried that way: under
 *     `opaque_mode: optional` the SDK has already made that retry itself
 *     (§23.4 rule 7), so a second one only re-sends a password that just
 *     failed.
 *  4. A tenant with `opaque_mode: required` answers `/auth/login` with `403`,
 *     which is an [AuthzError]. A user whose password is perfectly good must
 *     never be shown "invalid username or password".
 *
 * Illustrative and compile-checked against the public API; running it
 * end-to-end requires a reachable AXIAM server with OPAQUE enabled for the
 * tenant, and the shared library on `java.library.path` (or
 * `AXIAM_OPAQUE_LIBRARY` pointing at it).
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_TENANT_SLUG=... AXIAM_USERNAME=... AXIAM_PASSWORD=... \
 *   ./gradlew runOpaqueLoginExample
 * ```
 */
object OpaqueLoginExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = System.getenv("AXIAM_BASE_URL") ?: "https://localhost:8443"
        val tenantSlug = System.getenv("AXIAM_TENANT_SLUG") ?: "acme"
        val orgSlug = System.getenv("AXIAM_ORG_SLUG") ?: "acme"
        val username = System.getenv("AXIAM_USERNAME") ?: "alice"
        // A CharArray rather than a String so it can be cleared. The SDK clears
        // every copy it makes; it cannot clear the caller's.
        val password = (System.getenv("AXIAM_PASSWORD") ?: "").toCharArray()

        try {
            AxiamClient.builder(baseUrl, tenantSlug).orgSlug(orgSlug).build().use { client ->
                // Ask up front rather than discovering the gap mid-exchange.
                // Unlike the srpAvailable() this replaces -- hard-coded true on
                // the JVM -- this can really be false: net.java.dev.jna:jna is
                // compileOnly, and the shared library is a per-platform release
                // asset rather than a Maven artifact.
                var result = if (!client.opaqueAvailable()) {
                    println("libaxiam_opaque_ffi is not installed - using password login")
                    client.login(username, String(password))
                } else {
                    try {
                        // OPAQUE first, password second. The reverse order would
                        // mean a tenant running `opaque_mode: optional` never
                        // sees a single OPAQUE login -- which is the mode
                        // operators run for the whole of a migration.
                        client.loginOpaque(username, password.copyOf())
                    } catch (e: NetworkError) {
                        if ("opaque_mode is disabled" !in (e.message ?: "")) {
                            // A key-stretching function this build cannot
                            // perform, or a cost outside the accepted band. A
                            // configuration problem: falling back would hide it,
                            // and the plaintext would go to the server anyway.
                            throw e
                        }
                        println("OPAQUE unavailable on this tenant (${e.message}) - falling back")
                        client.login(username, String(password))
                    } catch (e: AuthError) {
                        // This covers BOTH halves of the mutual authentication:
                        // the envelope only opens under the right password, and
                        // KE2's MAC only verifies if the server actually holds
                        // the record. Do NOT retry over login() here: §23.4
                        // rule 7 puts that decision inside the SDK, which
                        // retries by itself when the tenant runs
                        // `opaque_mode: optional` and refuses to when it runs
                        // `required` (or is too old to say). Either way this
                        // AuthError is the final answer.
                        System.err.println("login failed: ${e.message}")
                        System.err.println("Not retrying with a password.")
                        return@runBlocking
                    } catch (e: AuthzError) {
                        // opaque_mode: required, reached through login()
                        // elsewhere in an application. The credentials were
                        // never examined.
                        System.err.println("this tenant refuses password login: ${e.message}")
                        return@runBlocking
                    }
                }

                if (result.mfaRequired) {
                    // Identical to the non-OPAQUE path -- that is the point of
                    // the same-result-type requirement.
                    val code = System.getenv("AXIAM_TOTP_CODE")
                    if (code.isNullOrEmpty()) {
                        System.err.println("MFA required; set AXIAM_TOTP_CODE")
                        return@runBlocking
                    }
                    result = client.verifyMfa(result.challengeToken!!, code)
                }

                println("authenticated as ${result.user?.userId}")

                // Enrolment, for any request that SETS a password. The server
                // cannot build a registration record -- it never sees the
                // plaintext -- so it has to arrive with the request or not at
                // all.
                //
                // Note what is NOT passed. No identity: a record binds to a
                // credential identifier the server chooses, so unlike the SRP
                // verifier this replaces there is no username/email confusion
                // that can produce a credential no login will ever satisfy. And
                // no group or KDF: those come from the register/start response,
                // so a caller cannot pick a cost the server will not honour.
                val newPassword = (System.getenv("AXIAM_NEW_PASSWORD") ?: "").toCharArray()
                if (newPassword.isNotEmpty()) {
                    try {
                        val enrolment = client.opaqueEnrollment(newPassword)
                        // Send enrolment.toJson() as the `opaque` member of the
                        // change-password body. Never log the record itself.
                        println("enrolment ready for session ${enrolment.opaqueSession}")
                    } finally {
                        newPassword.fill(' ')
                    }
                }
            }
        } finally {
            password.fill(' ')
        }
    }
}
