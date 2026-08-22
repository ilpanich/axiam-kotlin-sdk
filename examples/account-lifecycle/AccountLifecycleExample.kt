package io.axiam.sdk.examples.accountlifecycle

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.account.PasswordResetConfirmation
import io.axiam.sdk.account.PasswordResetRequest
import kotlinx.coroutines.runBlocking
import java.util.UUID

/**
 * CONTRACT.md §25 — account lifecycle and MFA enrolment: the calls a user makes
 * about their own account, none of which is administration.
 *
 * Four demonstrations:
 *
 * 1. **Forced enrolment** — the third `login` outcome. A tenant that requires
 *    MFA meets an account that has none, and the login is neither a success nor
 *    a failure.
 * 2. **Voluntary enrolment** — the same two calls from inside a session.
 * 3. **Email verification** — unauthenticated, because a user whose address is
 *    unverified may have no session at all.
 * 4. **Password reset** — including the §23 detour a tenant with OPAQUE enabled
 *    forces, and the enumeration guarantee that makes the first call return
 *    nothing useful on purpose.
 *
 * Run: `AXIAM_BASE_URL=… AXIAM_TENANT=… AXIAM_TENANT_ID=… ./gradlew runAccountLifecycleExample`
 */
object AccountLifecycleExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com")
        val tenant = env("AXIAM_TENANT", "acme")
        val tenantId = UUID.fromString(env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000"))

        AxiamClient.builder(baseUrl, tenant).orgSlug("globex").build().use { client ->
            loginWithForcedEnrolment(client)
            enrolVoluntarily(client)
            verifyAnEmailAddress(client, tenantId)
            resetAPassword(client, tenantId)
        }
    }

    // ------------------------------------------------------------------
    // 1. The third login outcome (§25.2 rule 1)
    // ------------------------------------------------------------------

    private suspend fun loginWithForcedEnrolment(client: AxiamClient) {
        println("== login ==")
        val result = client.login("alice@example.com", env("AXIAM_PASSWORD", "pw"))

        when {
            result.mfaSetupRequired -> {
                // Not a failure. The tenant requires MFA, this account has
                // none, and the server handed back a setup token to finish
                // with. There is no session yet — the token IS the credential
                // for the next two calls.
                val setupToken = result.setupToken!!

                val enrollment = client.mfaSetupEnroll(setupToken)
                println("  scan this: ${enrollment.totpUri.expose()}")

                // mfaSetupConfirm completes the LOGIN, not just the enrolment:
                // it adopts credentials exactly as login() does (§25.2 rule 2),
                // so there is nothing left for the caller to install.
                val completed = client.mfaSetupConfirm(setupToken, promptForCode())
                println("  signed in as ${completed.user}")
            }

            result.mfaRequired -> {
                // The account already HAS a factor — challenge it, don't enrol.
                client.verifyMfa(result.challengeToken!!, promptForCode())
                println("  signed in after an MFA challenge")
            }

            else -> println("  signed in as ${result.user}")
        }
    }

    // ------------------------------------------------------------------
    // 2. Voluntary enrolment (§25.1)
    // ------------------------------------------------------------------

    private suspend fun enrolVoluntarily(client: AxiamClient) {
        println("== enrolling TOTP from inside a session ==")
        val enrollment = client.mfaEnroll()

        // Both halves are Sensitive, and the second one matters: the otpauth
        // URI CONTAINS the secret (§25.3). Wrapping the bare secret and then
        // printing the URI into a log leaks exactly the same bytes.
        println("  secret (redacted in toString): ${enrollment.secretBase32}")
        renderQrCode(enrollment.totpUri.expose())

        if (client.mfaConfirm(promptForCode())) {
            println("  MFA is live on this account")
        }

        // Note what did NOT happen: the §17 decision memo was not cleared. The
        // subject has not changed, and discarding a warm memo on an unrelated
        // profile action costs a round trip on every check that follows
        // (§25.2 rule 3).
    }

    // ------------------------------------------------------------------
    // 3. Email verification (§25.1) — no session required
    // ------------------------------------------------------------------

    private suspend fun verifyAnEmailAddress(client: AxiamClient, tenantId: UUID) {
        println("== verifying an email address ==")
        try {
            // The tenant is a BODY field here. §12.1 rule 2's ?tenant_id=
            // convention is scoped to the /oauth2 endpoints, and this is not
            // one of those.
            client.verifyEmail(Sensitive.of(tokenFromTheVerificationMail()), tenantId)
            println("  verified")
        } catch (e: RuntimeException) {
            println("  that link has expired — sending another")
            client.resendVerification("alice@example.com", tenantId)
        }
    }

    // ------------------------------------------------------------------
    // 4. Password reset (§25.4)
    // ------------------------------------------------------------------

    private suspend fun resetAPassword(client: AxiamClient, tenantId: UUID) {
        println("== resetting a password ==")

        // Returns Unit, whether or not the address exists, and this SDK exposes
        // no way to tell the two apart. That is not an omission to improve on:
        // a client that surfaced a "no such user" state — even one inferred
        // from timing — would turn the endpoint into the account-enumeration
        // oracle its uniform response exists to prevent.
        client.requestPasswordReset(PasswordResetRequest("alice@example.com"))
        println("  if that address has an account, a mail is on its way")

        val token = Sensitive.of(tokenFromTheResetMail())

        // Ask the context BEFORE building anything. On a tenant with §23
        // enabled the client has to construct an OPAQUE registration record,
        // and building one needs parameters it cannot know before it has a
        // token to ask with. Sending a plaintext password to a tenant in
        // opaque_mode: required is refused, and refused late (§25.4 rule 1).
        try {
            val context = client.passwordResetContext(token)

            if (context.opaque != null) {
                println("  this tenant uses OPAQUE: ${context.opaque}")
                // Build the record with the SDK's §23 helpers, then:
                //   client.confirmPasswordReset(
                //       PasswordResetConfirmation(token, newPassword, tenantId, opaque = record))
            } else {
                client.confirmPasswordReset(
                    PasswordResetConfirmation(
                        token,
                        Sensitive.of("a new correct horse battery staple"),
                        tenantId,
                    ),
                )
                println("  password changed")
            }
        } catch (e: RuntimeException) {
            // A 404 means unknown, expired OR already-consumed, deliberately
            // without distinguishing them (§25.4 rule 3). Neither does this.
            println("  that reset link is no longer usable")
        }
    }

    // ------------------------------------------------------------------

    private fun promptForCode(): String = env("AXIAM_TOTP_CODE", "123456")

    private fun tokenFromTheVerificationMail(): String =
        env("AXIAM_VERIFY_TOKEN", "paste-the-token-from-the-mail")

    private fun tokenFromTheResetMail(): String =
        env("AXIAM_RESET_TOKEN", "paste-the-token-from-the-mail")

    private fun renderQrCode(otpauthUri: String) {
        println("  [QR code for ${otpauthUri.take(20)}...]")
    }

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
