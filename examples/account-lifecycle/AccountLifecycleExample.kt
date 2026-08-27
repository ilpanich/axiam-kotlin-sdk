package io.axiam.sdk.examples.accountlifecycle

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.account.PasswordResetConfirmation
import io.axiam.sdk.account.PasswordResetRequest
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
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

        // §5.2: whether this principal lives in the organization's reserved
        // tenant. Check it BEFORE offering a tenant switch — an ordinary tenant
        // principal is a principal of exactly one tenant, and changing
        // X-Tenant-ID for one of those is a 403 the user discovers.
        if (result.organizationLevel) {
            println("  organization-level: can act on any tenant of its organization")
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
            // The UNAUTHENTICATED resend: this caller followed a link and has
            // no session. It returns normally whatever happens — unknown
            // address, already verified, over the daily limit — because it
            // takes an address from an anonymous caller and a truthful answer
            // there is an oracle for which addresses have accounts (§25.7).
            println("  that link has expired — sending another")
            client.resendVerification("alice@example.com", tenantId)
        }
    }

    /**
     * The AUTHENTICATED resend — and the one a profile page wants (§25.7).
     *
     * Wiring that button to [verifyAnEmailAddress]'s `resendVerification` is
     * the defect §25.7 exists to separate: it reports success while doing
     * nothing, because the address was already verified, or the account was
     * locked, or the daily limit was reached, and the response looks identical
     * in every case.
     *
     * Here the caller is signed in to the account it is asking about, so this
     * one is both available and truthful. It takes no address: the server reads
     * it off the caller's own record, and a parameter would let a session mail
     * an arbitrary one.
     */
    private suspend fun resendMyVerificationMail(client: AxiamClient) {
        println("== resending my own verification mail ==")
        try {
            client.resendOwnVerification()
            // "Sent" means ENQUEUED. Delivery is asynchronous and can still
            // fail at the provider — a queue that accepts everything in front
            // of one that rejects it looks exactly like this succeeding.
            println("  verification mail enqueued")
        } catch (e: ConflictError) {
            println("  already verified, or this account may not be sent one")
        } catch (e: NetworkError) {
            println("  daily resend limit reached — try again tomorrow")
        }
        // Note what is NOT here: a fallback to resendVerification on either of
        // those. It would turn both back into a normal return and rebuild the
        // bug, with an extra round-trip (§25.7 rule 2).
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
