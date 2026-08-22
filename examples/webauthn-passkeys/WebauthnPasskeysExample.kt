package io.axiam.sdk.examples.webauthnpasskeys

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.webauthn.WebauthnChallenge
import io.axiam.sdk.webauthn.WebauthnFailure
import kotlinx.coroutines.runBlocking

/**
 * CONTRACT.md §24 — WebAuthn / passkeys, from Kotlin.
 *
 * **This SDK ships no §24.6b linked-API helper, and that is not a capability
 * gap.** `axiam-kotlin-sdk` is a plain `kotlin("jvm")` library — no AAR, no
 * Android Gradle Plugin, no second published coordinate — because Android's
 * Credential Manager is *a JSON string in and a JSON string out*, so wrapping
 * it would buy nothing. What the SDK exposes instead is §24.6a's bridge:
 * [WebauthnChallenge.requestJson] goes into `CreatePublicKeyCredentialRequest`,
 * and `registrationResponseJson` comes straight back into `webauthnRegisterFinish`.
 *
 * The same artifact therefore serves both of this SDK's audiences unchanged: a
 * desktop or server JVM (which has no authenticator at all and drives the RP
 * half only) and an Android app (which has one, reached through Credential
 * Manager as [androidCredentialManager] shows).
 *
 * Run: `AXIAM_BASE_URL=… AXIAM_TENANT=… AXIAM_ORG=… ./gradlew runWebauthnPasskeysExample`
 */
object WebauthnPasskeysExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com")
        val tenant = env("AXIAM_TENANT", "acme")
        val org = env("AXIAM_ORG", "globex")

        AxiamClient.builder(baseUrl, tenant).orgSlug(org).build().use { client ->
            enrolAPasskey(client)
            signInWithADiscoverableCredential(client)
        }
        androidCredentialManager()
        classifyWhatWentWrong()
    }

    // ------------------------------------------------------------------
    // 1. Enrolment — requires a session (§24.1)
    // ------------------------------------------------------------------

    private suspend fun enrolAPasskey(client: AxiamClient) {
        println("== enrolling a passkey ==")
        try {
            client.login("alice@example.com", env("AXIAM_PASSWORD", "pw"))

            // The server chooses every option: the challenge, the RP id, the
            // algorithms, the attestation policy, whether a resident key is
            // required. This SDK defaults nothing and validates nothing (§24.0)
            // — a client that "helpfully" filled in a missing field would be
            // overriding a policy decision it cannot see.
            val challenge = client.webauthnRegisterStart()
            println("  options: ${challenge.requestJson}")

            val authenticatorResponse = createCredentialSomehow()

            val credential = client.webauthnRegisterFinish(
                challenge.stateToken,
                credentialName = "Alice's laptop",
                response = authenticatorResponse,
            )
            println("  enrolled: ${credential.name} (${credential.credentialType}), id ${credential.id}")
        } catch (e: AuthzError) {
            // §24.4 rule 1: a 403 here is the tenant's ATTESTATION POLICY
            // rejecting this particular authenticator, and the server's message
            // is the only place that says which one would be accepted. Printing
            // a generic "forbidden" strands the person holding the key.
            println("  policy refused this authenticator: ${e.message}")
        } catch (e: AuthError) {
            println("  not signed in — passkey enrolment needs a session: ${e.message}")
        } catch (e: RuntimeException) {
            // §24.4 rule 2: a 503 from register/start means the tenant's
            // attestation policy needs FIDO metadata the server cannot reach.
            // That is a CONFIGURATION state, not a transient one — the SDK does
            // not retry it, and neither should this loop.
            println("  enrolment unavailable: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // 2. Sign-in — the discoverable ceremony (§24.1)
    // ------------------------------------------------------------------

    private suspend fun signInWithADiscoverableCredential(client: AxiamClient) {
        println("== signing in with a passkey ==")
        try {
            // No username. The authenticator already knows which accounts it
            // holds for this relying party, so the workspace — not the user —
            // is what the server needs, and it comes from the client's own
            // configuration when the argument is null.
            val challenge = client.webauthnDiscoverableStart()

            val result = client.webauthnDiscoverableFinish(
                challenge.stateToken,
                getCredentialSomehow(),
            )

            // As of contract 1.28 the server sets the session cookie triple on
            // this response as well, so the client is signed in for every
            // cookie-driven call that follows. Before that fix a completed
            // ceremony left the caller with no session at all.
            println("  signed in, session ${result.sessionId} valid for ${result.expiresIn}s")
        } catch (e: AuthError) {
            println("  the assertion did not verify: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // 3. Android — the §24.6a JSON bridge
    // ------------------------------------------------------------------

    /**
     * What an Android app writes. Not compiled here (it needs an Android
     * runtime), but the AXIAM half of it is exactly the code above.
     *
     * ```kotlin
     * // build.gradle.kts — the SDK is a plain JVM dependency, no AAR involved
     * implementation("io.github.ilpanich:axiam-kotlin-sdk:<version>")
     * implementation("androidx.credentials:credentials:1.3.0")
     * implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
     *
     * val challenge = client.webauthnRegisterStart()
     *
     * val response = CredentialManager.create(context).createCredential(
     *     context,
     *     CreatePublicKeyCredentialRequest(
     *         // Verbatim. Not re-serialized, not "normalized", not merged with
     *         // a local default — §24.0.
     *         requestJson = challenge.requestJson,
     *     ),
     * ) as CreatePublicKeyCredentialResponse
     *
     * client.webauthnRegisterFinish(
     *     challenge.stateToken,
     *     credentialName = "Pixel 9",
     *     response = response.registrationResponseJson,   // verbatim again
     * )
     * ```
     *
     * Sign-in is the mirror image:
     *
     * ```kotlin
     * val challenge = client.webauthnDiscoverableStart()
     * val credential = CredentialManager.create(context).getCredential(
     *     context,
     *     GetCredentialRequest(listOf(GetPublicKeyCredentialOption(challenge.requestJson))),
     * ).credential as PublicKeyCredential
     *
     * client.webauthnDiscoverableFinish(
     *     challenge.stateToken,
     *     credential.authenticationResponseJson,
     * )
     * ```
     */
    private fun androidCredentialManager() {
        println("== Android: see this function's KDoc ==")
    }

    // ------------------------------------------------------------------
    // 4. Saying something useful when the ceremony fails (§24.6b rule 5)
    // ------------------------------------------------------------------

    private fun classifyWhatWentWrong() {
        println("== classifying a ceremony failure ==")

        // An Android app catches a CreateCredentialException; a browser reports
        // a DOMException. Both carry one machine-readable thing — a name — and
        // translating it once beats translating it in every caller. This SDK
        // links neither platform, so it classifies whatever the caller hands it.
        val fromAndroid = RuntimeException(
            "CreatePublicKeyCredentialDomException: InvalidStateError: already registered",
        )
        val outcome = WebauthnFailure.classify(fromAndroid)
        println("  ${outcome.name}: ${outcome.message}")

        // The distinction that matters: already_registered is the only one
        // whose remedy is "use a different device" rather than "try again".
        check(outcome == WebauthnFailure.ALREADY_REGISTERED)

        // And the one that must never accuse the user. `cancelled` covers both
        // an explicit refusal and a silent timeout, because the spec refuses to
        // distinguish them — telling a website which happened would leak
        // whether an authenticator was present.
        println("  ${WebauthnFailure.classify("NotAllowedError").message}")
    }

    // ------------------------------------------------------------------

    /** Stands in for `navigator.credentials.create()` / Credential Manager. */
    private fun createCredentialSomehow(): String = """
        {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                     "attestationObject":"o2NmbXRkbm9uZQ"},
         "type":"public-key","clientExtensionResults":{}}
    """.trimIndent()

    /** Stands in for `navigator.credentials.get()` / Credential Manager. */
    private fun getCredentialSomehow(): String = """
        {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                     "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                     "userHandle":"dXNlci1oYW5kbGU"},
         "type":"public-key","clientExtensionResults":{}}
    """.trimIndent()

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
