package io.axiam.sdk.examples.devicelogin

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.oidc.DeviceLoginParams
import kotlinx.coroutines.runBlocking

/**
 * Device Authorization Grant (CONTRACT.md §14) — signing in a device that
 * cannot show a browser.
 *
 * The shape this sample is really demonstrating: the SDK hands you the user
 * code and verification URI **before** it starts polling, and what you do with
 * them is yours. Here that is `println`; on a real device it is a screen, a QR
 * code, or an e-ink panel. The SDK never prints them for you (§14.3 rule 2).
 *
 * `onUserCode` is a `suspend` function, so a device that must await a paint or
 * a redraw can — polling does not begin until it returns.
 */
object DeviceLoginExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = System.getenv("AXIAM_BASE_URL") ?: "https://localhost:8443"
        val tenantId = System.getenv("AXIAM_TENANT_ID") ?: "11111111-2222-3333-4444-555555555555"
        val clientId = System.getenv("AXIAM_OIDC_CLIENT_ID") ?: "my-device"

        // No client secret: a device that cannot show a browser cannot keep one
        // either, and §14.1 makes `deviceAuthorize` unauthenticated for that
        // reason.
        val client = AxiamClient.builder(baseUrl, tenantId)
            .oidcClientId(clientId)
            .build()

        client.use {
            val tokens = try {
                it.deviceLogin(
                    DeviceLoginParams(
                        scope = "openid profile",
                        tenantId = tenantId,
                        onUserCode = { authorization ->
                            println()
                            println("  To sign in, visit: ${authorization.verificationUri}")
                            println("  and enter code:    ${authorization.userCode}")
                            authorization.verificationUriComplete?.let { complete ->
                                // Prefer this when the device can render a QR
                                // code — the user then types nothing at all.
                                // Never build it yourself when it is absent:
                                // the format is the server's to choose (§14.3).
                                println("  or go straight to: $complete")
                            }
                            println()
                            println("Waiting for approval…")
                        },
                    ),
                )
            } catch (e: OAuthProtocolError) {
                // The two failure modes worth telling apart — a human said no,
                // versus nobody answered. Collapsing them loses the only
                // information the device can act on (§14.2 rule 3): whether
                // re-prompting could possibly help.
                when (e.error) {
                    "access_denied" -> println("The user refused the request.")
                    "expired_token" -> println("Nobody answered before the code expired.")
                    else -> throw e
                }
                return@runBlocking
            }

            // §14.3 rule 4 (contract 1.7): this SDK returns the tokens rather
            // than adopting them, matching its `loginClientCredentials`
            // posture.
            println("Signed in. Access token expires in ${tokens.expiresIn}s.")
            tokens.idClaims?.let { claims -> println("Subject: ${claims.sub}") }
        }
    }
}
