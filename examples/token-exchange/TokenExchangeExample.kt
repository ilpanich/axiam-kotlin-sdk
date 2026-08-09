package io.axiam.sdk.examples.tokenexchange

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.OAuthProtocolError
import io.axiam.sdk.oidc.TokenExchangeParams
import kotlinx.coroutines.runBlocking

/**
 * Token Exchange (CONTRACT.md §15) — narrowing a user's token before calling
 * the next service.
 *
 * The situation: an API gateway holds a user's access token and needs to call
 * an orders service. Forwarding the user's token verbatim over-privileges that
 * call and leaves the second hop unable to tell the caller from the user; using
 * the gateway's own service credentials has the right privileges but loses the
 * user entirely. The exchange gives you both.
 */
object TokenExchangeExample {

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        val baseUrl = System.getenv("AXIAM_BASE_URL") ?: "https://localhost:8443"
        val tenantId = System.getenv("AXIAM_TENANT_ID") ?: "11111111-2222-3333-4444-555555555555"
        val clientId = System.getenv("AXIAM_OIDC_CLIENT_ID") ?: "api-gateway"
        val clientSecret = System.getenv("AXIAM_OIDC_CLIENT_SECRET") ?: "gateway-secret"

        // The user's token, as it would arrive on an inbound request.
        val userToken = System.getenv("AXIAM_SUBJECT_TOKEN") ?: "the-users-access-token"

        // Unlike §14's device, an exchanging client is a confidential service
        // and authenticates.
        val client = AxiamClient.builder(baseUrl, tenantId)
            .oidcClientId(clientId)
            .oidcClientSecret(clientSecret)
            .build()

        client.use {
            val exchanged = try {
                // Delegation: "the gateway, acting on behalf of the user".
                // Supplying an `actorToken` is what makes it delegation;
                // omitting it asks for impersonation instead — a different
                // operation with different risk, which the server refuses
                // unless this client holds that grant. The SDK will not pick
                // for you (§15.2 rule 1).
                it.tokenExchange(
                    TokenExchangeParams(
                        subjectToken = Sensitive.of(userToken),
                        scopes = listOf("orders:read"),
                        audience = "orders-service",
                        tenantId = tenantId,
                    ),
                )
            } catch (e: OAuthProtocolError) {
                // Each names something an operator must fix rather than
                // something to retry.
                when (e.error) {
                    "unauthorized_client" ->
                        println("This client may not exchange, or may not impersonate — a registration fact.")
                    // Do NOT re-send with fewer scopes: the server refused
                    // rather than silently narrowing precisely so you would
                    // find out here.
                    "invalid_scope" -> println("You asked for a scope the user does not hold.")
                    // Cross-tenant collapses into this on purpose; do not try
                    // to tell the cases apart.
                    "invalid_grant" -> println("The subject token is invalid, expired, or from another tenant.")
                    else -> Unit
                }
                throw e
            }

            // Read what you actually got. On success the granted scope may
            // still be narrower than requested (§15.2 rule 7) — the client's
            // registration bounds it, and assuming the request was honoured
            // verbatim is how a caller ends up surprised at the *next* service.
            println(
                "exchanged for ${exchanged.expiresIn}s, " +
                    "granted scope: ${exchanged.scope ?: "(server default)"}",
            )

            // Hand it onward in ONE outbound call. It is not this client's
            // session: adopting it would silently re-privilege every later call
            // the gateway makes, and the narrowed token would make most of them
            // fail far from here (rule 5). There is also no refresh token, ever
            // — re-run the exchange (rule 4).
            @Suppress("UNUSED_VARIABLE")
            val authorizationHeader = "Bearer ${exchanged.accessToken.expose()}"
        }
    }
}
