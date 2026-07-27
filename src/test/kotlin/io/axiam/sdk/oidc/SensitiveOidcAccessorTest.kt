package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

/**
 * Follow-up F-03 (cross-SDK CONTRACT.md §12 conformance review, T9):
 * [Sensitive.expose] was `internal`, so a caller holding an [OidcTokenSet]
 * had no supported way to read `accessToken`/`refreshToken`/`idToken` at
 * all — CONTRACT.md §7 rule 3 now recommends widening the accessor
 * precisely because §12 hands tokens to the calling application in the
 * `/oauth2/token` response body rather than via a `Set-Cookie` the SDK
 * captures on its behalf.
 *
 * These tests prove (a) the round trip a real §12 caller performs —
 * complete `oidcExchange` and read the access/refresh token back out —
 * (b) redaction is unaffected by the widening, and (c) a caller can
 * rehydrate a bare `code_verifier` it persisted itself with the public
 * [Sensitive.of] factory and hand it back into `oidcExchange`.
 */
class SensitiveOidcAccessorTest {

    private lateinit var server: okhttp3.mockwebserver.MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = okhttp3.mockwebserver.MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `a caller can read the access and refresh token out of an exchanged OidcTokenSet`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        val configuration = client.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = "the-nonce")
        dispatcher.onJson(
            "/oauth2/token",
            200,
            OidcTestKit.tokenResponseJson(accessToken = "reader-visible-access-tok", refreshToken = "reader-visible-refresh-tok", idToken = idToken),
        )

        val tokens = client.oidcExchange(
            OidcExchangeParams(
                code = "auth-code-1",
                codeVerifier = Sensitive.of("the-verifier"),
                redirectUri = "https://app.example.com/cb",
                nonce = "the-nonce",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )

        // The round trip a real §12 caller performs: read the raw tokens
        // back out to persist/forward them. Sensitive.expose() must be
        // public (not internal) for this call to be part of the SDK's
        // supported, documented public API.
        val accessToken: String = tokens.accessToken.expose()
        val refreshToken: String? = tokens.refreshToken?.expose()

        assertEquals("reader-visible-access-tok", accessToken)
        assertEquals("reader-visible-refresh-tok", refreshToken)
    }

    @Test
    fun `redaction still holds on Sensitive toString and on a containing OidcTokenSet after widening expose`() {
        val accessToken = Sensitive.of("must-never-appear-in-output")

        assertEquals("[SENSITIVE]", accessToken.toString())
        assertFalse(accessToken.toString().contains("must-never-appear-in-output"))

        val tokenSet = OidcTokenSet(
            accessToken = accessToken,
            tokenType = "Bearer",
            expiresIn = 900,
            refreshToken = Sensitive.of("refresh-must-never-appear"),
        )

        val text = tokenSet.toString()
        assertTrue(text.contains("[SENSITIVE]"), "OidcTokenSet.toString() must redact its Sensitive components: $text")
        assertFalse(text.contains("must-never-appear-in-output"))
        assertFalse(text.contains("refresh-must-never-appear"))
    }

    @Test
    fun `a caller can rehydrate a bare code_verifier with Sensitive of and exchange it`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = "the-nonce")
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "rehydrated-flow-access-tok", idToken = idToken))

        // Simulates a caller that persisted the bare code_verifier string in
        // its own session store and must wrap it again before passing it
        // back into oidcExchange — Sensitive.of() is the public factory for
        // exactly this purpose.
        val bareVerifierFromCallersOwnStore = "rehydrated-verifier-value"
        val rehydrated: Sensitive<String> = Sensitive.of(bareVerifierFromCallersOwnStore)

        val tokens = client.oidcExchange(
            OidcExchangeParams(
                code = "auth-code-2",
                codeVerifier = rehydrated,
                redirectUri = "https://app.example.com/cb",
                nonce = "the-nonce",
                tenantId = "22222222-2222-2222-2222-222222222222",
            ),
        )

        assertEquals("rehydrated-flow-access-tok", tokens.accessToken.expose())

        var request = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request recorded")
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, TimeUnit.SECONDS) ?: error("token request not found")
        }
        assertTrue(request.body.readUtf8().contains("code_verifier=$bareVerifierFromCallersOwnStore"))
    }
}
