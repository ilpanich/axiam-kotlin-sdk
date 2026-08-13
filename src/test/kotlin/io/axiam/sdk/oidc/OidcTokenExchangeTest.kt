package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Token Exchange (RFC 8693) — CONTRACT.md §15.
 *
 * Most of §15 is a list of things an SDK must *not* helpfully do, so most of
 * these tests assert an absence: no defaulted `actorToken`, no auto-narrow
 * after `invalid_scope`, no synthesised refresh token, no adoption.
 */
class OidcTokenExchangeTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    private val tenantId = "22222222-2222-2222-2222-222222222222"
    private val subjectToken = "subject-token-value"
    private val actorToken = "actor-token-value"

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun confidentialClient() = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)

    private fun mountExchange(scope: String? = "orders:read", refreshToken: String? = null) {
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.exchangeResponseJson(scope, refreshToken))
    }

    private fun decodedTokenBody(): String {
        server.takeRequest() // discovery
        return java.net.URLDecoder.decode(server.takeRequest().body.readUtf8(), "UTF-8")
    }

    // -----------------------------------------------------------------------
    // §15.1 wire shape
    // -----------------------------------------------------------------------

    @Test
    fun `tokenExchange sends the RFC 8693 grant and authenticates as a confidential client`(): Unit = runBlocking {
        mountExchange()

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(subjectToken),
                scopes = listOf("orders:read", "orders:write"),
                audience = "orders-service",
                tenantId = tenantId,
            ),
        )

        val body = decodedTokenBody()
        assertTrue(body.contains("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"))
        assertTrue(body.contains("subject_token=$subjectToken"))
        assertTrue(body.contains("subject_token_type=urn:ietf:params:oauth:token-type:access_token"))
        assertTrue(body.contains("scope=orders:read orders:write"))
        assertTrue(body.contains("audience=orders-service"))
        assertTrue(
            body.contains("client_secret=${OidcTestKit.CLIENT_SECRET}"),
            "§15.1: the exchanging client is confidential and authenticates",
        )

        assertEquals(OidcTestKit.ISSUED_TOKEN, result.accessToken.expose())
        assertEquals(
            "urn:ietf:params:oauth:token-type:access_token",
            result.issuedTokenType,
            "§15.2 rule 6: issued_token_type is surfaced, not dropped",
        )
        assertEquals(300L, result.expiresIn)
    }

    @Test
    fun `a public client fails client-side with no wire call`(): Unit = runBlocking {
        val calls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            calls.incrementAndGet()
            okhttp3.mockwebserver.MockResponse().setResponseCode(200)
        }

        assertThrows(AuthError::class.java) {
            runBlocking {
                OidcTestKit.clientFor(server).tokenExchange(
                    TokenExchangeParams(subjectToken = Sensitive.of(subjectToken), tenantId = tenantId),
                )
            }
        }
        assertEquals(0, calls.get(), "no request should have been sent")
    }

    // -----------------------------------------------------------------------
    // §15.2 rule 1 — delegation vs impersonation
    // -----------------------------------------------------------------------

    @Test
    fun `an absent actor token is never defaulted`(): Unit = runBlocking {
        mountExchange()

        confidentialClient().tokenExchange(
            TokenExchangeParams(subjectToken = Sensitive.of(subjectToken), tenantId = tenantId),
        )

        val body = decodedTokenBody()
        // §15.2 rule 1: passing none asks for IMPERSONATION. An SDK that
        // helpfully substituted its own session token would silently turn that
        // into a delegation — a different operation with different risk.
        assertFalse(body.contains("actor_token"))
    }

    @Test
    fun `an actor token and its type are sent as a pair`(): Unit = runBlocking {
        mountExchange(scope = null)

        confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(subjectToken),
                actorToken = Sensitive.of(actorToken),
                tenantId = tenantId,
            ),
        )

        val body = decodedTokenBody()
        assertTrue(body.contains("actor_token=$actorToken"))
        // RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
        assertTrue(body.contains("actor_token_type=urn:ietf:params:oauth:token-type:access_token"))
    }

    // -----------------------------------------------------------------------
    // §15.2 rules 2-3 and §15.3 — refusals surface unchanged
    // -----------------------------------------------------------------------

    @Test
    fun `the six error codes reach the caller unchanged, with no retry`(): Unit = runBlocking {
        // Including cross-tenant, which the server deliberately collapses into
        // invalid_grant — the SDK must not re-derive the distinction it
        // withheld (that is a tenant-enumeration signal).
        for (code in listOf(
            "invalid_request", "invalid_grant", "invalid_scope",
            "invalid_target", "unauthorized_client", "invalid_client",
        )) {
            val calls = AtomicInteger(0)
            val status = if (code == "invalid_client") 401 else 400
            dispatcher.on("/oauth2/token") {
                calls.incrementAndGet()
                okhttp3.mockwebserver.MockResponse()
                    .setResponseCode(status)
                    .addHeader("Content-Type", "application/json")
                    .setBody(OidcTestKit.oauth2ErrorJson(code, "$code description"))
            }

            val error = assertThrows(OAuthProtocolError::class.java) {
                runBlocking {
                    confidentialClient().tokenExchange(
                        TokenExchangeParams(
                            subjectToken = Sensitive.of(subjectToken),
                            scopes = listOf("orders:read", "orders:admin"),
                            tenantId = tenantId,
                        ),
                    )
                }
            }
            assertEquals(code, error.error)
            // §15.2 rules 2-3: no retry, no downgrade, no auto-narrowing. The
            // server refuses rather than silently narrowing precisely so the
            // caller finds out HERE.
            assertEquals(1, calls.get())
        }
    }

    // -----------------------------------------------------------------------
    // §15.2 rules 4-7 — what the result is, and is not
    // -----------------------------------------------------------------------

    @Test
    fun `a server-sent refresh token cannot be surfaced`(): Unit = runBlocking {
        // Deliberately hostile fixture: RFC 8693 issues no refresh token, so
        // the type has no property for one and there is nothing to synthesise.
        mountExchange(refreshToken = "should-not-exist")

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(subjectToken = Sensitive.of(subjectToken), tenantId = tenantId),
        )

        assertFalse(result.toString().contains("should-not-exist"))
        assertEquals(OidcTestKit.ISSUED_TOKEN, result.accessToken.expose())
    }

    @Test
    fun `the granted scope is readable when narrower than requested`(): Unit = runBlocking {
        mountExchange(scope = "orders:read")

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(subjectToken),
                scopes = listOf("orders:read", "orders:write"),
                tenantId = tenantId,
            ),
        )

        // §15.2 rule 7: the response scope is the GRANTED set and may be
        // narrower than requested even on success.
        assertEquals("orders:read", result.scope)
    }

    @Test
    fun `an absent scope is null and an empty scope list is omitted`(): Unit = runBlocking {
        mountExchange(scope = null)

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(subjectToken),
                scopes = emptyList(),
                tenantId = tenantId,
            ),
        )

        assertNull(result.scope)
        // §12.1: an absent optional field is omitted, never sent empty.
        assertFalse(decodedTokenBody().contains("scope="))
    }

    @Test
    fun `the issued token is redacted`(): Unit = runBlocking {
        mountExchange()

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(subjectToken = Sensitive.of(subjectToken), tenantId = tenantId),
        )

        assertFalse(
            result.toString().contains(OidcTestKit.ISSUED_TOKEN),
            "§15.5: the issued token is a bearer credential and must not render",
        )
        assertFalse(result.accessToken.toString().contains(OidcTestKit.ISSUED_TOKEN))
    }

    @Test
    fun `a failed exchange never echoes the subject or actor token`(): Unit = runBlocking {
        // §15.5 calls this out specifically: an exchange failure is exactly
        // when a naive implementation logs the request body.
        dispatcher.onJson("/oauth2/token", 400, OidcTestKit.oauth2ErrorJson("invalid_grant", "bad"))

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                confidentialClient().tokenExchange(
                    TokenExchangeParams(
                        subjectToken = Sensitive.of(subjectToken),
                        actorToken = Sensitive.of(actorToken),
                        tenantId = tenantId,
                    ),
                )
            }
        }

        val rendered = "${error.message}${error.error}${error.errorDescription}"
        assertFalse(rendered.contains(subjectToken))
        assertFalse(rendered.contains(actorToken))
    }

    @Test
    fun `resource is sent when supplied`(): Unit = runBlocking {
        mountExchange()

        confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(subjectToken),
                resource = "https://orders.example.com",
                tenantId = tenantId,
            ),
        )

        // RFC 8707's synonym for audience; the server refuses the pair when
        // they disagree, so the SDK passes both through rather than choosing.
        assertTrue(decodedTokenBody().contains("resource=https://orders.example.com"))
    }

    // -----------------------------------------------------------------------
    // §15.7 — external-IdP subject tokens (X4)
    //
    // No new operation: the same tokenExchange carries a partner IdP's token.
    // What changes is which subject tokens the server accepts and what its
    // refusals mean, so these tests are about not getting in the way of
    // either.
    // -----------------------------------------------------------------------

    /**
     * A token minted by a partner's IdP. Opaque to the SDK — deliberately not
     * a well-formed JWT, because nothing here may decode it.
     */
    private val externalSubjectToken = "partner-idp-subject-token"

    /**
     * The one normative `error_description` (§15.7). It means "fix the AXIAM
     * trust configuration", not "fix your token".
     */
    private val issuerNotConfigured =
        "the subject token's issuer is not configured for token exchange"

    @Test
    fun `an external subject_token_type is sent verbatim and the result surfaces unchanged`(): Unit = runBlocking {
        mountExchange(scope = "read:orders")

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(externalSubjectToken),
                subjectTokenType = OidcSupport.JWT_TOKEN_TYPE,
                scopes = listOf("read:orders"),
                audience = "https://orders.internal",
                tenantId = tenantId,
            ),
        )

        val body = decodedTokenBody()
        // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK
        // must not inspect the subject token to pick this, and must not
        // override it.
        assertTrue(
            body.contains("subject_token_type=urn:ietf:params:oauth:token-type:jwt"),
            "the caller's …:jwt must reach the wire, got: $body",
        )
        assertTrue(body.contains("subject_token=$externalSubjectToken"))
        // Delegation across a trust boundary is unsupported; nothing may add one.
        assertFalse(
            body.contains("actor_token"),
            "§15.7: no actor_token may be invented for an external exchange",
        )

        // The cross-domain path is not a different result shape, and §15.2
        // rules 6-7 still hold.
        assertEquals(OidcTestKit.ISSUED_TOKEN, result.accessToken.expose())
        assertEquals("urn:ietf:params:oauth:token-type:access_token", result.issuedTokenType)
        assertEquals("read:orders", result.scope)
    }

    @Test
    fun `subject_token_type is never inferred from the token itself`(): Unit = runBlocking {
        mountExchange()

        // A subject token that *looks* exactly like a JWT. An SDK that sniffed
        // the token would send …:jwt here; §15.7 says it must not look, so the
        // caller's silence still means the §15.1 same-domain default.
        val jwtShaped = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig"
        confidentialClient().tokenExchange(
            TokenExchangeParams(subjectToken = Sensitive.of(jwtShaped), tenantId = tenantId),
        )

        assertTrue(
            decodedTokenBody().contains(
                "subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            ),
            "§15.7: the token's shape must not pick the type",
        )
    }

    @Test
    fun `an actor token with an external subject token is refused without retry`(): Unit = runBlocking {
        val calls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            calls.incrementAndGet()
            okhttp3.mockwebserver.MockResponse()
                .setResponseCode(400)
                .addHeader("Content-Type", "application/json")
                .setBody(
                    OidcTestKit.oauth2ErrorJson(
                        "invalid_request",
                        "actor_token is not supported for an external subject token",
                    ),
                )
        }

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                confidentialClient().tokenExchange(
                    TokenExchangeParams(
                        subjectToken = Sensitive.of(externalSubjectToken),
                        subjectTokenType = OidcSupport.JWT_TOKEN_TYPE,
                        actorToken = Sensitive.of(actorToken),
                        tenantId = tenantId,
                    ),
                )
            }
        }

        assertEquals("invalid_request", error.error)
        // §15.7: no retry, and no rewriting. Dropping the actor token and
        // re-sending would turn a delegation the caller asked for into an
        // impersonation they did not.
        assertEquals(1, calls.get(), "exactly one request")
        val body = decodedTokenBody()
        assertTrue(
            body.contains("actor_token=$actorToken"),
            "the request must be sent as written, actor token included",
        )
        assertTrue(
            body.contains("subject_token_type=urn:ietf:params:oauth:token-type:jwt"),
            "subject_token_type must not be rewritten",
        )
    }

    @Test
    fun `a refused subject_token_type is never retried as another`(): Unit = runBlocking {
        // A refresh token is a re-authentication credential and an ID token is
        // an assertion to a client about a login; neither is a bearer
        // credential for an API, so both are refused BY NAME. Retrying as
        // …:jwt would present one as if it were.
        for (refused in listOf(
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token",
        )) {
            val calls = AtomicInteger(0)
            dispatcher.on("/oauth2/token") {
                calls.incrementAndGet()
                okhttp3.mockwebserver.MockResponse()
                    .setResponseCode(400)
                    .addHeader("Content-Type", "application/json")
                    .setBody(
                        OidcTestKit.oauth2ErrorJson(
                            "invalid_request",
                            "unsupported subject_token_type $refused",
                        ),
                    )
            }

            assertThrows(OAuthProtocolError::class.java) {
                runBlocking {
                    confidentialClient().tokenExchange(
                        TokenExchangeParams(
                            subjectToken = Sensitive.of(externalSubjectToken),
                            subjectTokenType = refused,
                            tenantId = tenantId,
                        ),
                    )
                }
            }

            assertEquals(1, calls.get(), "no retry after a refused type")
            assertTrue(
                decodedTokenBody().contains("subject_token_type=$refused"),
                "§15.7: the refused type must be sent as named, not swapped",
            )
        }
    }

    @Test
    fun `the issuer-not-configured description reaches the caller intact`(): Unit = runBlocking {
        dispatcher.onJson(
            "/oauth2/token",
            400,
            OidcTestKit.oauth2ErrorJson("invalid_grant", issuerNotConfigured),
        )

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                confidentialClient().tokenExchange(
                    TokenExchangeParams(
                        subjectToken = Sensitive.of(externalSubjectToken),
                        subjectTokenType = OidcSupport.JWT_TOKEN_TYPE,
                        tenantId = tenantId,
                    ),
                )
            }
        }

        assertEquals("invalid_grant", error.error)
        // This is the ONLY distinguishable external failure, and the whole
        // point of it is that an integrator can tell "fix the AXIAM trust
        // config" from "fix your token". Truncating or rewording it destroys
        // that.
        assertEquals(issuerNotConfigured, error.errorDescription)
    }

    @Test
    fun `no helper re-exchanges an externally exchanged token`(): Unit = runBlocking {
        // Tokens minted from an external subject token carry `ext_exchange`,
        // and BOTH exchange paths refuse a subject token bearing it: exchanges
        // do not compose. The SDK's part is to never feed a result back in by
        // itself.
        val calls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            calls.incrementAndGet()
            okhttp3.mockwebserver.MockResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.exchangeResponseJson("read:orders", null))
        }

        val result = confidentialClient().tokenExchange(
            TokenExchangeParams(
                subjectToken = Sensitive.of(externalSubjectToken),
                subjectTokenType = OidcSupport.JWT_TOKEN_TYPE,
                tenantId = tenantId,
            ),
        )

        assertEquals(OidcTestKit.ISSUED_TOKEN, result.accessToken.expose())
        // Exactly one exchange happened: nothing looped the result back in.
        // §15.2 rule 5 is what stops it — had the result been adopted, the next
        // exchange would carry it as a *subject* token, which is exactly the
        // re-exchange §15.7 forbids, arrived at by accident rather than by
        // decision.
        assertEquals(1, calls.get(), "exactly one exchange — nothing re-exchanged the result")
    }
}
