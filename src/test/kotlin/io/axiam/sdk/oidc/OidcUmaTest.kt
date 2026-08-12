package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * UMA 2.0 — CONTRACT.md §20.7 required assertions.
 *
 * Most of §20, like §15, is a list of things an SDK must *not* helpfully do, so
 * most of these tests assert an absence. The centrepiece is §20.2 rule 6: a
 * permission ticket must never be retried.
 *
 * That rule is the one §16 exception in the contract, and the only way to
 * assert it is to count requests. A ticket is consumed *before* the request is
 * evaluated, so a failed exchange has already spent it — and under concurrency
 * a retry is precisely the second redemption that ilpanich/axiam#302's measured
 * residual describes. "Exactly one request" is a security assertion here, not a
 * performance one.
 *
 * Every test is named after the thing it stops.
 */
class OidcUmaTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    private val pat = Sensitive.of("pat-token-value")
    private val ticket = Sensitive.of("ticket-value")
    private val claimToken = Sensitive.of("claim-token-value")
    private val resourceId = "99999999-8888-7777-6666-555555555555"

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

    private fun confidentialClient() =
        OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)

    private fun rptJson() =
        """{"access_token":"rpt-value","token_type":"Bearer","expires_in":300}"""

    // -----------------------------------------------------------------------
    // §20.2 rule 6 — the ticket grant is never retried
    // -----------------------------------------------------------------------

    /**
     * A `500` must not be retried. The ticket is spent whether or not the
     * exchange succeeded, so a retry cannot succeed — and it is the concurrent
     * redemption ilpanich/axiam#302 measures.
     */
    @Test
    fun `a 5xx on the ticket grant is not retried`(): Unit = runBlocking {
        dispatcher.onJson("/oauth2/token", 500, "{}")

        assertThrows(Exception::class.java) {
            runBlocking {
                confidentialClient().umaExchangeTicket(
                    UmaExchangeTicketParams(ticket = ticket, claimToken = claimToken),
                )
            }
        }

        // Discovery plus exactly one token request — no retry.
        assertEquals(
            2,
            server.requestCount,
            "the ticket grant must issue exactly one request — retrying a spent " +
                "ticket is the concurrent redemption ilpanich/axiam#302 describes",
        )
    }

    /** `invalid_grant` is what a replayed ticket gets, and it is not retried either. */
    @Test
    fun `an invalid_grant on the ticket grant is not retried`(): Unit = runBlocking {
        dispatcher.onJson(
            "/oauth2/token",
            400,
            """{"error":"invalid_grant","error_description":"permission ticket is invalid, expired, or already used"}""",
        )

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                confidentialClient().umaExchangeTicket(
                    UmaExchangeTicketParams(ticket = ticket, claimToken = claimToken),
                )
            }
        }

        assertEquals("invalid_grant", error.error)
        assertEquals(2, server.requestCount)
    }

    /**
     * `access_denied` arrives as **403** on this grant (UMA 2.0 §3.3.6), unlike
     * RFC 8628's, which is a 400. The SDK dispatches on the `error` field, so
     * the code reaches the caller either way — and the refusal is not
     * auto-narrowed into a smaller ticket request (§20.2 rule 3).
     */
    @Test
    fun `access_denied surfaces as itself and is not auto-narrowed`(): Unit = runBlocking {
        dispatcher.onJson(
            "/oauth2/token",
            403,
            """{"error":"access_denied","error_description":"the requesting party is not authorized for every requested permission"}""",
        )

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                confidentialClient().umaExchangeTicket(
                    UmaExchangeTicketParams(ticket = ticket, claimToken = claimToken),
                )
            }
        }

        assertEquals(
            "access_denied",
            error.error,
            "the 403 must not be flattened into a generic authorization error",
        )
        assertEquals(
            2,
            server.requestCount,
            "a refused ticket must not be re-requested with fewer scopes",
        )
    }

    // -----------------------------------------------------------------------
    // The ticket grant's wire shape
    // -----------------------------------------------------------------------

    @Test
    fun `the grant sends the required claim_token and format`(): Unit = runBlocking {
        dispatcher.onJson("/oauth2/token", 200, rptJson())

        val rpt = confidentialClient().umaExchangeTicket(
            UmaExchangeTicketParams(ticket = ticket, claimToken = claimToken),
        )

        server.takeRequest() // discovery
        val body = java.net.URLDecoder.decode(server.takeRequest().body.readUtf8(), "UTF-8")
        assertTrue(
            body.contains("grant_type=urn:ietf:params:oauth:grant-type:uma-ticket"),
            "unexpected body: $body",
        )
        assertTrue(body.contains("ticket=ticket-value"), "unexpected body: $body")
        assertTrue(body.contains("claim_token=claim-token-value"), "unexpected body: $body")
        assertTrue(body.contains("claim_token_format="), "unexpected body: $body")

        assertEquals("rpt-value", rpt.accessToken.expose())
        assertEquals(300L, rpt.expiresIn)
    }

    /**
     * §20.2 rule 5: the grant issues no refresh token, so the data class has no
     * property for one — an application that wants a fresh RPT re-runs the
     * grant. Asserted structurally, because a property that does not exist
     * cannot be populated by a server that sends one anyway.
     */
    @Test
    fun `the rpt type cannot carry a refresh token`() {
        assertTrue(
            RequestingPartyToken::class.members.none {
                it.name.lowercase().contains("refresh")
            },
            "RequestingPartyToken must have no refresh-token property",
        )
    }

    // -----------------------------------------------------------------------
    // The Protection API
    // -----------------------------------------------------------------------

    /**
     * The UMA `_id` **is** the AXIAM resource id — there is no parallel
     * identifier to translate through.
     */
    @Test
    fun `a registered id is usable as a ticket resource id`(): Unit = runBlocking {
        dispatcher.onJson(
            "/uma2/rreg/resource_set",
            201,
            """{"_id":"$resourceId","name":"invoice-7","type":"document","resource_scopes":["view"]}""",
        )
        dispatcher.onJson("/uma2/perm", 201, """{"ticket":"ticket-value"}""")

        val client = confidentialClient()
        val registered = client.umaRegisterResource(
            pat,
            ResourceSet(name = "invoice-7", type = "document", resourceScopes = listOf("view")),
        )
        assertEquals(resourceId, registered.id)

        val minted = client.umaRequestTicket(
            pat,
            listOf(RequestedPermission(resourceId = registered.id!!, resourceScopes = listOf("view"))),
        )
        assertEquals("ticket-value", minted.expose())

        server.takeRequest() // registration
        val permBody = server.takeRequest().body.readUtf8()
        assertTrue(permBody.contains("\"resource_id\":\"$resourceId\""), "unexpected body: $permBody")
    }

    @Test
    fun `the pat is sent as a bearer token`(): Unit = runBlocking {
        dispatcher.onJson("/uma2/perm", 201, """{"ticket":"ticket-value"}""")

        confidentialClient().umaRequestTicket(
            pat,
            listOf(RequestedPermission(resourceId = resourceId, resourceScopes = listOf("view"))),
        )

        assertEquals("Bearer pat-token-value", server.takeRequest().getHeader("Authorization"))
    }

    /**
     * §20.2 rule 8: an update replaces the scope list. No GET is mounted, so a
     * read-modify-write implementation would fail here rather than pass
     * quietly.
     */
    @Test
    fun `an update sends only the scopes given and does not read first`(): Unit = runBlocking {
        dispatcher.onJson(
            "/uma2/rreg/resource_set/$resourceId",
            200,
            """{"_id":"$resourceId","name":"invoice-7","resource_scopes":["view"]}""",
        )

        confidentialClient().umaUpdateResource(
            pat,
            resourceId,
            ResourceSet(name = "invoice-7", type = "document", resourceScopes = listOf("view")),
        )

        assertEquals(1, server.requestCount, "no read-before-write")
        val request = server.takeRequest()
        assertEquals("PUT", request.method)
        assertTrue(request.body.readUtf8().contains("""["view"]"""))
    }

    /**
     * Omitting the key would leave the server's copy untouched, which would
     * make clearing a scope set impossible through the SDK.
     */
    @Test
    fun `an update that drops every scope still sends the key`(): Unit = runBlocking {
        dispatcher.onJson(
            "/uma2/rreg/resource_set/$resourceId",
            200,
            """{"_id":"$resourceId","name":"invoice-7","resource_scopes":[]}""",
        )

        confidentialClient().umaUpdateResource(pat, resourceId, ResourceSet(name = "invoice-7"))

        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("\"resource_scopes\":[]"), "unexpected body: $body")
    }

    @Test
    fun `a non-pat refusal reaches the caller`(): Unit = runBlocking {
        dispatcher.onJson(
            "/uma2/perm",
            403,
            """{"error":"authorization_denied","message":"the protection API requires the 'uma_protection' scope"}""",
        )

        assertThrows(Exception::class.java) {
            runBlocking {
                confidentialClient().umaRequestTicket(
                    Sensitive.of("not-a-pat"),
                    listOf(RequestedPermission(resourceId = resourceId, resourceScopes = listOf("view"))),
                )
            }
        }

        assertEquals(1, server.requestCount)
    }

    @Test
    fun `the listing returns ids`(): Unit = runBlocking {
        dispatcher.onJson("/uma2/rreg/resource_set", 200, """["$resourceId"]""")

        assertEquals(listOf(resourceId), confidentialClient().umaListResources(pat))
    }

    // -----------------------------------------------------------------------
    // §20.3 the challenge helpers
    // -----------------------------------------------------------------------

    @Test
    fun `parses a well-formed challenge`() {
        val parsed = umaParseChallenge(
            """UMA realm="example", as_uri="https://id.example", ticket="ticket-value"""",
        )
        assertNotNull(parsed)
        assertEquals("example", parsed!!.realm)
        assertEquals("https://id.example", parsed.asUri)
        assertEquals("ticket-value", parsed.ticket!!.expose())
    }

    @Test
    fun `rejects a scheme that merely starts with UMA`() {
        assertNull(umaParseChallenge("""Bearer realm="example""""))
        assertNull(umaParseChallenge("""UMAX realm="example""""))
    }

    @Test
    fun `the challenge round-trips through the emit half`() {
        val header = umaChallengeHeader("example", "https://id.example", Sensitive.of("tkt"))
        val parsed = umaParseChallenge(header)
        assertNotNull(parsed)
        assertEquals("https://id.example", parsed!!.asUri)
        assertEquals("tkt", parsed.ticket!!.expose())
    }

    /** §20.6: the ticket's 60-second life is exactly what invites logging it. */
    @Test
    fun `the ticket is redacted in toString`() {
        val parsed = umaParseChallenge("""UMA ticket="super-secret-ticket"""")
        assertNotNull(parsed)
        assertFalse(
            parsed.toString().contains("super-secret-ticket"),
            "the ticket must be redacted in toString, got: $parsed",
        )
    }
}
