package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * RP-initiated and back-channel logout — CONTRACT.md §12.7.
 *
 * The §12.7.6 required tests. The `verifyLogoutToken` half carries the
 * security weight: its input arrives unsolicited, from the network, and
 * instructs the RP to terminate a session — so each rejection test names the
 * attack it prevents rather than merely asserting an error.
 */
class OidcLogoutTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    private val idToken = "the-users-id-token"

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

    private fun issuer() = server.url("/").toString().trimEnd('/')

    private fun client() = OidcTestKit.clientFor(server)

    private fun query(url: String, name: String): String? = url.toHttpUrl().queryParameter(name)

    // -----------------------------------------------------------------------
    // §12.7.2 logoutUrl
    // -----------------------------------------------------------------------

    @Test
    fun `logoutUrl uses the discovered endpoint rather than concatenating onto the issuer`(): Unit = runBlocking {
        val url = client().logoutUrl(LogoutUrlParams(idToken = Sensitive.of(idToken)))

        // §12.7.2 rule 1: the endpoint comes from discovery. Code that builds
        // "{issuer}/oauth2/end_session" works against AXIAM and breaks against
        // every other OP the same application is pointed at.
        assertTrue(url.startsWith("${issuer()}/oauth2/end_session"))
        assertEquals(idToken, query(url, "id_token_hint"))
    }

    @Test
    fun `logoutUrl omits what was not supplied and passes state through unmodified`(): Unit = runBlocking {
        val c = client()

        val bare = c.logoutUrl(LogoutUrlParams(idToken = Sensitive.of(idToken)))
        assertNull(query(bare, "post_logout_redirect_uri"))
        assertNull(query(bare, "state"))

        val full = c.logoutUrl(
            LogoutUrlParams(
                idToken = Sensitive.of(idToken),
                postLogoutRedirectUri = "https://app.example.com/bye",
                state = "caller-generated-state",
            ),
        )
        assertEquals("https://app.example.com/bye", query(full, "post_logout_redirect_uri"))
        // §12.7.2 rule 2: the SDK never invents one, because the value only
        // means something to the caller.
        assertEquals("caller-generated-state", query(full, "state"))
    }

    @Test
    fun `logoutUrl does not pre-validate the redirect against a local list`(): Unit = runBlocking {
        // §12.7.2 rule 3: the allow-list lives in the client's server-side
        // registration. A client-side copy would drift and reject a URI an
        // operator had just registered.
        val url = client().logoutUrl(
            LogoutUrlParams(
                idToken = Sensitive.of(idToken),
                postLogoutRedirectUri = "https://somewhere-else.example/x",
            ),
        )
        assertEquals("https://somewhere-else.example/x", query(url, "post_logout_redirect_uri"))
    }

    @Test
    fun `logoutUrl errors when the server advertises no end_session_endpoint`(): Unit = runBlocking {
        server.dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = { OidcTestKit.discoveryJsonWithoutOptionalEndpoints(server.url("/").toString()) },
            jwksBody = { OidcTestKit.jwksJson(signingKey.toPublicJWK()) },
        )

        val error = assertThrows(AuthError::class.java) {
            runBlocking { client().logoutUrl(LogoutUrlParams(idToken = Sensitive.of("super-secret-id-token"))) }
        }
        assertTrue(error.message!!.contains("end_session_endpoint"))
        assertFalse(
            error.message!!.contains("super-secret-id-token"),
            "the ID token must never appear in an error",
        )
    }

    // -----------------------------------------------------------------------
    // §12.7.3 verifyLogoutToken
    // -----------------------------------------------------------------------

    @Test
    fun `a valid logout token surfaces sid, sub and jti`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signingKey, issuer())

        val verified = client().verifyLogoutToken(token)

        // Not a bare Boolean: the RP has to know WHICH session to end, and a
        // verifier that only says "valid" forces the caller to re-parse the
        // token themselves with none of these checks.
        assertEquals(OidcTestKit.LOGOUT_SID, verified.sid)
        assertEquals("user-1", verified.sub)
        assertEquals(OidcTestKit.LOGOUT_JTI, verified.jti)
    }

    @Test
    fun `an ID token replayed as a logout token is rejected`(): Unit = runBlocking {
        // The attack rules 3 and 4 exist to stop, asserted with a real,
        // otherwise-valid ID token rather than a synthetic mutation: correctly
        // signed by a published key, right issuer and audience, unexpired.
        // Only the missing `events` and the present `nonce` distinguish it.
        val idTokenJwt = OidcTestKit.signIdToken(signingKey, issuer())

        assertThrows(AuthError::class.java) {
            runBlocking { client().verifyLogoutToken(idTokenJwt) }
        }
    }

    @Test
    fun `a token with no events, or the wrong event, is rejected`(): Unit = runBlocking {
        val c = client()

        val noEvents = OidcTestKit.signLogoutToken(signingKey, issuer(), omitEvents = true)
        val noEventsError = assertThrows(AuthError::class.java) {
            runBlocking { c.verifyLogoutToken(noEvents) }
        }
        assertTrue(noEventsError.message!!.contains("events"))

        val otherEvent = OidcTestKit.signLogoutToken(
            signingKey,
            issuer(),
            eventKey = "http://schemas.openid.net/event/some-other-thing",
        )
        assertThrows(AuthError::class.java) { runBlocking { c.verifyLogoutToken(otherEvent) } }
    }

    @Test
    fun `an events value that is not an object is rejected`(): Unit = runBlocking {
        // Back-Channel Logout 1.0 §2.4 specifies a JSON object (normally
        // empty); accepting a string would let a near-miss token through on a
        // technicality.
        val token = OidcTestKit.signLogoutToken(signingKey, issuer(), eventValueNotAnObject = true)

        assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
    }

    @Test
    fun `a nonce is rejected rather than ignored`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signingKey, issuer(), nonce = "n-0S6_WzA2Mj")

        val error = assertThrows(AuthError::class.java) {
            runBlocking { client().verifyLogoutToken(token) }
        }
        assertTrue(error.message!!.contains("nonce"))
    }

    @Test
    fun `a token naming neither sid nor sub is rejected`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signingKey, issuer(), sid = null, subject = null)

        val error = assertThrows(AuthError::class.java) {
            runBlocking { client().verifyLogoutToken(token) }
        }
        assertTrue(error.message!!.contains("identifies no session"))
    }

    @Test
    fun `sub alone is accepted, and sid is preferred when present`(): Unit = runBlocking {
        val c = client()

        val subOnly = OidcTestKit.signLogoutToken(signingKey, issuer(), sid = null)
        val verified = c.verifyLogoutToken(subOnly)
        assertNull(verified.sid)
        assertEquals("user-1", verified.sub)

        // With sid present the RP must end THAT session only — falling back to
        // "every session for sub" is over-reach the server itself refuses.
        val both = c.verifyLogoutToken(OidcTestKit.signLogoutToken(signingKey, issuer()))
        assertEquals(OidcTestKit.LOGOUT_SID, both.sid)
    }

    @Test
    fun `a token for another client or another issuer is rejected`(): Unit = runBlocking {
        val c = client()

        val wrongAud = OidcTestKit.signLogoutToken(signingKey, issuer(), audience = "some-other-rp")
        assertTrue(
            assertThrows(AuthError::class.java) { runBlocking { c.verifyLogoutToken(wrongAud) } }
                .message!!.contains("audience"),
        )

        val wrongIss = OidcTestKit.signLogoutToken(signingKey, "https://evil.example.com")
        assertTrue(
            assertThrows(AuthError::class.java) { runBlocking { c.verifyLogoutToken(wrongIss) } }
                .message!!.contains("issuer"),
        )
    }

    @Test
    fun `a token signed by an unpublished key is rejected without echoing the token`(): Unit = runBlocking {
        val rogue = OidcTestKit.generateSigningKey(kid = "rogue-kid")
        val token = OidcTestKit.signLogoutToken(rogue, issuer())

        // The signature is what makes the token a statement rather than a
        // request.
        val error = assertThrows(AuthError::class.java) {
            runBlocking { client().verifyLogoutToken(token) }
        }
        assertFalse(
            error.message!!.contains(token),
            "an unverifiable logout token is exactly what a naive implementation logs",
        )
    }

    @Test
    fun `an expired or stale token is rejected`(): Unit = runBlocking {
        val c = client()
        val now = System.currentTimeMillis() / 1000

        // A long-lived logout token is a replayable session-termination command.
        val expired = OidcTestKit.signLogoutToken(
            signingKey, issuer(), expEpochSec = now - 600, iatEpochSec = now - 700,
        )
        assertThrows(AuthError::class.java) { runBlocking { c.verifyLogoutToken(expired) } }

        // exp still ahead, but issued a day ago: a captured delivery being
        // replayed rather than a live one.
        val stale = OidcTestKit.signLogoutToken(
            signingKey, issuer(), iatEpochSec = now - 86_400, expEpochSec = now + 600,
        )
        assertTrue(
            assertThrows(AuthError::class.java) { runBlocking { c.verifyLogoutToken(stale) } }
                .message!!.contains("too old"),
        )
    }

    @Test
    fun `a token issued in the future is rejected`(): Unit = runBlocking {
        val now = System.currentTimeMillis() / 1000
        val token = OidcTestKit.signLogoutToken(
            signingKey, issuer(), iatEpochSec = now + 600, expEpochSec = now + 900,
        )

        assertTrue(
            assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
                .message!!.contains("future"),
        )
    }

    @Test
    fun `a token with no jti is rejected`(): Unit = runBlocking {
        val token = OidcTestKit.signLogoutToken(signingKey, issuer(), jti = null)

        assertTrue(
            assertThrows(AuthError::class.java) { runBlocking { client().verifyLogoutToken(token) } }
                .message!!.contains("jti"),
            "without jti the RP cannot dedup at-least-once redeliveries",
        )
    }

    @Test
    fun `verifying the same token twice does not raise`(): Unit = runBlocking {
        // §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid
        // token legitimately arrives twice — that is a retry, not an attack. An
        // SDK that dedupped internally would have no durable store and would
        // silently drop a real second logout after a restart, so jti is
        // surfaced for the RP to dedup on and never consumed here.
        val c = client()
        val token = OidcTestKit.signLogoutToken(signingKey, issuer())

        val first = c.verifyLogoutToken(token)
        val second = c.verifyLogoutToken(token)

        assertEquals(first, second)
        assertEquals(OidcTestKit.LOGOUT_JTI, first.jti)
    }
}
