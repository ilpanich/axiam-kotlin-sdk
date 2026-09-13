package io.axiam.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.RevocationFeed
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger

/**
 * CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
 * AXIAM threats T-39 and T-143).
 *
 * Two things are under test and they are separable: what the poller does with a
 * document, and what attaching one changes about a verification. The second is
 * the shorter half and the one that matters — the feed may only ever turn an
 * accept into a reject, and only for a token that names a session.
 *
 * Every negative is paired with its I4 twin: a client built as it was before
 * 1.44, a token with no session behind it, a feed that cannot be read. A guard
 * that started denying requests because an advisory document went missing would
 * be a worse failure than the fifteen-minute window §10.2 records, and those
 * twins are what rule it out.
 */
class RevocationFeedTest {

    private val revokedSid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
    private val liveSid = "11111111-2222-3333-4444-555555555555"

    private lateinit var server: MockWebServer
    private lateinit var signingKey: OctetKeyPair

    /** The feed's answer; set per test before any call. */
    private var feedStatus = 200
    private var feedBody = ""
    private val feedFetches = AtomicInteger()

    @BeforeEach
    fun setUp() {
        signingKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("k1").generate()
        feedStatus = 200
        feedBody = document(entries = emptyList())
        feedFetches.set(0)
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path ?: ""
                return when {
                    path.startsWith(RevocationFeed.FEED_PATH) -> {
                        feedFetches.incrementAndGet()
                        MockResponse().setResponseCode(feedStatus)
                            .addHeader("Content-Type", "application/json").setBody(feedBody)
                    }
                    path.startsWith("/oauth2/jwks") ->
                        MockResponse().setResponseCode(200)
                            .addHeader("Content-Type", "application/json")
                            .setBody(JWKSet(signingKey.toPublicJWK()).toString())
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    // ---- fixtures -------------------------------------------------------

    private fun document(alg: String = "SHA-256", entries: List<String>) =
        """{"alg":"$alg","revoked":[${entries.joinToString(",") { "\"$it\"" }}]}"""

    private fun feed(pollSeconds: Long = RevocationFeed.DEFAULT_POLL_INTERVAL_SECONDS) =
        RevocationFeed(OkHttpClient(), server.url("/").toString(), pollSeconds)

    private fun tokenWithSid(sid: String?): String {
        val b = JWTClaimsSet.Builder()
            .subject("user-1")
            .claim("tenant_id", TestSupport.TENANT_ID)
            .claim("scope", "documents:read")
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
        // Omitted entirely when null, so "a token with no session behind it" —
        // client credentials, an RPT, a token exchange — stays expressible.
        if (sid != null) b.claim("sid", sid)
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), b.build())
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    private fun client(withFeed: RevocationFeed? = null): AxiamClient =
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .apply { if (withFeed != null) revocationFeed(withFeed) }
            .build()

    // ---- the entry format ------------------------------------------------

    /**
     * The server computes this entry in `axiam_core::revocation_feed` and every
     * SDK recomputes it from a `sid` claim. A pinned vector is the only thing
     * keeping twelve implementations of one wire format in agreement; a round
     * trip through this class's own hash would agree with itself while agreeing
     * with nobody.
     */
    @Test
    fun `the feed entry matches the pinned vector`() {
        assertEquals(
            "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ",
            RevocationFeed.entryFor(revokedSid),
        )
    }

    /**
     * Hashed over the claim's exact string. An implementation that parsed the
     * sid as a UUID and re-rendered it would agree on canonical input and
     * disagree the moment a server issued anything else.
     */
    @Test
    fun `the entry hashes the string, not a parsed UUID`() {
        assertTrue(
            RevocationFeed.entryFor(revokedSid) !=
                RevocationFeed.entryFor(revokedSid.uppercase()),
        )
    }

    // ---- the poller ------------------------------------------------------

    @Test
    fun `a listed session is reported revoked and an unlisted one is not`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor(revokedSid)))
        val f = feed()

        assertTrue(f.isRevoked(revokedSid))
        assertFalse(f.isRevoked(liveSid))
    }

    /**
     * §10.4 rule 3 — every way the feed can be unusable behaves exactly as no
     * feed at all. The failure this forecloses is the opposite: a guard that
     * starts denying every request because a document it treats as advisory
     * became unreachable.
     */
    @Test
    fun `an unusable feed denies nothing`() {
        val listed = RevocationFeed.entryFor(revokedSid)
        val cases = listOf(
            Triple("a 404 — the deployment does not publish the feed", 404, document(entries = listOf(listed))),
            Triple("a 500 — the feed is broken", 500, document(entries = listOf(listed))),
            Triple("a body that is not JSON", 200, "not json"),
            Triple("a document that is not an object", 200, "[]"),
            Triple("an alg this build does not know", 200, document("SHA-512", listOf(listed))),
            Triple("a revoked member that is not an array", 200, """{"alg":"SHA-256","revoked":"x"}"""),
            Triple("no revoked member at all", 200, """{"alg":"SHA-256"}"""),
        )

        for ((name, status, body) in cases) {
            feedStatus = status
            feedBody = body
            assertFalse(feed().isRevoked(revokedSid), name)
        }
    }

    /**
     * An over-sized document drops the WHOLE set rather than truncating it. A
     * truncated set is a guard that admits some revoked sessions and reports
     * none, which is worse than one that admits all of them and says so.
     */
    @Test
    fun `an oversized document drops everything rather than truncating`() {
        val entries = buildList {
            add(RevocationFeed.entryFor(revokedSid))
            repeat(RevocationFeed.MAX_ENTRIES) { add("e$it") }
        }
        feedBody = document(entries = entries)

        assertFalse(feed().isRevoked(revokedSid))
    }

    /**
     * A blip must not un-revoke a session the guard already knows about: the
     * previous set stays in place across a failed refresh.
     */
    @Test
    fun `a failed poll keeps the previous set`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor(revokedSid)))
        val f = feed()
        assertTrue(f.isRevoked(revokedSid))

        feedStatus = 500
        f.refresh()

        assertTrue(f.isRevoked(revokedSid))
    }

    // ---- §10.4 rule 2 — the poll interval --------------------------------

    /**
     * The request path never waits on a fetch it does not need: inside one
     * interval, repeated checks answer from the cache.
     */
    @Test
    fun `repeated checks inside one interval do not refetch`() {
        val f = feed()
        repeat(5) { f.isRevoked(liveSid) }

        assertEquals(1, feedFetches.get())
    }

    /**
     * Once the interval has elapsed, the next check refetches. Asserted through
     * the injected clock rather than by sleeping — a test that really waited
     * fifteen seconds is a test nobody runs.
     */
    @Test
    fun `an elapsed interval refetches`() {
        val f = feed()
        var nanos = 1_000_000_000L
        f.nanoTime = { nanos }

        f.isRevoked(liveSid)
        nanos += (RevocationFeed.DEFAULT_POLL_INTERVAL_SECONDS + 1) * 1_000_000_000L
        f.isRevoked(liveSid)

        assertEquals(2, feedFetches.get())
    }

    /**
     * A feed that is down must not be retried on every request, which would put
     * the request path back on the network — the cost §10.4 exists to avoid.
     * The interval is measured from the last *attempt*, not the last success.
     */
    @Test
    fun `a down feed is not retried on every request`() {
        feedStatus = 500
        val f = feed()
        repeat(5) { f.isRevoked(liveSid) }

        assertEquals(1, feedFetches.get())
    }

    /**
     * The floor is applied by clamping, not by refusing: a caller who asks for
     * something faster gets the fastest thing on offer.
     */
    @Test
    fun `a shorter interval is clamped rather than refused`() {
        assertEquals(RevocationFeed.MIN_POLL_INTERVAL_SECONDS, feed(pollSeconds = 1).pollIntervalSeconds)
        assertEquals(120L, feed(pollSeconds = 120).pollIntervalSeconds)
    }

    @Test
    fun `the feed path is appended to the base URL`() {
        assertEquals(
            server.url("/").toString().trimEnd('/') + "/oauth2/revocations",
            feed().feedUrl,
        )
    }

    /** A token with no session behind it asks the feed no question at all. */
    @Test
    fun `a blank sid is never matched and triggers no fetch`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor("")))
        val f = feed()

        assertFalse(f.isRevoked(""))
        assertFalse(f.isRevoked(null))
        assertEquals(0, feedFetches.get())
    }

    // ---- what attaching one changes about a verification ------------------

    @Test
    fun `a revoked session is rejected`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor(revokedSid)))
        client(feed()).use { c ->
            val refused = assertThrows(AuthError::class.java) {
                c.verifySession(tokenWithSid(revokedSid))
            }
            // Its own report: "the session is gone" is not "this credential was
            // never valid", and a guard that conflated them would tell a
            // logged-out user their token had expired.
            assertTrue(refused.message!!.contains("revoked"), refused.message)
            assertFalse(refused.message!!.contains("expired"), refused.message)
        }
    }

    @Test
    fun `a session the feed does not list is admitted`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor(revokedSid)))
        client(feed()).use { c ->
            assertEquals("user-1", c.verifySession(tokenWithSid(liveSid)).userId)
        }
    }

    /**
     * The feed can only ever turn an accept into a reject: a token that fails
     * §10.1 still fails for its own reason, so a feed listing nothing can never
     * rescue an expired token.
     */
    @Test
    fun `the feed never turns a reject into an accept`() {
        client(feed()).use { c ->
            val expired = JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", TestSupport.TENANT_ID)
                .claim("sid", liveSid)
                .expirationTime(Date(System.currentTimeMillis() - 3_600_000))
                .build()
            val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), expired)
            jwt.sign(Ed25519Signer(signingKey))

            assertThrows(AuthError::class.java) { c.verifySession(jwt.serialize()) }
        }
    }

    // ---- I4 — configured as today, behaves as today ----------------------

    /**
     * The default. A client built as it was before contract 1.44 accepts
     * exactly what it accepted then, including a token whose session a feed
     * WOULD have listed — the §10.2 posture this narrows rather than replaces.
     * And it never polls.
     */
    @Test
    fun `no feed attached is unchanged behaviour`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor(revokedSid)))
        client().use { c ->
            assertEquals("user-1", c.verifySession(tokenWithSid(revokedSid)).userId)
        }
        assertEquals(0, feedFetches.get())
    }

    /**
     * A token with no session behind it is never matched against the feed, even
     * when the document happens to list the hash of the empty string. Hashing
     * `jti` instead would match nothing while looking like it worked.
     */
    @Test
    fun `a token with no session is never matched`() {
        feedBody = document(entries = listOf(RevocationFeed.entryFor("")))
        client(feed()).use { c ->
            assertEquals("user-1", c.verifySession(tokenWithSid(null)).userId)
        }
        // Not even a fetch: a sid-less token asks the feed no question at all.
        assertEquals(0, feedFetches.get())
    }

    /**
     * §10.4 rule 3 at the guard, not just at the poller: a feed that cannot be
     * read denies nothing. This is what keeps the feature safe to turn on — the
     * alternative is a guard that stops serving when an advisory document goes
     * missing.
     */
    @Test
    fun `an unreadable feed denies nothing at the guard`() {
        feedStatus = 500
        client(feed()).use { c ->
            assertEquals("user-1", c.verifySession(tokenWithSid(revokedSid)).userId)
        }
    }
}
