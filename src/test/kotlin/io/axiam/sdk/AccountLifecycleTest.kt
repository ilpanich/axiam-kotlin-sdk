package io.axiam.sdk

import io.axiam.sdk.account.PasswordResetConfirmation
import io.axiam.sdk.account.PasswordResetRequest
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
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
 * CONTRACT.md §25 — account lifecycle and MFA enrolment.
 *
 * The two assertions worth reading twice are the §25.4 pair:
 * `requestPasswordReset says nothing about whether the account exists` pins the
 * account-enumeration guarantee to the SDK's *surface* rather than to the
 * server's behaviour, and `the reset context token travels as a query
 * parameter` exists because building that URL by concatenation percent-escapes
 * the `?` into the path — a bug that produces a 404 reading exactly like an
 * expired token.
 */
class AccountLifecycleTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private companion object {
        const val SETUP_TOKEN = "setup-token-fixture-do-not-log"
        const val RESET_TOKEN = "reset-token-fixture-do-not-log"
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }

    private fun enrollmentResponse() = TestSupport.json(
        200,
        """{"secret_base32":"$SECRET","totp_uri":"otpauth://totp/AXIAM:alice?secret=$SECRET&issuer=AXIAM"}""",
    )

    private fun body() = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject

    // -----------------------------------------------------------------------
    // §25.2 rule 1 — login gains a third outcome
    // -----------------------------------------------------------------------

    @Test
    fun `login answers 403 mfa_setup_required as the third outcome`() = runBlocking {
        server.enqueue(
            TestSupport.json(403, """{"mfa_setup_required":true,"setup_token":"$SETUP_TOKEN"}"""),
        )
        TestSupport.clientFor(server).use { client ->
            val result = client.login("alice@example.com", "pw")

            assertTrue(
                result.mfaSetupRequired,
                "a tenant that requires MFA on an account without it is not a failure",
            )
            assertFalse(result.mfaRequired, "the account has no factor to challenge yet")
            assertNull(result.user, "there is no session, so there is no user")
            assertNotNull(result.setupToken)
            assertEquals(SETUP_TOKEN, result.setupToken!!.expose())
            assertEquals("[SENSITIVE]", result.setupToken.toString())
        }
    }

    @Test
    fun `an ordinary 403 is still a failure`() = runBlocking {
        // §25.2 rule 1 keys the third outcome on the error BODY, never on the
        // status alone: a plain 403 must keep throwing, and must keep its
        // §2 authorization mapping.
        server.enqueue(
            TestSupport.json(403, """{"error":"authorization_denied","message":"tenant suspended"}"""),
        )
        TestSupport.clientFor(server).use { client ->
            assertThrows(RuntimeException::class.java) {
                runBlocking { client.login("alice@example.com", "pw") }
            }
        }
        Unit
    }

    @Test
    fun `a non-JSON 403 body does not become a parse failure`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(403).setBody("forbidden"))
        TestSupport.clientFor(server).use { client ->
            val error = assertThrows(RuntimeException::class.java) {
                runBlocking { client.login("alice@example.com", "pw") }
            }
            assertTrue(
                error is io.axiam.sdk.errors.AuthzError,
                "peeking the body for a setup token must leave the §2 mapping intact, got $error",
            )
        }
    }

    @Test
    fun `the three outcomes are mutually exclusive`() {
        // Additive, so every pre-1.28 construction still compiles and reads
        // false for the new flag.
        val challenge = LoginResult(mfaRequired = true, challengeToken = Sensitive.of("chal"))
        assertTrue(challenge.mfaRequired)
        assertFalse(challenge.mfaSetupRequired)
        assertNull(challenge.setupToken)
    }

    // -----------------------------------------------------------------------
    // §25.1 — voluntary enrolment
    // -----------------------------------------------------------------------

    @Test
    fun `mfaEnroll returns the secret and its uri`() = runBlocking {
        server.enqueue(enrollmentResponse())
        TestSupport.clientFor(server).use { client ->
            val enrollment = client.mfaEnroll()

            assertEquals(SECRET, enrollment.secretBase32.expose())
            assertTrue(enrollment.totpUri.expose().startsWith("otpauth://totp/"))
        }
        assertEquals("/api/v1/auth/mfa/enroll", server.takeRequest().path)
    }

    @Test
    fun `both halves of an enrolment are sensitive`() = runBlocking {
        server.enqueue(enrollmentResponse())
        TestSupport.clientFor(server).use { client ->
            val enrollment = client.mfaEnroll()

            // §25.3: the otpauth URI CONTAINS the secret. Wrapping only the
            // bare secret and printing the URI leaks the same bytes — this is
            // the mistake the rule exists to name.
            assertFalse(enrollment.secretBase32.toString().contains(SECRET))
            assertFalse(enrollment.totpUri.toString().contains(SECRET))
            assertFalse(enrollment.toString().contains(SECRET))
        }
    }

    @Test
    fun `mfaConfirm reports whether the factor is live`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"mfa_enabled":true}"""))
        TestSupport.clientFor(server).use { client ->
            assertTrue(client.mfaConfirm("123456"))
        }
        val request = server.takeRequest()
        assertEquals("/api/v1/auth/mfa/confirm", request.path)
        assertEquals(
            "123456",
            Json.parseToJsonElement(request.body.readUtf8()).jsonObject["totp_code"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `a wrong code is an authentication error`() = runBlocking {
        server.enqueue(TestSupport.json(401, """{"message":"invalid code"}"""))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { runBlocking { client.mfaConfirm("000000") } }
        }
        Unit
    }

    @Test
    fun `enrolment does not clear the decision memo`() = runBlocking {
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .decisionMemoTtl(java.time.Duration.ofMinutes(5))
            .build().use { client ->
                server.enqueue(TestSupport.loginOkResponse())
                client.login("alice@example.com", "pw")
                server.takeRequest()

                server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
                assertTrue(client.can("read", "documents/1"))
                server.takeRequest()

                server.enqueue(enrollmentResponse())
                client.mfaEnroll()
                server.takeRequest()

                // §25.2 rule 3: the subject has not changed, and discarding a
                // warm memo on an unrelated profile action costs a round trip
                // on every check that follows. Nothing is enqueued here — if
                // the memo had been cleared, this call would hang on an empty
                // dispatcher queue rather than answer from cache.
                assertTrue(client.can("read", "documents/1"))
                assertEquals(0, server.requestCount - 3)
            }
    }

    // -----------------------------------------------------------------------
    // §25.1 / §25.2 rule 2 — forced enrolment completes a login
    // -----------------------------------------------------------------------

    @Test
    fun `mfaSetupEnroll authenticates with the setup token alone`() = runBlocking {
        server.enqueue(enrollmentResponse())
        TestSupport.clientFor(server).use { client ->
            client.mfaSetupEnroll(Sensitive.of(SETUP_TOKEN))
        }
        val request = server.takeRequest()
        assertEquals("/api/v1/auth/mfa/setup/enroll", request.path)
        // There is no session yet — the setup token IS the credential.
        assertEquals(
            SETUP_TOKEN,
            Json.parseToJsonElement(request.body.readUtf8()).jsonObject["setup_token"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `mfaSetupConfirm adopts the session like a login`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        TestSupport.clientFor(server).use { client ->
            val result = client.mfaSetupConfirm(Sensitive.of(SETUP_TOKEN), "123456")

            // §25.2 rule 2: this IS the completion of a login, so the
            // credentials it returns are adopted exactly as login() adopts
            // them — not handed back for the caller to install.
            assertFalse(result.mfaRequired)
            assertFalse(result.mfaSetupRequired)
            assertNotNull(result.user)
            assertEquals("user-1", result.user!!.userId)
        }
        assertEquals("/api/v1/auth/mfa/setup/confirm", server.takeRequest().path)
    }

    // -----------------------------------------------------------------------
    // §25.1 — email verification
    // -----------------------------------------------------------------------

    @Test
    fun `verifyEmail needs no session and carries the tenant in the body`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))
        TestSupport.clientFor(server).use { client ->
            client.verifyEmail(Sensitive.of("verify-token"), TestSupport.TENANT_UUID)
        }
        val request = server.takeRequest()
        assertEquals("/api/v1/auth/verify-email", request.path)
        val json = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        // Not ?tenant_id=: §12.1 rule 2's query convention is scoped to the
        // /oauth2 endpoints, and this is not one of those.
        assertEquals(TestSupport.TENANT_UUID.toString(), json["tenant_id"]!!.jsonPrimitive.content)
        assertEquals("verify-token", json["token"]!!.jsonPrimitive.content)
    }

    @Test
    fun `resendVerification accepts a 202`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(202))
        TestSupport.clientFor(server).use { client ->
            client.resendVerification("alice@example.com", TestSupport.TENANT_UUID)
        }
        assertEquals("/api/v1/auth/resend-verification", server.takeRequest().path)
    }

    @Test
    fun `an expired verification token is an error`() = runBlocking {
        server.enqueue(TestSupport.json(400, """{"message":"token expired"}"""))
        TestSupport.clientFor(server).use { client ->
            assertThrows(NetworkError::class.java) {
                runBlocking { client.verifyEmail(Sensitive.of("stale"), TestSupport.TENANT_UUID) }
            }
        }
        Unit
    }

    // -----------------------------------------------------------------------
    // §25.7 — the two resends are two operations
    // -----------------------------------------------------------------------

    /**
     * The authenticated resend carries no address, and hits its own path.
     *
     * The body assertion is the one that matters: a signature with no address
     * parameter proves nothing about what the SDK serializes, and an address on
     * this endpoint would let an authenticated session mail an arbitrary one.
     */
    @Test
    fun `resendOwnVerification sends no address`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"sent":true}"""))
        TestSupport.clientFor(server).use { client ->
            client.resendOwnVerification()
        }
        val request = server.takeRequest()
        assertEquals("/api/v1/users/me/resend-verification", request.path)
        val sent = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertTrue(sent.isEmpty(), "caller-supplied data went out: $sent")
    }

    /**
     * The two resends are distinct operations against distinct paths.
     *
     * An SDK that aliased one to the other would reintroduce the exact defect
     * §25.7 exists to describe, and every other test here would still pass — so
     * this asserts on the path each one actually reached.
     */
    @Test
    fun `the two resends reach different endpoints`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200))
        server.enqueue(TestSupport.json(200, """{"sent":true}"""))
        TestSupport.clientFor(server).use { client ->
            client.resendVerification("alice@example.com", TestSupport.TENANT_UUID)
            client.resendOwnVerification()
        }
        assertEquals("/api/v1/auth/resend-verification", server.takeRequest().path)
        assertEquals("/api/v1/users/me/resend-verification", server.takeRequest().path)
    }

    /**
     * A 409 surfaces, and is not retried through the public endpoint.
     *
     * The bug this operation exists to fix was a success return on a request
     * that achieved nothing, so "throws" is the assertion — and the request
     * count is what rules out the §25.7 rule 2 fallback, which would turn both
     * failures back into a normal return with an extra round-trip.
     */
    @Test
    fun `resendOwnVerification surfaces a 409 without falling back`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(409))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthzError::class.java) {
                runBlocking { client.resendOwnVerification() }
            }
        }
        assertEquals(
            1, server.requestCount,
            "a second request means a fallback to the enumeration-safe endpoint",
        )
        assertEquals("/api/v1/users/me/resend-verification", server.takeRequest().path)
    }

    /** A 429 surfaces too, as the §2 mapping of a rate limit. */
    @Test
    fun `resendOwnVerification surfaces the daily limit`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(429))
        TestSupport.clientFor(server).use { client ->
            assertThrows(NetworkError::class.java) {
                runBlocking { client.resendOwnVerification() }
            }
        }
        assertEquals(
            1, server.requestCount,
            "a second request means a fallback to the enumeration-safe endpoint",
        )
        assertEquals("/api/v1/users/me/resend-verification", server.takeRequest().path)
    }

    // -----------------------------------------------------------------------
    // §5.2 — organization-level principals
    // -----------------------------------------------------------------------

    /**
     * `organizationLevel` is carried through from the login response.
     *
     * It is what an application checks *before* offering a tenant switch: such
     * a principal changes the tenant it acts on with a header on the next
     * request, and an ordinary one cannot, so offering the switch to both turns
     * a distinction the server made into a 403 the user discovers.
     *
     * The absent case is the one that matters: a server older than contract
     * 1.31 omits the field, and `false` is the safe reading — the client then
     * offers no cross-tenant action rather than one that would fail.
     */
    @Test
    fun `login reports an organization-level principal`() = runBlocking {
        val cases = listOf(
            """{"id":"u1","organization_level":true}""" to true,
            """{"id":"u1","organization_level":false}""" to false,
            """{"id":"u1"}""" to false,
        )
        for ((userJson, expected) in cases) {
            val local = MockWebServer()
            local.start()
            try {
                local.enqueue(
                    TestSupport.loginOkResponse()
                        .setBody("""{"user":$userJson,"session_id":"s1","expires_in":900}"""),
                )
                TestSupport.clientFor(local).use { client ->
                    val result = client.login("alice@example.com", "correct horse")
                    assertEquals(
                        expected, result.organizationLevel,
                        "organizationLevel for user $userJson",
                    )
                }
            } finally {
                local.shutdown()
            }
        }
    }

    // -----------------------------------------------------------------------
    // §25.4 — password reset
    // -----------------------------------------------------------------------

    @Test
    fun `requestPasswordReset says nothing about whether the account exists`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            // Both an existing and an unknown address answer 202 with an empty
            // body, and the SDK returns Unit — there is no field, no boolean and
            // no exception for a caller to build an enumeration oracle out of.
            server.enqueue(MockResponse().setResponseCode(202))
            client.requestPasswordReset(PasswordResetRequest("alice@example.com"))

            server.enqueue(MockResponse().setResponseCode(202))
            client.requestPasswordReset(PasswordResetRequest("nobody@example.com"))

            assertEquals(2, server.requestCount)
        }
    }

    @Test
    fun `requestPasswordReset fills the workspace from the client`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(202))
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgSlug("globex")
            .build().use { client ->
                client.requestPasswordReset(PasswordResetRequest("alice@example.com"))
            }
        val json = body()
        assertEquals("globex", json["org_slug"]!!.jsonPrimitive.content)
        assertEquals(TestSupport.TENANT_ID, json["tenant_slug"]!!.jsonPrimitive.content)
    }

    @Test
    fun `an explicit workspace wins over the client configuration`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(202))
        TestSupport.clientFor(server).use { client ->
            client.requestPasswordReset(
                PasswordResetRequest(
                    "alice@example.com",
                    orgSlug = "other-org",
                    tenantId = TestSupport.TENANT_UUID,
                ),
            )
        }
        val json = body()
        assertEquals("other-org", json["org_slug"]!!.jsonPrimitive.content)
        assertEquals(TestSupport.TENANT_UUID.toString(), json["tenant_id"]!!.jsonPrimitive.content)
        assertNull(json["tenant_slug"], "a resolved tenant_id makes tenant_slug ambiguous")
    }

    @Test
    fun `the reset context token travels as a query parameter`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"opaque":null}"""))
        TestSupport.clientFor(server).use { client ->
            client.passwordResetContext(Sensitive.of(RESET_TOKEN))
        }
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        // Not percent-escaped into the path, which 404s in a way that reads
        // exactly like an expired token.
        assertEquals("/api/v1/auth/reset/context?token=$RESET_TOKEN", request.path)
    }

    @Test
    fun `a tenant without opaque reports no policy`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"opaque":null}"""))
        TestSupport.clientFor(server).use { client ->
            val context = client.passwordResetContext(Sensitive.of(RESET_TOKEN))
            assertNull(context.opaque, "no policy means the plaintext path is allowed")
        }
    }

    @Test
    fun `a tenant with opaque hands back the parameters untouched`() = runBlocking {
        val opaque = """{"mode":"required","cipher_suite":"ristretto255-sha512",
            "server_public_key":"c2VydmVyLXBr","vendorSpecific":"must-survive"}"""
        server.enqueue(TestSupport.json(200, """{"opaque":$opaque}"""))
        TestSupport.clientFor(server).use { client ->
            val context = client.passwordResetContext(Sensitive.of(RESET_TOKEN))

            // Structural equality: the SDK does not model, validate or
            // re-encode the §23 parameter block, it forwards it.
            assertEquals(Json.parseToJsonElement(opaque), context.opaque)
        }
    }

    @Test
    fun `unknown expired and consumed reset tokens all look alike`() = runBlocking {
        // §25.4 rule 3: the server refuses to distinguish these three, and the
        // SDK must not invent a distinction of its own.
        server.enqueue(TestSupport.json(404, "{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(NetworkError::class.java) {
                runBlocking { client.passwordResetContext(Sensitive.of(RESET_TOKEN)) }
            }
        }
        Unit
    }

    @Test
    fun `confirm sends the plaintext password when the tenant has no opaque`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))
        TestSupport.clientFor(server).use { client ->
            client.confirmPasswordReset(
                PasswordResetConfirmation(
                    Sensitive.of(RESET_TOKEN),
                    Sensitive.of("new-password"),
                    TestSupport.TENANT_UUID,
                ),
            )
        }
        val request = server.takeRequest()
        assertEquals("/api/v1/auth/reset/confirm", request.path)
        val json = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("new-password", json["new_password"]!!.jsonPrimitive.content)
        assertNull(json["opaque"])
    }

    @Test
    fun `confirm forwards the opaque registration record verbatim`() = runBlocking {
        val record = Json.parseToJsonElement(
            """{"registration_record":"cmVjb3Jk","export_key_hint":"aGludA"}""",
        ).jsonObject
        server.enqueue(MockResponse().setResponseCode(204))
        TestSupport.clientFor(server).use { client ->
            client.confirmPasswordReset(
                PasswordResetConfirmation(
                    Sensitive.of(RESET_TOKEN),
                    Sensitive.of("unused"),
                    TestSupport.TENANT_UUID,
                    opaque = record,
                ),
            )
        }
        assertEquals(record, body()["opaque"])
    }

    @Test
    fun `a rejected reset surfaces the error`() = runBlocking {
        server.enqueue(TestSupport.json(400, """{"message":"password does not meet policy"}"""))
        TestSupport.clientFor(server).use { client ->
            assertThrows(NetworkError::class.java) {
                runBlocking {
                    client.confirmPasswordReset(
                        PasswordResetConfirmation(
                            Sensitive.of(RESET_TOKEN),
                            Sensitive.of("x"),
                            TestSupport.TENANT_UUID,
                        ),
                    )
                }
            }
        }
        Unit
    }

    @Test
    fun `every operation refuses on a closed client`() = runBlocking {
        val client = TestSupport.clientFor(server)
        client.close()

        assertThrows(NetworkError::class.java) { runBlocking { client.mfaEnroll() } }
        assertThrows(NetworkError::class.java) { runBlocking { client.mfaConfirm("1") } }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.mfaSetupEnroll(Sensitive.of(SETUP_TOKEN)) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.mfaSetupConfirm(Sensitive.of(SETUP_TOKEN), "1") }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.verifyEmail(Sensitive.of("t"), TestSupport.TENANT_UUID) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.resendVerification("a@b.c", TestSupport.TENANT_UUID) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.requestPasswordReset(PasswordResetRequest("a@b.c")) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking { client.passwordResetContext(Sensitive.of(RESET_TOKEN)) }
        }
        assertThrows(NetworkError::class.java) {
            runBlocking {
                client.confirmPasswordReset(
                    PasswordResetConfirmation(
                        Sensitive.of(RESET_TOKEN),
                        Sensitive.of("pw"),
                        TestSupport.TENANT_UUID,
                    ),
                )
            }
        }
        assertEquals(0, server.requestCount, "a closed client makes no wire call")
    }
}
