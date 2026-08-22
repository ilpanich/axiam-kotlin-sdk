package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.webauthn.WebauthnFailure
import io.axiam.sdk.webauthn.WebauthnWorkspace
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * CONTRACT.md §24 — the WebAuthn relying-party layer and the §24.6a JSON
 * bridge, which is what makes this JVM-only artifact fully usable from an
 * Android app.
 *
 * Two assertions are worth reading twice:
 *
 * - `the 503 is not retried` asserts on the **request count**, not the
 *   exception type, because §24.4 rule 2 regresses the moment someone tidies a
 *   retry predicate — and a type assertion would still pass.
 * - `the state token is never parsed` hands the SDK a state token that is not a
 *   JWT at all. If anything decoded one, this is where it would fail.
 */
class WebauthnTest {

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
        const val STATE_TOKEN = "state-token-fixture-value-do-not-log"
        const val CHALLENGE_TOKEN = "challenge-token-fixture-do-not-log"
        const val ACCESS_TOKEN = "access-token-fixture-do-not-log"
        const val REFRESH_TOKEN = "refresh-token-fixture-do-not-log"

        /**
         * Deliberately "unusual but valid": every optional field populated, so
         * the pass-through assertion has something to catch an over-eager
         * implementation dropping. A minimal fixture would prove nothing.
         */
        val CREATION_CHALLENGE = """
            {"publicKey":{
              "challenge":"Y2hhbGxlbmdlLWJ5dGVz",
              "rp":{"id":"axiam.test","name":"AXIAM Test"},
              "user":{"id":"dXNlci1oYW5kbGU","name":"alice","displayName":"Alice"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},
                                  {"type":"public-key","alg":-257}],
              "timeout":60000,
              "excludeCredentials":[{"id":"ZXhpc3Rpbmc","type":"public-key","transports":["usb","nfc"]}],
              "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,
                                        "userVerification":"required"},
              "attestation":"direct",
              "extensions":{"credProps":true}
            }}
        """.trimIndent()

        val MINIMAL_CREATION_CHALLENGE = """
            {"publicKey":{
              "challenge":"bWluaW1hbA",
              "rp":{"name":"AXIAM Test"},
              "user":{"id":"dQ","name":"bob","displayName":"Bob"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7}]
            }}
        """.trimIndent()

        val DISCOVERABLE_CHALLENGE = """
            {"publicKey":{"challenge":"ZGlzY292ZXJhYmxl","rpId":"axiam.test",
             "allowCredentials":[],"userVerification":"required"}}
        """.trimIndent()

        /** Carries an unknown key the SDK must forward rather than strip. */
        val REGISTRATION_RESPONSE = """
            {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
             "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                         "attestationObject":"o2NmbXRkbm9uZQ",
                         "transports":["internal"],
                         "vendorSpecific":"must-survive"},
             "type":"public-key","clientExtensionResults":{"credProps":{"rk":true}}}
        """.trimIndent()

        val AUTHENTICATION_RESPONSE = """
            {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
             "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                         "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                         "userHandle":"dXNlci1oYW5kbGU"},
             "type":"public-key","clientExtensionResults":{}}
        """.trimIndent()
    }

    private fun challengeResponse(challenge: String) =
        TestSupport.json(200, """{"challenge":$challenge,"state_token":"$STATE_TOKEN"}""")

    private fun credentialResponse() = TestSupport.json(
        201,
        """{"id":"${UUID.randomUUID()}","credential_id":"bmV3LWNyZWQ","name":"Alice's laptop",
            "credential_type":"passkey","created_at":"2026-08-22T10:00:00Z"}""",
    )

    /**
     * The token body a completed passkey sign-in returns, alongside the cookie
     * triple contract 1.28 added. Before that fix the client had no session at
     * all after a ceremony the server had already accepted.
     */
    private fun webauthnLoginResponse() = MockResponse()
        .setResponseCode(200)
        .addHeader("Content-Type", "application/json")
        .addHeader("Set-Cookie", "axiam_access=${TestSupport.fakeJwt()}; Path=/")
        .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
        .addHeader("X-CSRF-Token", "csrf-abc")
        .setBody(
            """{"access_token":"$ACCESS_TOKEN","refresh_token":"$REFRESH_TOKEN",
                "session_id":"${UUID.randomUUID()}","expires_in":900}""",
        )

    /** Seed the access cookie — what the SDK reads as "signed in" (§24.1). */
    private suspend fun signIn(client: AxiamClient) {
        server.enqueue(TestSupport.loginOkResponse())
        client.login("alice@example.com", "pw")
        server.takeRequest()
    }

    // -----------------------------------------------------------------------
    // §24.0 — options and responses pass through untouched
    // -----------------------------------------------------------------------

    @Test
    fun `options pass through structurally unchanged`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(challengeResponse(CREATION_CHALLENGE))

            val challenge = client.webauthnRegisterStart()

            // Structural equality, not a spot-check of three fields: the
            // failure mode this guards is an SDK that quietly drops the one
            // option it did not recognise.
            assertEquals(Json.parseToJsonElement(CREATION_CHALLENGE), challenge.challenge)
        }
    }

    @Test
    fun `no field the server omitted is synthesized`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(challengeResponse(MINIMAL_CREATION_CHALLENGE))

            val options = client.webauthnRegisterStart().challenge["publicKey"]!!.jsonObject

            assertNull(options["authenticatorSelection"], "the SDK must not invent a selection")
            assertNull(options["timeout"], "the SDK must not invent a timeout")
            assertNull(options["attestation"], "the SDK must not invent a conveyance")
        }
    }

    @Test
    fun `the authenticator response reaches the wire byte for byte`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(credentialResponse())

            client.webauthnRegisterFinish(Sensitive.of(STATE_TOKEN), "Alice's laptop", REGISTRATION_RESPONSE)

            val body = server.takeRequest().body.readUtf8()
            // The literal substring, not a parsed comparison: this is the
            // assertion that catches a re-encode (§24.0), which a structural
            // comparison would happily pass.
            assertTrue(
                body.contains(REGISTRATION_RESPONSE),
                "the response JSON was re-encoded on the way to the wire: $body",
            )
            assertTrue(body.contains("must-survive"), "an unknown field was dropped")
        }
    }

    // -----------------------------------------------------------------------
    // §24.1 — register requires a session
    // -----------------------------------------------------------------------

    @Test
    fun `register start without a session makes zero wire calls`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) { runBlocking { client.webauthnRegisterStart() } }
            assertThrows(AuthError::class.java) {
                runBlocking {
                    client.webauthnRegisterFinish(Sensitive.of(STATE_TOKEN), "k", REGISTRATION_RESPONSE)
                }
            }
            // Asserted on the transport, not the exception type: §24.1 requires
            // the refusal to be client-side.
            assertEquals(0, server.requestCount)
        }
    }

    @Test
    fun `register finish returns the credential`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(credentialResponse())

            val credential = client.webauthnRegisterFinish(
                Sensitive.of(STATE_TOKEN), "Alice's laptop", REGISTRATION_RESPONSE,
            )

            assertEquals("bmV3LWNyZWQ", credential.credentialId)
            assertEquals("passkey", credential.credentialType)
            assertNull(credential.lastUsedAt, "a never-used credential has no lastUsedAt")
        }
    }

    // -----------------------------------------------------------------------
    // §24.2 — two ceremonies, not one with a flag
    // -----------------------------------------------------------------------

    @Test
    fun `the second-factor ceremony sends the challenge token`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE))

            client.webauthnAuthenticateStart(Sensitive.of(CHALLENGE_TOKEN))

            val request = server.takeRequest()
            assertEquals("/api/v1/auth/webauthn/authenticate/start", request.path)
            val body = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
            assertEquals(CHALLENGE_TOKEN, body["challenge_token"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `the discoverable ceremony sends a workspace and no challenge token`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE))

            client.webauthnDiscoverableStart()

            val request = server.takeRequest()
            assertEquals("/api/v1/auth/webauthn/authenticate/discoverable/start", request.path)
            val body = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
            assertNull(
                body["challenge_token"],
                "merging the two ceremonies reproduces a bug the server already fixed (§24.2)",
            )
            // §24.1: unlike the /oauth2 endpoints this one accepts slugs, and
            // the SDK fills the workspace from its own configuration.
            assertEquals(TestSupport.ORG_ID.toString(), body["org_id"]!!.jsonPrimitive.content)
            assertEquals(TestSupport.TENANT_ID, body["tenant_slug"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `an explicit workspace overrides the client configuration`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE))

            client.webauthnDiscoverableStart(
                WebauthnWorkspace(orgSlug = "other-org", tenantId = TestSupport.TENANT_UUID),
            )

            val body = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
            assertEquals("other-org", body["org_slug"]!!.jsonPrimitive.content)
            assertEquals(TestSupport.TENANT_UUID.toString(), body["tenant_id"]!!.jsonPrimitive.content)
            assertNull(body["tenant_slug"], "a resolved tenant_id makes tenant_slug ambiguous")
        }
    }

    @Test
    fun `a client with no organization cannot start a discoverable ceremony`() = runBlocking {
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID).build().use { client ->
            assertThrows(AuthError::class.java) { runBlocking { client.webauthnDiscoverableStart() } }
            assertEquals(0, server.requestCount)
        }
    }

    // -----------------------------------------------------------------------
    // §24.3 — credential adoption
    // -----------------------------------------------------------------------

    @Test
    fun `a completed ceremony leaves the client authenticated`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            server.enqueue(webauthnLoginResponse())

            val result = client.webauthnDiscoverableFinish(
                Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE,
            )

            assertEquals(900L, result.expiresIn)
            // The client's OWN authenticated state, not just that a token came
            // back (§24.3 rule 1): verifySession works off the adopted cookie.
            server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
            assertTrue(client.can("read", "documents/1"))
        }
    }

    @Test
    fun `a memoized decision is dropped by a ceremony`() = runBlocking {
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .decisionMemoTtl(java.time.Duration.ofMinutes(5))
            .build().use { client ->
                signIn(client)
                server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
                assertTrue(client.can("read", "documents/1"))
                server.takeRequest()

                server.enqueue(webauthnLoginResponse())
                client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE)
                server.takeRequest()

                // §24.3 rule 4: memo entries are keyed by subject, and the
                // ceremony changed it — so this must hit the wire again.
                server.enqueue(TestSupport.json(200, """{"allowed":false}"""))
                assertFalse(client.can("read", "documents/1"))
            }
    }

    // -----------------------------------------------------------------------
    // §24.4 — the two error rows that are not the §2 defaults
    // -----------------------------------------------------------------------

    @Test
    fun `the 503 from register start is not retried`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            val before = server.requestCount
            server.enqueue(TestSupport.json(503, """{"message":"FIDO metadata unavailable"}"""))

            assertThrows(RuntimeException::class.java) { runBlocking { client.webauthnRegisterStart() } }

            // §24.4 rule 2, asserted on the request count: a 503 here is a
            // server CONFIGURATION state, retrying changes nothing, and this
            // regresses silently the moment the retry predicate is tidied.
            assertEquals(1, server.requestCount - before, "the 503 must not be retried")
        }
    }

    @Test
    fun `the 403 attestation policy message survives`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(
                TestSupport.json(403, """{"message":"this security key is not FIDO certified"}"""),
            )

            val error = assertThrows(AuthzError::class.java) {
                runBlocking {
                    client.webauthnRegisterFinish(Sensitive.of(STATE_TOKEN), "key", REGISTRATION_RESPONSE)
                }
            }
            // §24.4 rule 1: the policy message is the only way the person
            // holding the key learns a different one would work.
            assertTrue(
                error.message!!.contains("FIDO certified"),
                "the attestation policy message was lost: ${error.message}",
            )
        }
    }

    @Test
    fun `a failed assertion is an authentication error`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            server.enqueue(TestSupport.json(401, """{"message":"assertion failed"}"""))
            assertThrows(AuthError::class.java) {
                runBlocking {
                    client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE)
                }
            }
        }
        Unit
    }

    // -----------------------------------------------------------------------
    // §24.5 — opaque and sensitive
    // -----------------------------------------------------------------------

    @Test
    fun `the state token is never parsed`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            // Not a JWT, not base64, not three dot-separated parts. If anything
            // decoded it, this round trip would not survive.
            val nonsense = "-----definitely not a jwt-----"
            server.enqueue(
                TestSupport.json(
                    200,
                    """{"challenge":$DISCOVERABLE_CHALLENGE,"state_token":"$nonsense"}""",
                ),
            )
            val challenge = client.webauthnDiscoverableStart()
            server.takeRequest()
            assertEquals(nonsense, challenge.stateToken.expose())

            server.enqueue(webauthnLoginResponse())
            client.webauthnDiscoverableFinish(challenge.stateToken, AUTHENTICATION_RESPONSE)

            val body = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
            assertEquals(nonsense, body["state_token"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `no fixture token appears in a rendered value`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(challengeResponse(CREATION_CHALLENGE))
            val challenge = client.webauthnRegisterStart()

            assertEquals("[SENSITIVE]", challenge.stateToken.toString())
            assertFalse(challenge.toString().contains(STATE_TOKEN))

            server.enqueue(webauthnLoginResponse())
            val login = client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE)
            assertFalse(login.toString().contains(ACCESS_TOKEN))
            assertFalse(login.toString().contains(REFRESH_TOKEN))
        }
    }

    // -----------------------------------------------------------------------
    // §24.6a — the JSON bridge
    // -----------------------------------------------------------------------

    @Test
    fun `requestJson round-trips and drops the publicKey wrapper`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            server.enqueue(challengeResponse(CREATION_CHALLENGE))

            val challenge = client.webauthnRegisterStart()
            val parsed = Json.parseToJsonElement(challenge.requestJson).jsonObject

            // The inner options object: the publicKey wrapper belongs to the
            // DOM's CredentialCreationOptions, and the platform JSON APIs — the
            // very ones this accessor exists for — do not want it.
            assertNull(parsed["publicKey"])
            assertEquals(
                Json.parseToJsonElement(CREATION_CHALLENGE).jsonObject["publicKey"],
                parsed,
            )
            assertEquals("direct", parsed["attestation"]!!.jsonPrimitive.content)
            assertEquals(60000, parsed["timeout"]!!.jsonPrimitive.content.toInt())
            assertTrue(parsed["excludeCredentials"].toString().contains("ZXhpc3Rpbmc"))
        }
    }

    @Test
    fun `a response that is not a JSON object is refused before the wire`() = runBlocking {
        TestSupport.clientFor(server).use { client ->
            signIn(client)
            val before = server.requestCount

            assertThrows(AuthError::class.java) {
                runBlocking {
                    client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), "not json at all")
                }
            }
            assertThrows(AuthError::class.java) {
                runBlocking {
                    client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), "[\"an\",\"array\"]")
                }
            }
            assertEquals(before, server.requestCount, "the SDK must not POST a body it cannot verify")
        }
    }

    @Test
    fun `the error classification is reachable without a linked API`() {
        // §24.6b rule 5, required of this SDK too: an Android app catching a
        // CreateCredentialException has the same five outcomes.
        assertEquals(WebauthnFailure.CANCELLED, WebauthnFailure.classify("NotAllowedError"))
        assertEquals(WebauthnFailure.ALREADY_REGISTERED, WebauthnFailure.classify("InvalidStateError"))
        assertEquals(WebauthnFailure.TIMEOUT, WebauthnFailure.classify("AbortError"))
        assertEquals(WebauthnFailure.UNSUPPORTED, WebauthnFailure.classify("NotSupportedError"))
        assertEquals(WebauthnFailure.UNSUPPORTED, WebauthnFailure.classify("SecurityError"))
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify("SomethingElseError"))
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify(null as String?))

        // ASAuthorizationError.canceled spells it with one L.
        assertEquals(WebauthnFailure.CANCELLED, WebauthnFailure.classify("canceled"))
    }

    @Test
    fun `a caught platform exception classifies without linking androidx`() {
        // What an Android caller actually holds: an exception whose DOM error
        // name is only in its message. Reaching it any other way would mean
        // this artifact linking androidx.credentials.
        val domException = IllegalStateException(
            "androidx.credentials.exceptions.publickeycredential." +
                "CreatePublicKeyCredentialDomException: NotAllowedError: the request was aborted",
        )
        assertEquals(WebauthnFailure.CANCELLED, WebauthnFailure.classify(domException))

        assertEquals(
            WebauthnFailure.ALREADY_REGISTERED,
            WebauthnFailure.classify(RuntimeException("InvalidStateError: already registered")),
        )
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify(RuntimeException("who knows")))
        // Never throws and never rethrows — it is called from a catch block.
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify(null as Throwable?))
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify(RuntimeException()))
    }

    @Test
    fun `already registered is distinguishable from cancelled`() {
        assertNotEquals(
            WebauthnFailure.classify("InvalidStateError"),
            WebauthnFailure.classify("NotAllowedError"),
        )
        // The only classification whose remedy is "use a different device".
        assertTrue(WebauthnFailure.ALREADY_REGISTERED.message.contains("different device"))
        // And the one that must not accuse the user: it also covers a silent
        // timeout, which the spec refuses to distinguish.
        assertTrue(WebauthnFailure.CANCELLED.message.contains("cancelled or timed out"))
    }
}
