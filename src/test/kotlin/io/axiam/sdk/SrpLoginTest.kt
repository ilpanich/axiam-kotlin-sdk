package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.AuthzError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.srp.Srp
import io.axiam.sdk.srp.SrpGroup
import io.axiam.sdk.srp.SrpKdfParams
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * `loginSrp` end-to-end against a fake server that performs REAL SRP arithmetic
 * (CONTRACT.md §23.7 rules 5, 7 and 8).
 *
 * A fake that echoed canned values would pass whatever the client computed.
 * This one holds a verifier, derives its own `S` from it and answers with the
 * `M2` that follows — so a client that gets `u`, `PAD()` or the identity wrong
 * fails here rather than in production.
 */
class SrpLoginTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    /** The server half of one enrolled account. */
    private class FakeSrpServer(private val group: SrpGroup) : Dispatcher() {

        // PBKDF2 at a low iteration count: the KDF's cost is not what these
        // tests measure, and Argon2id at production memory would dominate them.
        val kdf = SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000)
        val salt = ByteArray(32) { 0xa3.toByte() }
        private val verifier: BigInteger

        private var bPriv: BigInteger = BigInteger.ZERO
        private var bPub: BigInteger = BigInteger.ZERO
        private var aPub: BigInteger = BigInteger.ZERO

        var corruptServerProof = false
        var mfaRequired = false

        /** When set, answered on the first challenge so the client restarts. */
        var namedGroup: SrpGroup? = null

        val bodies = mutableListOf<String>()

        init {
            val x = Srp.deriveX(IDENTITY, PASSWORD.toCharArray(), salt, kdf)
            verifier = group.generator.modPow(BigInteger(1, x).mod(group.modulus), group.modulus)
        }

        override fun dispatch(request: RecordedRequest): MockResponse {
            val body = request.body.readUtf8()
            bodies += body
            val path = request.path ?: ""
            return when {
                path.endsWith("/auth/srp/challenge") -> challenge(body)
                path.endsWith("/auth/srp/verify") -> verify(body)
                else -> MockResponse().setResponseCode(404)
            }
        }

        private fun challenge(body: String): MockResponse {
            val parsed = Json.parseToJsonElement(body).jsonObject
            check(parsed["password"] == null) { "the challenge request must not carry a password field" }
            aPub = BigInteger(1, Srp.fromHex(parsed["client_public"]!!.jsonPrimitive.content, "client_public"))

            val named = namedGroup
            if (named != null && named != group) {
                // Name a different group and answer in it; the client is
                // expected to restart rather than continue with the A it sent.
                namedGroup = null
                return challengeBody(named, BigInteger.ONE)
            }
            bPriv = BigInteger(1, ByteArray(32) { 0x22 })
            bPub = Srp.multiplier(group).multiply(verifier)
                .add(group.generator.modPow(bPriv, group.modulus)).mod(group.modulus)
            return challengeBody(group, bPub)
        }

        private fun challengeBody(named: SrpGroup, publicValue: BigInteger) = MockResponse()
            .setResponseCode(200)
            .addHeader("Content-Type", "application/json")
            .setBody(
                """{"srp_session":"opaque-session-token","identity":"$IDENTITY",""" +
                    """"salt":"${Srp.toHex(salt)}","group":"${named.wireName}",""" +
                    """"kdf":"${kdf.kdf}","iterations":${kdf.iterations},""" +
                    """"b_pub":"${Srp.toHex(Srp.pad(publicValue, named.byteLength))}"}""",
            )

        private fun verify(body: String): MockResponse {
            val parsed = Json.parseToJsonElement(body).jsonObject
            check(parsed["srp_session"]!!.jsonPrimitive.content == "opaque-session-token") {
                "srp_session must be echoed verbatim"
            }

            // S = (A * v^u)^b mod N — the server's own derivation.
            val u = Srp.hashToInt(Srp.pad(aPub, group.byteLength), Srp.pad(bPub, group.byteLength))
            val s = aPub.multiply(verifier.modPow(u, group.modulus)).mod(group.modulus)
                .modPow(bPriv, group.modulus)
            val sessionKey = Srp.hash(Srp.pad(s, group.byteLength))
            val m1 = Srp.fromHex(parsed["client_proof"]!!.jsonPrimitive.content, "client_proof")
            var proof = Srp.toHex(Srp.hash(Srp.pad(aPub, group.byteLength), m1, sessionKey))
            if (corruptServerProof) proof = "0".repeat(proof.length)

            // Cookies are set exactly as on /auth/login (§23.5) — including on
            // the corrupt-proof path, so the test can assert they are discarded.
            val response = MockResponse()
                .addHeader("Content-Type", "application/json")
                .addHeader("Set-Cookie", "axiam_access=${TestSupport.fakeJwt()}; Path=/")
                .addHeader("Set-Cookie", "axiam_refresh=refresh-tok; Path=/")
            return if (mfaRequired) {
                response.setResponseCode(202).setBody(
                    """{"challenge_token":"mfa-challenge","available_methods":["totp"],""" +
                        """"server_proof":"$proof"}""",
                )
            } else {
                response.setResponseCode(200).setBody("""{"expires_in":900,"server_proof":"$proof"}""")
            }
        }

        companion object {
            const val IDENTITY = "alice"
            const val PASSWORD = "correct horse battery staple"
        }
    }

    /** The happy path against real arithmetic on both sides. */
    @Test
    fun `loginSrp establishes a session against a server that only holds a verifier`() = runBlocking {
        server.dispatcher = FakeSrpServer(SrpGroup.RFC5054_2048)
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertTrue(client.srpAvailable())
            val result = client.loginSrp(FakeSrpServer.IDENTITY, FakeSrpServer.PASSWORD.toCharArray())
            assertFalse(result.mfaRequired)
            assertNotNull(result.user)
            assertEquals("user-1", result.user!!.userId)
        }
    }

    /**
     * §23.1's hard requirement that both login paths return the same result
     * type: an application switching a tenant to SRP must not need a second
     * result handler.
     */
    @Test
    fun `loginSrp returns the same MFA branch as login`() = runBlocking {
        server.dispatcher = FakeSrpServer(SrpGroup.RFC5054_2048).apply { mfaRequired = true }
        server.start()
        TestSupport.clientFor(server).use { client ->
            val result = client.loginSrp(FakeSrpServer.IDENTITY, FakeSrpServer.PASSWORD.toCharArray())
            assertTrue(result.mfaRequired, "a 202 must surface as mfaRequired, not as an exception")
            assertEquals("mfa-challenge", result.challengeToken!!.expose())
            assertNull(result.user)
        }
    }

    /**
     * `A` is computed before the server has named a group, so a tenant on a
     * narrower group must work rather than fail.
     */
    @Test
    fun `loginSrp restarts when the server names another group`() = runBlocking {
        server.dispatcher = FakeSrpServer(SrpGroup.RFC5054_2048).apply {
            // Differs from the 4096 opening guess.
            namedGroup = SrpGroup.RFC5054_2048
        }
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertFalse(client.loginSrp(FakeSrpServer.IDENTITY, FakeSrpServer.PASSWORD.toCharArray()).mfaRequired)
        }
    }

    /**
     * §23.7 rule 5. The assertion is on the ABSENCE of a session, not merely on
     * a thrown message: skipping `M2` keeps the half of SRP that authenticates
     * the client and throws away the half that authenticates the server.
     */
    @Test
    fun `a wrong server proof yields AuthError and no session`() = runBlocking {
        server.dispatcher = FakeSrpServer(SrpGroup.RFC5054_2048).apply { corruptServerProof = true }
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) {
                runBlocking { client.loginSrp(FakeSrpServer.IDENTITY, FakeSrpServer.PASSWORD.toCharArray()) }
            }
            // The cookies the rogue server set must not survive: an endpoint
            // that cannot prove it holds the verifier is not the server it
            // claims to be.
            assertThrows(AuthError::class.java) { runBlocking { client.refresh() } }
        }
    }

    /**
     * A 404 is a property of the tenant, so a caller can fall back to `login()`
     * without mistaking it for a bad password.
     */
    @Test
    fun `a tenant with SRP disabled is not a credential failure`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(404))
        server.start()
        TestSupport.clientFor(server).use { client ->
            val error = assertThrows(NetworkError::class.java) {
                runBlocking { client.loginSrp("alice", "pw".toCharArray()) }
            }
            assertTrue(error.message!!.contains("srp_mode"), error.message)
        }
    }

    @Test
    fun `a wrong password is an AuthError`() = runBlocking {
        val fake = FakeSrpServer(SrpGroup.RFC5054_2048)
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                if ((request.path ?: "").endsWith("/auth/srp/verify")) {
                    MockResponse().setResponseCode(401).setBody("""{"error":"authentication_failed"}""")
                } else {
                    fake.dispatch(request)
                }
        }
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) {
                runBlocking { client.loginSrp(FakeSrpServer.IDENTITY, "wrong".toCharArray()) }
            }
        }
    }

    /**
     * §23.7 rule 7 and §23.3 rule 10. A user whose password is perfectly good
     * must never be shown "invalid username or password" because the tenant
     * moved to `srp_mode: required`.
     */
    @Test
    fun `srp_required is an AuthzError rather than an AuthError`() = runBlocking {
        server.enqueue(
            TestSupport.json(403, """{"error":"srp_required","message":"this tenant requires SRP"}"""),
        )
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthzError::class.java) { runBlocking { client.login("alice", "hunter2") } }
        }
    }

    /**
     * §23.7 rule 8: `A`, `M1`, `srp_session` and the salt must reach no log
     * record. This SDK's telemetry hook is the sink an application would attach
     * a metrics exporter to, so drive one and read it back — `srp_session` in
     * particular is bearer-equivalent while it lives.
     */
    @Test
    fun `nothing sensitive reaches the telemetry sink`() = runBlocking {
        val fake = FakeSrpServer(SrpGroup.RFC5054_2048)
        server.dispatcher = fake
        server.start()

        val sink = StringBuilder()
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgId(TestSupport.ORG_ID)
            .telemetryHook { event -> sink.append(event.toString()) }
            .build()
            .use { client ->
                client.loginSrp(FakeSrpServer.IDENTITY, FakeSrpServer.PASSWORD.toCharArray())
            }

        // Pull the exact values that crossed the wire out of the recorded
        // bodies rather than guessing at them, so this cannot pass by looking
        // for a string the client never produced.
        val logged = sink.toString()
        fake.bodies.forEach { body ->
            val parsed = Json.parseToJsonElement(body).jsonObject
            listOf("client_public", "client_proof", "srp_session").forEach { key ->
                parsed[key]?.jsonPrimitive?.content?.takeIf { it.isNotEmpty() }?.let { value ->
                    assertFalse(logged.contains(value), "§23.7 rule 8: $key reached the telemetry sink")
                }
            }
        }
        assertFalse(logged.contains(Srp.toHex(fake.salt)), "the salt reached the telemetry sink")
        assertFalse(logged.contains(FakeSrpServer.PASSWORD), "the password reached the telemetry sink")
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment through the client API
    // -----------------------------------------------------------------------

    @Test
    fun `srpEnrollment produces a verifier reproducible from its own salt`() = runBlocking {
        server.start()
        TestSupport.clientFor(server).use { client ->
            val params = SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000)
            val first = client.srpEnrollment("alice", "hunter2".toCharArray(), params = params)

            assertEquals(SrpGroup.RFC5054_4096.wireName, first.group, "the default group")
            assertEquals(64, first.salt.length, "the salt must be 32 bytes")
            assertEquals(0, first.memoryKib, "pbkdf2 enrolment must not carry argon2 parameters")
            assertEquals(0, first.parallelism)

            val x = Srp.deriveX("alice", "hunter2".toCharArray(), Srp.fromHex(first.salt, "salt"), params)
            assertEquals(
                first.verifier,
                Srp.computeVerifier(SrpGroup.RFC5054_4096, x),
                "the reported verifier is not g^x for the reported salt",
            )

            // A reused salt would make every verifier in a tenant equally
            // attackable with one precomputation.
            val second = client.srpEnrollment("alice", "hunter2".toCharArray(), params = params)
            assertNotEquals(first.salt, second.salt)

            // Argon2id enrolment carries its memory and lane costs.
            val argon = client.srpEnrollment(
                "alice",
                "hunter2".toCharArray(),
                SrpGroup.RFC5054_2048,
                SrpKdfParams(SrpKdfParams.ARGON2ID, 1, 8192, 1),
            )
            assertEquals("rfc5054_2048", argon.group)
            assertEquals(8192, argon.memoryKib)
            assertEquals(1, argon.parallelism)
        }
    }

    @Test
    fun `srpEnrollment refuses a KDF this SDK does not implement`() = runBlocking {
        server.start()
        TestSupport.clientFor(server).use { client ->
            assertThrows(NetworkError::class.java) {
                runBlocking {
                    client.srpEnrollment("alice", "pw".toCharArray(), params = SrpKdfParams("scrypt", 1))
                }
            }
        }
    }
}

private fun assertNotEquals(unexpected: Any?, actual: Any?) =
    org.junit.jupiter.api.Assertions.assertNotEquals(unexpected, actual)
