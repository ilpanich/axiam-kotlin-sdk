package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.opaque.FakeOpaqueNative
import io.axiam.sdk.opaque.decodeHex
import io.axiam.sdk.opaque.installAbsentOpaque
import io.axiam.sdk.opaque.installFakeOpaque
import io.axiam.sdk.opaque.resetOpaque
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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom

/**
 * `loginOpaque` / `opaqueEnrollment` end to end (CONTRACT.md §23).
 *
 * The protocol is `libaxiam_opaque_ffi`'s and is covered by
 * `opaque/OpaqueBindingTest`. What is tested here is the part the SDK owns:
 * what goes on the wire — and, more importantly, what does *not* — which
 * failures are [AuthError] and which are [NetworkError], and that a failed
 * credential check never reaches `login/finish`.
 */
class OpaqueLoginTest {

    private lateinit var server: MockWebServer
    private lateinit var lib: FakeOpaqueNative

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        lib = installFakeOpaque()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        resetOpaque()
    }

    /** A server that answers the three OPAQUE endpoints and records what it saw. */
    private class FakeOpaqueServer : Dispatcher() {

        val loginStartBodies = mutableListOf<String>()
        val loginFinishBodies = mutableListOf<String>()
        val registerStartBodies = mutableListOf<String>()

        /** Bodies seen at the plaintext `POST /api/v1/auth/login` (§23.4 rule 7). */
        val passwordLoginBodies = mutableListOf<String>()

        var loginStartStatus = 200
        var loginFinishStatus = 200
        var registerStartStatus = 200
        var passwordLoginStatus = 200
        var mfaRequired = false
        var omitKe2 = false
        var ksf = "argon2id"

        /**
         * The tenant's `opaque_mode` as `login/start` reports it, or `null` for
         * a server older than the field — which §23.4 rule 7 reads as
         * `required`.
         */
        var mode: String? = null

        override fun dispatch(request: RecordedRequest): MockResponse {
            val body = request.body.readUtf8()
            return when {
                request.path.orEmpty().endsWith("/auth/opaque/login/start") -> {
                    loginStartBodies += body
                    loginStart()
                }
                request.path.orEmpty().endsWith("/auth/opaque/login/finish") -> {
                    loginFinishBodies += body
                    loginFinish()
                }
                request.path.orEmpty().endsWith("/auth/opaque/register/start") -> {
                    registerStartBodies += body
                    registerStart()
                }
                request.path.orEmpty().endsWith("/auth/login") -> {
                    passwordLoginBodies += body
                    passwordLogin()
                }
                else -> MockResponse().setResponseCode(404)
            }
        }

        private fun ksfFields(): String = if (ksf == "scrypt") {
            """"ksf":"scrypt","log_n":15,"r":8,"p":1"""
        } else {
            """"ksf":"$ksf","memory_kib":19456,"iterations":2,"parallelism":1"""
        }

        private fun loginStart(): MockResponse {
            if (loginStartStatus != 200) return MockResponse().setResponseCode(loginStartStatus)
            val ke2 = if (omitKe2) "" else """"ke2":"$WIRE_KE2","""
            val modeField = mode?.let { """"mode":"$it",""" } ?: ""
            return TestSupport.json(
                200,
                """{"opaque_session":"handle-42",$modeField$ke2${ksfFields()}}""",
            )
        }

        private fun passwordLogin(): MockResponse {
            if (passwordLoginStatus != 200) {
                return MockResponse().setResponseCode(passwordLoginStatus)
            }
            return TestSupport.loginOkResponse()
        }

        private fun loginFinish(): MockResponse {
            if (loginFinishStatus != 200) return MockResponse().setResponseCode(loginFinishStatus)
            if (mfaRequired) {
                return MockResponse()
                    .setResponseCode(202)
                    .addHeader("Content-Type", "application/json")
                    .setBody("""{"challenge_token":"mfa-challenge","available_methods":["totp"]}""")
            }
            return TestSupport.loginOkResponse()
        }

        private fun registerStart(): MockResponse {
            if (registerStartStatus != 200) {
                return MockResponse().setResponseCode(registerStartStatus)
            }
            return TestSupport.json(
                200,
                """{"opaque_session":"reg-handle",""" +
                    """"registration_response":"$WIRE_REGISTRATION_RESPONSE",${ksfFields()}}""",
            )
        }
    }

    private fun parse(body: String) = Json.parseToJsonElement(body).jsonObject

    private fun field(body: String, name: String): String? =
        parse(body)[name]?.jsonPrimitive?.content

    private fun <T> withClient(fake: FakeOpaqueServer, block: suspend (AxiamClient) -> T): T {
        server.dispatcher = fake
        return runBlocking { TestSupport.clientFor(server).use { block(it) } }
    }

    // -----------------------------------------------------------------
    // What crosses the wire
    // -----------------------------------------------------------------

    @Test
    @DisplayName("login/start carries KE1 and no password field")
    fun loginStartCarriesNoPassword() {
        val fake = FakeOpaqueServer()
        withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }

        val body = parse(fake.loginStartBodies[0])
        // The entire point of the exchange. A body that still carried a
        // password would be SRP's failure mode with extra steps.
        assertNull(body["password"])
        assertEquals(USER, body["username_or_email"]?.jsonPrimitive?.content)
        assertEquals(TestSupport.TENANT_ID, body["tenant_slug"]?.jsonPrimitive?.content)
        assertEquals(
            "ke1:${String(PASSWORD)}",
            decodeHex(body["ke1"]!!.jsonPrimitive.content),
        )
    }

    @Test
    @DisplayName("register/start names no account at all")
    fun registerStartNamesNoAccount() {
        val fake = FakeOpaqueServer()
        val enrollment = withClient(fake) { it.opaqueEnrollment(PASSWORD.copyOf()) }

        assertEquals("reg-handle", enrollment.opaqueSession)
        assertTrue(
            decodeHex(enrollment.registrationRecord)
                .startsWith("record:${String(PASSWORD)}:$WIRE_REGISTRATION_RESPONSE:"),
        )

        val body = parse(fake.registerStartBodies[0])
        assertNull(body["password"])
        // No username either: a record binds to a credential identifier the
        // server chooses, which is why a later rename cannot invalidate one.
        assertNull(body["username_or_email"])
        assertEquals(TestSupport.TENANT_ID, body["tenant_slug"]?.jsonPrimitive?.content)
        assertEquals(
            "req:${String(PASSWORD)}",
            decodeHex(body["registration_request"]!!.jsonPrimitive.content),
        )
    }

    @Test
    @DisplayName("login/finish echoes the session handle the server issued")
    fun loginFinishEchoesTheServerHandle() {
        val fake = FakeOpaqueServer()
        withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }

        assertEquals("handle-42", field(fake.loginFinishBodies[0], "opaque_session"))
        assertTrue(
            decodeHex(field(fake.loginFinishBodies[0], "ke3")!!)
                .startsWith("ke3:${String(PASSWORD)}:$WIRE_KE2:"),
        )
    }

    @Test
    @DisplayName("the key-stretching function the server named is the one used")
    fun theServerNamedKsfIsTheOneUsed() {
        // §23.4 rule 2: never local defaults. A credential enrolled under one
        // cost keeps working after a tenant raises its policy, so a client that
        // guessed would fail against a record that is perfectly good.
        val fake = FakeOpaqueServer().apply { ksf = "scrypt" }
        withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }

        // The fake encodes the handle it was given; scrypt handles start 0xb.
        val ke3 = decodeHex(field(fake.loginFinishBodies[0], "ke3")!!)
        assertTrue(ke3.endsWith(":" + (0xB0000L + 15 + 8 + 1).toString(16)), ke3)
    }

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a successful login returns what login() returns")
    fun successReturnsTheSameShapeAsLogin() {
        val result = withClient(FakeOpaqueServer()) {
            assertTrue(it.opaqueAvailable())
            it.loginOpaque(USER, PASSWORD.copyOf())
        }
        assertFalse(result.mfaRequired)
        assertNotNull(result.user)
    }

    @Test
    @DisplayName("the mfa_required branch survives the OPAQUE path")
    fun mfaRequiredSurvives() {
        // One result handler must serve both login paths, so the second phase
        // has to arrive here exactly as it does from login().
        val result = withClient(FakeOpaqueServer().apply { mfaRequired = true }) {
            it.loginOpaque(USER, PASSWORD.copyOf())
        }
        assertTrue(result.mfaRequired)
        assertNotNull(result.challengeToken)
    }

    // -----------------------------------------------------------------
    // Failures -- which exception, and why it matters
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a disabled tenant is a NetworkError a caller can fall back from")
    fun disabledTenantIsANetworkError() {
        // A 404 is a property of the tenant, not of the credentials. As an
        // AuthError it would be shown as "invalid password" and send a user to
        // reset a working one, while stopping a fallback to login().
        val fake = FakeOpaqueServer().apply { loginStartStatus = 404 }
        val error = assertThrows<NetworkError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(error.message!!.contains("opaque_mode is disabled"))
        assertTrue(fake.loginFinishBodies.isEmpty())
    }

    @Test
    @DisplayName("enrolment reports a disabled tenant the same way")
    fun disabledTenantAtEnrolment() {
        val fake = FakeOpaqueServer().apply { registerStartStatus = 404 }
        val error = assertThrows<NetworkError> {
            withClient(fake) { it.opaqueEnrollment(PASSWORD.copyOf()) }
        }
        assertTrue(error.message!!.contains("opaque_mode is disabled"))
    }

    @Test
    @DisplayName("a 401 at login/start is an AuthError")
    fun unauthorizedAtStartIsAnAuthError() {
        val fake = FakeOpaqueServer().apply { loginStartStatus = 401 }
        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
    }

    @Test
    @DisplayName("a wrong password never reaches login/finish")
    fun wrongPasswordNeverReachesFinish() {
        // §23.4 rule 7. The envelope failing to open IS the authentication
        // check; sending anything afterwards would ask the server to decide
        // something the client has already decided.
        lib.fail("login_finish")
        val fake = FakeOpaqueServer()
        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.loginFinishBodies.isEmpty())
    }

    // -----------------------------------------------------------------
    // §23.4 rule 7 -- what `mode` decides after a failed KE2
    // -----------------------------------------------------------------

    @Test
    @DisplayName("optional: a failed KE2 retries over /auth/login and returns its success")
    fun optionalRetriesOverPasswordLogin() {
        // Under `optional` an account with no registration record is the
        // ordinary case, not an error: every account has none the moment an
        // operator enables OPAQUE, and acquires one only when its password is
        // next set. Treating the failed exchange as final would lock out every
        // user of a tenant mid-migration.
        lib.fail("login_finish")
        val fake = FakeOpaqueServer().apply { mode = "optional" }

        val result = withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }

        assertFalse(result.mfaRequired)
        assertNotNull(result.user)
        // KE3 is still never sent -- the fallback is a different endpoint, not
        // a second opinion on the exchange that just failed.
        assertTrue(fake.loginFinishBodies.isEmpty())
        assertEquals(1, fake.passwordLoginBodies.size)
        val retry = parse(fake.passwordLoginBodies[0])
        assertEquals(USER, retry["username_or_email"]?.jsonPrimitive?.content)
        assertEquals(String(PASSWORD), retry["password"]?.jsonPrimitive?.content)
    }

    @Test
    @DisplayName("optional: a failed KE2 and a failed /auth/login is the authentication error")
    fun optionalReportsThePasswordLoginFailure() {
        lib.fail("login_finish")
        val fake = FakeOpaqueServer().apply {
            mode = "optional"
            passwordLoginStatus = 401
        }

        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.loginFinishBodies.isEmpty())
        assertEquals(1, fake.passwordLoginBodies.size)
    }

    @Test
    @DisplayName("required: a failed KE2 is final and never reaches /auth/login")
    fun requiredNeverFallsBackToPasswordLogin() {
        // `required` answers 403 opaque_required for every principal, so the
        // retry would put a plaintext password on the wire for nothing.
        lib.fail("login_finish")
        val fake = FakeOpaqueServer().apply { mode = "required" }

        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.loginFinishBodies.isEmpty())
        assertTrue(fake.passwordLoginBodies.isEmpty())
    }

    @Test
    @DisplayName("no mode field: a server older than the field is read as required")
    fun absentModeIsReadAsRequired() {
        lib.fail("login_finish")
        val fake = FakeOpaqueServer()
        assertNull(fake.mode)

        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.loginFinishBodies.isEmpty())
        assertTrue(fake.passwordLoginBodies.isEmpty())
    }

    @Test
    @DisplayName("an unrecognised mode fails closed, exactly as required does")
    fun unknownModeFailsClosed() {
        lib.fail("login_finish")
        val fake = FakeOpaqueServer().apply { mode = "mandatory-ish" }

        assertThrows<AuthError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.loginFinishBodies.isEmpty())
        assertTrue(fake.passwordLoginBodies.isEmpty())
    }

    @Test
    @DisplayName("optional does not turn a KSF this build cannot perform into a password retry")
    fun optionalDoesNotFallBackForAConfigurationError() {
        // The fallback is keyed to the credential check failing, not to any
        // failure: an unknown KSF is a NetworkError no password endpoint fixes.
        val fake = FakeOpaqueServer().apply {
            mode = "optional"
            ksf = "bcrypt"
        }

        assertThrows<NetworkError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(fake.passwordLoginBodies.isEmpty())
    }

    @Test
    @DisplayName("an unsupported KSF is a configuration error, not a bad password")
    fun unsupportedKsfIsAConfigurationError() {
        val fake = FakeOpaqueServer().apply { ksf = "bcrypt" }
        val error = assertThrows<NetworkError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(error.message!!.contains("bcrypt"))
        assertTrue(fake.loginFinishBodies.isEmpty())
    }

    @Test
    @DisplayName("a start response without ke2 is a malformed response, not a credential failure")
    fun missingKe2IsAMalformedResponse() {
        val fake = FakeOpaqueServer().apply { omitKe2 = true }
        val error = assertThrows<NetworkError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
        assertTrue(error.message!!.contains("no `ke2`"))
    }

    @Test
    @DisplayName("a 5xx at login/finish is a NetworkError")
    fun serverErrorAtFinishIsANetworkError() {
        val fake = FakeOpaqueServer().apply { loginFinishStatus = 503 }
        assertThrows<NetworkError> {
            withClient(fake) { it.loginOpaque(USER, PASSWORD.copyOf()) }
        }
    }

    @Test
    @DisplayName("an absent library is reported before any request is sent")
    fun absentLibraryIsReportedBeforeAnyRequest() {
        installAbsentOpaque()
        val fake = FakeOpaqueServer()
        val error = assertThrows<NetworkError> {
            withClient(fake) {
                assertFalse(it.opaqueAvailable())
                it.loginOpaque(USER, PASSWORD.copyOf())
            }
        }
        assertTrue(error.message!!.contains("libaxiam_opaque_ffi"))
        assertEquals(0, server.requestCount)
    }

    companion object {
        private const val USER = "alice"

        /**
         * Minted per run rather than written down: nothing here depends on the
         * value, and a literal that reads like a credential is a finding for
         * every secret scanner that looks at this repository.
         */
        private val PASSWORD: CharArray = ByteArray(8)
            .also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
            .let { "correct-$it".toCharArray() }

        /**
         * The hex KE2 and RegistrationResponse the fake server answers with.
         * Hex because that is what the wire carries; the binding hands them to
         * the library verbatim and the fake library echoes them back inside its
         * own payload, which is how these tests see that nothing was rewritten
         * in between.
         */
        private const val WIRE_KE2 = "6b6532"
        private const val WIRE_REGISTRATION_RESPONSE = "726573703a"
    }
}
