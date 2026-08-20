package io.axiam.sdk.opaque

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import java.security.SecureRandom

/**
 * The JNA binding to `libaxiam_opaque_ffi`.
 *
 * §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography
 * here to test. What these cover is the part a binding gets wrong: ownership of
 * library-allocated strings, single-use state handles, the key-stretching
 * function the *server* named being the one used, and an absent library
 * reporting rather than resembling a wrong password.
 */
class OpaqueBindingTest {

    private lateinit var lib: FakeOpaqueNative

    @BeforeEach
    fun installFake() {
        lib = installFakeOpaque()
    }

    @AfterEach
    fun restoreLoader() {
        resetOpaque()
    }

    private fun argon2id(): KsfParams = KsfParams.fromWire(
        buildJsonObject {
            put("ksf", "argon2id")
            put("memory_kib", 19456)
            put("iterations", 2)
            put("parallelism", 1)
        },
    )

    private fun scrypt(): KsfParams = KsfParams.fromWire(
        buildJsonObject {
            put("ksf", "scrypt")
            put("log_n", 15)
            put("r", 8)
            put("p", 1)
        },
    )

    // -----------------------------------------------------------------
    // Availability (§23.2) -- reporting, never throwing
    // -----------------------------------------------------------------

    @Test
    @DisplayName("available() is true when the library loads and says yes")
    fun availableWhenPresent() {
        assertTrue(Opaque.available())
    }

    @Test
    @DisplayName("a library that is present but built without OPAQUE reports false")
    fun availableFalseWhenLibrarySaysNo() {
        // Present is not the same as usable, and answering from the file's
        // existence would strand a caller at login.
        lib.availableValue = 0
        assertFalse(Opaque.available())
    }

    @Test
    @DisplayName("an absent library reports false rather than throwing")
    fun availableFalseWhenAbsent() {
        installAbsentOpaque()
        assertFalse(Opaque.available())
    }

    @Test
    @DisplayName("an absent library names the artifact, not the password")
    fun absentLibraryNamesTheArtifact() {
        installAbsentOpaque()
        val error = assertThrows<NetworkError> { Opaque.startLogin(PASSWORD) }
        assertTrue(error.message!!.contains("libaxiam_opaque_ffi"))
        assertTrue(error.message!!.contains("AXIAM_OPAQUE_LIBRARY"))
        assertTrue(error.message!!.contains("jna"))
    }

    @Test
    @DisplayName("the real loader treats an unloadable library as absent, and memoizes that")
    fun realLoaderReportsAbsentRatherThanThrowing() {
        // No libaxiam_opaque_ffi is installed in CI, so this exercises the
        // genuine dlopen failure path -- including that retrying it is not a
        // per-login filesystem walk.
        resetOpaque()
        System.setProperty(OpaqueLibrary.LIBRARY_PROPERTY, "/nonexistent/libabsent.so")
        try {
            assertNull(OpaqueLibrary.load())
            assertNull(OpaqueLibrary.load())
        } finally {
            System.clearProperty(OpaqueLibrary.LIBRARY_PROPERTY)
            resetOpaque()
        }
    }

    // -----------------------------------------------------------------
    // KsfParams -- absence preserved, bounds enforced (§23.4 rules 2-5)
    // -----------------------------------------------------------------

    @Test
    @DisplayName("fromWire preserves absence rather than defaulting to zero")
    fun absenceIsPreserved() {
        val params = argon2id()
        assertEquals("argon2id", params.ksf)
        assertEquals(19456, params.memoryKib)
        // scrypt's fields do not apply. Reading them as 0 would stretch at the
        // wrong cost and fail against a record that is perfectly good.
        assertNull(params.logN)
        assertNull(params.r)
        assertNull(params.p)
    }

    @Test
    @DisplayName("a cost the named function needs but the server omitted is refused")
    fun missingCostIsRefused() {
        val wire = buildJsonObject {
            put("ksf", "argon2id")
            put("iterations", 2)
            put("parallelism", 1)
        }
        val error = assertThrows<NetworkError> { KsfParams.fromWire(wire).build(lib) }
        assertTrue(error.message!!.contains("without `memory_kib`"))
        assertEquals(0, lib.ksfAlive)
    }

    @ParameterizedTest
    @CsvSource(
        "argon2id, memory_kib, 4096",
        "argon2id, memory_kib, 2097152",
        "argon2id, iterations, 0",
        "argon2id, iterations, 99",
        "argon2id, parallelism, 64",
        "scrypt, log_n, 13",
        "scrypt, log_n, 21",
        "scrypt, r, 0",
        "scrypt, p, 17",
    )
    @DisplayName("a cost outside the accepted band is refused, naming the field")
    fun costsOutsideTheBandAreRefused(ksf: String, field: String, value: Int) {
        // A server is trusted to name its own policy, not to name a cost that
        // would wedge every device an account owns.
        val wire = buildJsonObject {
            put("ksf", ksf)
            if (ksf == "argon2id") {
                put("memory_kib", 19456)
                put("iterations", 2)
                put("parallelism", 1)
            } else {
                put("log_n", 15)
                put("r", 8)
                put("p", 1)
            }
            put(field, value)
        }
        val error = assertThrows<NetworkError> { KsfParams.fromWire(wire).build(lib) }
        assertTrue(error.message!!.contains(field), error.message)
        assertEquals(0, lib.ksfAlive)
    }

    @ParameterizedTest
    @ValueSource(strings = ["bcrypt", "pbkdf2_sha256", ""])
    @DisplayName("an unrecognised key-stretching function is refused, never substituted")
    fun unknownKsfIsRefused(ksf: String) {
        // Substituting produces a well-formed randomized password no AXIAM
        // server agrees with, which surfaces to the user as a wrong password.
        val wire: JsonObject = buildJsonObject { put("ksf", ksf) }
        assertThrows<NetworkError> { KsfParams.fromWire(wire).build(lib) }
        assertEquals(0, lib.ksfAlive)
    }

    @Test
    @DisplayName("a null ksf handle reports the library's own message")
    fun nullKsfHandleReportsLibraryMessage() {
        lib.fail("ksf_argon2id")
        val error = assertThrows<NetworkError> { argon2id().build(lib) }
        assertTrue(error.message!!.contains("argon2id parameters rejected"))
    }

    @Test
    @DisplayName("both key-stretching functions are reachable")
    fun bothKsfsReachable() {
        listOf(argon2id(), scrypt()).forEach { lib.axiam_opaque_ksf_free(it.build(lib)) }
        assertEquals(0, lib.ksfAlive)
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a registration round trip frees every allocation exactly once")
    fun registrationRoundTrip() {
        val exchange = Opaque.startRegistration(PASSWORD)
        assertEquals("req:${String(PASSWORD)}", decodeHex(exchange.request))

        val record = exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id())

        assertTrue(
            decodeHex(record).startsWith("record:${String(PASSWORD)}:$REGISTRATION_RESPONSE:"),
        )
        // Two library allocations were handed over -- the request and the
        // record -- and both were released. A binding that leaks here leaks
        // once per enrolment.
        assertEquals(2, lib.freed.size)
        assertEquals(2, lib.freed.distinct().size)
        assertEquals(0, lib.allocationsAlive)
        assertEquals(0, lib.ksfAlive)
        assertEquals(0, lib.statesAlive)
    }

    @Test
    @DisplayName("a failed registration start reports the library's message")
    fun registrationStartFailure() {
        lib.fail("registration_start")
        val error = assertThrows<NetworkError> { Opaque.startRegistration(PASSWORD) }
        assertTrue(error.message!!.contains("registration could not be started"))
    }

    @Test
    @DisplayName("a failed registration finish still consumed the handle, and leaks nothing")
    fun registrationFinishFailure() {
        lib.fail("registration_finish")
        val exchange = Opaque.startRegistration(PASSWORD)
        val error = assertThrows<NetworkError> {
            exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id())
        }
        assertTrue(error.message!!.contains("the envelope could not be sealed"))
        // The library consumes the state whether it succeeds or fails, so the
        // binding must not free it again -- and must not leak the ksf either.
        assertEquals(0, lib.statesAlive)
        assertEquals(0, lib.ksfAlive)
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a login round trip frees every allocation exactly once")
    fun loginRoundTrip() {
        val exchange = Opaque.startLogin(PASSWORD)
        assertEquals("ke1:${String(PASSWORD)}", decodeHex(exchange.ke1))

        val ke3 = exchange.finish(PASSWORD, KE2, scrypt())

        assertTrue(decodeHex(ke3).startsWith("ke3:${String(PASSWORD)}:$KE2:"))
        assertEquals(2, lib.freed.size)
        assertEquals(0, lib.allocationsAlive)
        assertEquals(0, lib.ksfAlive)
        assertEquals(0, lib.statesAlive)
    }

    @Test
    @DisplayName("a failed login start reports the library's message")
    fun loginStartFailure() {
        lib.fail("login_start")
        val error = assertThrows<NetworkError> { Opaque.startLogin(PASSWORD) }
        assertTrue(error.message!!.contains("login could not be started"))
    }

    @Test
    @DisplayName("a failed login finish is an AuthError -- it IS the credential check")
    fun failedLoginFinishIsAnAuthError() {
        // Both halves of the mutual authentication live here: the envelope only
        // opens under the right password, and KE2's MAC only verifies if the
        // server actually holds the record. AuthError rather than NetworkError
        // is what keeps a misconfigured KSF from being shown as a wrong password.
        lib.fail("login_finish")
        val exchange = Opaque.startLogin(OTHER_PASSWORD)
        val error = assertThrows<AuthError> { exchange.finish(OTHER_PASSWORD, KE2, argon2id()) }
        assertTrue(error.message!!.contains("invalid credentials"))
        assertEquals(0, lib.statesAlive)
        assertEquals(0, lib.ksfAlive)
    }

    @Test
    @DisplayName("a silent library still produces a sentence")
    fun failedLoginFinishFallsBackWhenLibraryIsSilent() {
        lib.fail("login_finish")
        lib.failMessage("login_finish", "")
        val exchange = Opaque.startLogin(OTHER_PASSWORD)
        val error = assertThrows<AuthError> { exchange.finish(OTHER_PASSWORD, KE2, argon2id()) }
        assertTrue(error.message!!.contains("the OPAQUE envelope did not open"))
    }

    @Test
    @DisplayName("an exchange is single-use")
    fun exchangeIsSingleUse() {
        val exchange = Opaque.startLogin(PASSWORD)
        exchange.finish(PASSWORD, KE2, argon2id())
        val error = assertThrows<NetworkError> { exchange.finish(PASSWORD, KE2, argon2id()) }
        assertTrue(error.message!!.contains("already been completed"))
    }

    @Test
    @DisplayName("a refused ksf spends the handle, so a retry fails loudly")
    fun refusedKsfStillSpendsTheHandle() {
        val exchange = Opaque.startRegistration(PASSWORD)
        val unknown = KsfParams.fromWire(buildJsonObject { put("ksf", "bcrypt") })
        assertThrows<NetworkError> { exchange.finish(PASSWORD, REGISTRATION_RESPONSE, unknown) }
        // The handle was taken before the ksf was built, so it is spent.
        // Retrying must fail rather than pass a dangling pointer across the ABI.
        val second = assertThrows<NetworkError> {
            exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id())
        }
        assertTrue(second.message!!.contains("already been completed"))
    }

    @Test
    @DisplayName("use { } releases an exchange that was never finished")
    fun useReleasesAnAbandonedExchange() {
        Opaque.startLogin(PASSWORD).use {
            assertEquals(1, lib.statesAlive)
            assertTrue(it.ke1.isNotEmpty())
        }
        assertEquals(0, lib.statesAlive)
    }

    @Test
    @DisplayName("close() after a finish is a no-op, not a double free")
    fun closeAfterFinishIsIdempotent() {
        Opaque.startLogin(PASSWORD).use {
            it.finish(PASSWORD, KE2, argon2id())
            it.close()
        }
        assertEquals(0, lib.statesAlive)
    }

    @Test
    @DisplayName("an abandoned registration is released too")
    fun useReleasesAnAbandonedRegistration() {
        Opaque.startRegistration(PASSWORD).use {
            assertEquals(1, lib.statesAlive)
        }
        assertEquals(0, lib.statesAlive)
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    @Test
    @DisplayName("passwords cross the ABI as UTF-8, not as the platform charset")
    fun passwordsCrossAsUtf8() {
        // A password that encoded differently under a different default locale
        // would derive a randomized password no AXIAM server agrees with, and
        // would surface as a wrong password on that machine only. The
        // conformance vectors require UTF-8.
        val accented = "pàsswörd-ünïcøde-🔐".toCharArray()
        Opaque.startLogin(accented).use {
            assertEquals("ke1:${String(accented)}", decodeHex(it.ke1))
        }
    }

    @Test
    @DisplayName("an empty password is still a password")
    fun emptyPasswordIsEncoded() {
        Opaque.startLogin(CharArray(0)).use {
            assertEquals("ke1:", decodeHex(it.ke1))
        }
    }

    companion object {
        /**
         * Minted per run rather than written down. Nothing here depends on the
         * value — only on the two differing — and a literal that reads like a
         * credential is a finding for every secret scanner that looks at this
         * repository, which trains people to wave those findings through.
         */
        private fun password(label: String): CharArray {
            val entropy = ByteArray(8).also { SecureRandom().nextBytes(it) }
            return (label + "-" + entropy.joinToString("") { "%02x".format(it) }).toCharArray()
        }

        val PASSWORD: CharArray = password("correct")
        val OTHER_PASSWORD: CharArray = password("incorrect")

        const val KE2: String = "ke2-hex"
        const val REGISTRATION_RESPONSE: String = "resp-hex"
    }
}
