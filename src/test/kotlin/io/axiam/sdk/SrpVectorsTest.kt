package io.axiam.sdk

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.srp.Srp
import io.axiam.sdk.srp.SrpClientSession
import io.axiam.sdk.srp.SrpGroup
import io.axiam.sdk.srp.SrpKdfParams
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.math.BigInteger

/**
 * CONTRACT.md §23.7 conformance for the SRP-6a client.
 *
 * `srp-test-vectors.json` is generated from the AXIAM server implementation and
 * vendored into every SDK. Eleven independent SRP implementations do not
 * interoperate by accident; this is the file that says whether this one does.
 *
 * §23.7 rule 1 requires every intermediate to be reproduced, not only the final
 * proof — an SDK that gets `u` wrong should find out at `u` rather than at
 * "login sometimes fails".
 */
class SrpVectorsTest {

    private fun vectors(): List<JsonObject> = SrpTestSupport.vectors()

    private fun JsonObject.str(key: String): String = this[key]!!.jsonPrimitive.content

    // -----------------------------------------------------------------------
    // §23.7 rule 4 — group constants
    // -----------------------------------------------------------------------

    /**
     * A transcription slip in a modulus is a silent, total break: client and
     * server would still agree with each other while the discrete-log hardness
     * the protocol rests on quietly vanished. A round-trip test cannot catch
     * it, because both sides share the same wrong constant.
     */
    @TestFactory
    fun `every group is a safe prime of the advertised width`(): List<DynamicTest> =
        SrpGroup.entries.map { group ->
            DynamicTest.dynamicTest(group.wireName) {
                val n = group.modulus
                assertEquals(group.byteLength * 8, n.bitLength(), "modulus width")
                assertTrue(n.isProbablePrime(64), "modulus is not prime")
                val q = n.subtract(BigInteger.ONE).shiftRight(1)
                assertTrue(q.isProbablePrime(64), "(N-1)/2 is not prime — not a safe prime")
                // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
                assertEquals(
                    n.subtract(BigInteger.ONE),
                    group.generator.modPow(q, n),
                    "g does not generate the large subgroup",
                )
            }
        }

    @Test
    fun `an unrecognised group is refused rather than guessed`() {
        // Guessing would mean computing in a group whose safety this SDK has
        // not verified — potentially one whose discrete log the server knows.
        val error = assertThrows(NetworkError::class.java) { SrpGroup.fromWire("rfc5054_1024") }
        // NetworkError, not AuthError: this is a client capability gap, and
        // calling it an auth failure would send a user to reset a working
        // password.
        assertTrue(error.message!!.contains("rfc5054_1024"), error.message)
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 1 — PAD()
    // -----------------------------------------------------------------------

    @Test
    fun `PAD left-pads to the group width`() {
        assertEquals("00000001", Srp.toHex(Srp.pad(BigInteger.ONE, 4)))
        assertEquals("0102", Srp.toHex(Srp.pad(BigInteger.valueOf(0x0102), 2)))
    }

    // -----------------------------------------------------------------------
    // §23.7 rules 1–3 — the vectors
    // -----------------------------------------------------------------------

    /**
     * Guards the fixture itself: if these stop holding, everything below
     * silently stops testing the two things it was built to test.
     */
    @Test
    fun `the fixtures cover the cases they exist for`() {
        val vectors = vectors()
        assertTrue(vectors.isNotEmpty())
        assertTrue(
            vectors.any { it.str("salt").startsWith("00") },
            "§23.7 rule 2: no vector has a leading-zero salt",
        )
        assertTrue(
            vectors.any { it.str("x").startsWith("00") },
            "§23.7 rule 2: no vector has a leading-zero x",
        )
        assertTrue(
            vectors.any { v -> v.str("identity").any { it.code > 0x7f } },
            "§23.7 rule 3: no vector has a non-ASCII identity",
        )
        SrpGroup.entries.forEach { group ->
            assertTrue(vectors.any { it.str("group") == group.wireName }, "no vector covers ${group.wireName}")
        }
    }

    @TestFactory
    fun `every vector reproduces every intermediate`(): List<DynamicTest> = vectors().map { v ->
        DynamicTest.dynamicTest("${v.str("group")}/${v.str("identity")}") {
            val group = SrpGroup.fromWire(v.str("group"))
            val n = group.modulus
            val x = BigInteger(v.str("x"), 16).mod(n)

            // k = H(N | PAD(g))
            assertEquals(v.str("k"), Srp.toHex(Srp.pad(Srp.multiplier(group), 32)), "k")

            // v = g^x mod N
            assertEquals(v.str("verifier"), Srp.computeVerifier(group, Srp.fromHex(v.str("x"), "x")), "verifier")

            // A = g^a mod N
            val a = BigInteger(v.str("a_priv"), 16)
            val aPub = group.generator.modPow(a, n)
            assertEquals(v.str("a_pub"), Srp.toHex(Srp.pad(aPub, group.byteLength)), "A")

            // B = (k*v + g^b) mod N
            val b = BigInteger(v.str("b_priv"), 16)
            val verifier = group.generator.modPow(x, n)
            val bPub = Srp.multiplier(group).multiply(verifier)
                .add(group.generator.modPow(b, n)).mod(n)
            assertEquals(v.str("b_pub"), Srp.toHex(Srp.pad(bPub, group.byteLength)), "B")

            // u = H(PAD(A) | PAD(B))
            val u = Srp.hashToInt(Srp.pad(aPub, group.byteLength), Srp.pad(bPub, group.byteLength))
            assertEquals(v.str("u"), Srp.toHex(Srp.pad(u, 32)), "u")

            // S and K, from the client's derivation.
            val kgx = Srp.multiplier(group).multiply(group.generator.modPow(x, n)).mod(n)
            val s = bPub.subtract(kgx).mod(n).modPow(a.add(u.multiply(x)), n)
            assertEquals(v.str("session_secret"), Srp.toHex(Srp.pad(s, group.byteLength)), "S")
            assertEquals(v.str("session_key"), Srp.toHex(Srp.hash(Srp.pad(s, group.byteLength))), "K")
        }
    }

    /**
     * Drives the real session rather than the helpers, with `a` pinned to the
     * vector's value — otherwise this would only test the internals.
     */
    @TestFactory
    fun `every vector produces the contract proofs through the public API`(): List<DynamicTest> =
        vectors().map { v ->
            DynamicTest.dynamicTest("${v.str("group")}/${v.str("identity")}") {
                val group = SrpGroup.fromWire(v.str("group"))
                val session = SrpClientSession.withFixedEphemeral(group, BigInteger(v.str("a_priv"), 16))
                assertEquals(v.str("a_pub"), session.clientPublic, "A")

                val proofs = session.finish(
                    v.str("identity"),
                    v.str("salt"),
                    v.str("b_pub"),
                    Srp.fromHex(v.str("x"), "x"),
                )
                assertEquals(v.str("client_proof"), proofs.clientProof, "M1")
                assertEquals(v.str("server_proof"), proofs.expectedServerProof, "M2")
            }
        }

    // -----------------------------------------------------------------------
    // §23.3 protocol refusals
    // -----------------------------------------------------------------------

    /**
     * §23.7 rule 6, with no network round trip. The classic SRP break: a client
     * that accepts `B ≡ 0` derives a predictable `S` and would authenticate
     * against a server that never knew the verifier.
     */
    @Test
    fun `a server public value congruent to zero is refused`() {
        val session = SrpClientSession.begin(SrpGroup.RFC5054_2048)
        val error = assertThrows(NetworkError::class.java) {
            session.finish("alice", "00".repeat(32), "0".repeat(SrpGroup.RFC5054_2048.byteLength * 2), ByteArray(32))
        }
        assertTrue(error.message!!.contains("invalid public value"), error.message)
    }

    @Test
    fun `every exchange uses a fresh client ephemeral`() {
        assertNotEquals(
            SrpClientSession.begin(SrpGroup.RFC5054_2048).clientPublic,
            SrpClientSession.begin(SrpGroup.RFC5054_2048).clientPublic,
        )
    }

    @Test
    fun `an unknown KDF is refused rather than substituted`() {
        // Substituting the other KDF derives a different x and surfaces as
        // "invalid password" — the single most misleading failure available.
        val error = assertThrows(NetworkError::class.java) {
            Srp.deriveX("alice", "pw".toCharArray(), ByteArray(32), SrpKdfParams("scrypt", 1))
        }
        assertTrue(error.message!!.contains("scrypt"), error.message)
    }

    @Test
    fun `a malformed hex field is refused rather than silently truncated`() {
        assertThrows(NetworkError::class.java) { Srp.fromHex("zz", "salt") }
        assertThrows(NetworkError::class.java) { Srp.fromHex("abc", "salt") }
    }

    // -----------------------------------------------------------------------
    // KDF
    // -----------------------------------------------------------------------

    /**
     * Every one of these must change the output, or a verifier would be
     * replayable against a different account or a different salt.
     */
    @Test
    fun `the KDF binds identity password and salt`() {
        val params = SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000)
        val salt = ByteArray(32) { 0x0a }
        val base = Srp.toHex(Srp.deriveX("alice", "pw".toCharArray(), salt, params))

        assertEquals(32, Srp.deriveX("alice", "pw".toCharArray(), salt, params).size)
        assertEquals(base, Srp.toHex(Srp.deriveX("alice", "pw".toCharArray(), salt, params)))
        assertNotEquals(base, Srp.toHex(Srp.deriveX("bob", "pw".toCharArray(), salt, params)))
        assertNotEquals(base, Srp.toHex(Srp.deriveX("alice", "pw2".toCharArray(), salt, params)))
        assertNotEquals(base, Srp.toHex(Srp.deriveX("alice", "pw".toCharArray(), ByteArray(32) { 0x0b }, params)))
    }

    /**
     * Argon2id is the KDF the server asks for by default. Low memory so the
     * test stays fast; the code path is identical to the 19 MiB production
     * parameters.
     */
    @Test
    fun `argon2id runs and is the default KDF`() {
        assertEquals(
            32,
            Srp.deriveX("alice", "pw".toCharArray(), ByteArray(32), SrpKdfParams(SrpKdfParams.ARGON2ID, 1, 8192, 1)).size,
        )
        val defaults = SrpKdfParams("", 0).withDefaults()
        assertEquals(SrpKdfParams.ARGON2ID, defaults.kdf)
        assertEquals(19456, defaults.memoryKib)
        assertEquals(2, defaults.iterations)
        assertEquals(1, defaults.parallelism)
        assertEquals(600_000, SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 0).withDefaults().iterations)
    }

    /**
     * The two KDFs must encode the identity identically, or they would disagree
     * about the same account — which is exactly what the non-ASCII vector
     * exists to pin.
     */
    @Test
    fun `both KDFs agree on the UTF-8 encoding of a non-ASCII identity`() {
        val params = SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000)
        val salt = ByteArray(32)
        val correct = Srp.toHex(Srp.deriveX("renée", "pw".toCharArray(), salt, params))
        val mangled = Srp.toHex(Srp.deriveX("renÃ©e", "pw".toCharArray(), salt, params))
        assertNotEquals(mangled, correct)
        assertEquals(correct, Srp.toHex(Srp.deriveX("renée", "pw".toCharArray(), salt, params)))

        // The Argon2id path encodes the identity separately; both must agree
        // that the mangled form is a different account.
        val argon = SrpKdfParams(SrpKdfParams.ARGON2ID, 1, 8192, 1)
        assertNotEquals(
            Srp.toHex(Srp.deriveX("renÃ©e", "pw".toCharArray(), salt, argon)),
            Srp.toHex(Srp.deriveX("renée", "pw".toCharArray(), salt, argon)),
        )
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 6 — server proof comparison
    // -----------------------------------------------------------------------

    @Test
    fun `the server proof comparison accepts a match and rejects everything else`() {
        val proof = vectors().first().str("server_proof")
        assertTrue(Srp.verifyServerProof(proof, proof))
        assertFalse(Srp.verifyServerProof(proof, proof.dropLast(1) + "0"))
        assertFalse(Srp.verifyServerProof(proof, proof.take(32)))
        assertFalse(Srp.verifyServerProof(proof, ""))
        assertFalse(Srp.verifyServerProof(proof, null))
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment salts
    // -----------------------------------------------------------------------

    @Test
    fun `enrolment salts are 32 fresh bytes`() {
        // A reused salt would make every verifier in a tenant equally
        // attackable with one precomputation.
        val first = Srp.generateSalt()
        val second = Srp.generateSalt()
        assertEquals(32, first.size)
        assertNotEquals(Srp.toHex(first), Srp.toHex(second))
    }
}

/** Locates and parses the vendored §23.7 fixture. */
object SrpTestSupport {

    /**
     * Walks up from the working directory to find the vendored fixture, so this
     * does not encode how Gradle happens to set `user.dir`.
     */
    fun vectors(): List<JsonObject> {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "srp-test-vectors.json")
            if (candidate.isFile) {
                return Json.parseToJsonElement(candidate.readText())
                    .jsonObject["vectors"]!!.jsonArray.map { it.jsonObject }
            }
            dir = dir.parentFile
        }
        error("srp-test-vectors.json not found in any parent directory")
    }
}
