package io.axiam.sdk.srp

import io.axiam.sdk.errors.NetworkError
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * The KDF and cost the server dictates for one SRP exchange (CONTRACT.md §23.5).
 *
 * §23.3 rule 4: these arrive per exchange and are honoured as given. They are
 * deliberately **not** cached across logins — a verifier enrolled under
 * different costs is still valid and has to keep working.
 *
 * @property kdf `"argon2id"` or `"pbkdf2_sha256"`.
 * @property iterations Argon2id's time cost, or PBKDF2's iteration count.
 * @property memoryKib Argon2id's memory cost in KiB; ignored for PBKDF2.
 * @property parallelism Argon2id's lane count; ignored for PBKDF2.
 */
data class SrpKdfParams(
    val kdf: String,
    val iterations: Int,
    val memoryKib: Int = 0,
    val parallelism: Int = 0,
) {
    /**
     * This instance with any zero cost replaced by AXIAM's default for the
     * chosen KDF.
     *
     * Used on the enrolment path, where the caller may know only which KDF the
     * tenant runs. It is never applied to a challenge response: a server that
     * omits a cost it is required to send is a server this SDK should not be
     * guessing on behalf of.
     */
    fun withDefaults(): SrpKdfParams {
        val resolved = kdf.ifEmpty { ARGON2ID }
        return if (resolved == PBKDF2_SHA256) {
            SrpKdfParams(resolved, if (iterations > 0) iterations else 600_000)
        } else {
            SrpKdfParams(
                resolved,
                if (iterations > 0) iterations else 2,
                if (memoryKib > 0) memoryKib else 19456,
                if (parallelism > 0) parallelism else 1,
            )
        }
    }

    companion object {
        /** The wire name of the memory-hard KDF AXIAM asks for by default. */
        const val ARGON2ID: String = "argon2id"

        /** The wire name of the fallback for runtimes with no vetted Argon2. */
        const val PBKDF2_SHA256: String = "pbkdf2_sha256"
    }
}

/**
 * The `srp` object CONTRACT.md §23.5 defines: a verifier and the parameters it
 * was computed under.
 *
 * The server cannot compute this — it never sees the plaintext — so any request
 * that **sets** a password has to carry it: `POST /api/v1/users`,
 * `/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`
 * (§23.3 rule 11).
 *
 * Neither [salt] nor [verifier] may be logged (§23.3 rule 12).
 */
data class SrpEnrollment(
    val group: String,
    val kdf: String,
    val memoryKib: Int,
    val iterations: Int,
    val parallelism: Int,
    val salt: String,
    val verifier: String,
)

/**
 * The two proofs an SRP exchange produces (CONTRACT.md §23.2).
 *
 * [clientProof] goes on the verify request. [expectedServerProof] stays here
 * and is compared against the response's `server_proof`: that comparison is the
 * half of SRP that authenticates the *server*, and §23.3 rule 6 makes it
 * mandatory.
 */
data class SrpProofs(val clientProof: String, val expectedServerProof: String)

/**
 * SRP-6a protocol arithmetic (CONTRACT.md §23).
 *
 * Everything here is pure: no I/O, no client state, no network. The two HTTP
 * calls and the policy around them live in `AxiamClient.loginSrp`.
 *
 * `H` is **SHA-256** throughout. RFC 5054 specifies SHA-1; AXIAM does not use
 * SHA-1 anywhere and does not start here.
 */
object Srp {

    private val random = SecureRandom()

    /**
     * `PAD(v)` — [value] as exactly [byteLength] big-endian bytes
     * (§23.3 rule 1).
     *
     * Skipping this is the classic SRP interop bug: two implementations agree
     * until a value happens to have a leading zero byte, and then roughly one
     * login in 256 fails in a way that reads as a flaky network.
     */
    fun pad(value: BigInteger, byteLength: Int): ByteArray {
        val out = ByteArray(byteLength)
        val raw = value.toByteArray()
        // BigInteger#toByteArray carries a sign byte, and a value wider than
        // the modulus is a caller error rather than something to truncate.
        val from = maxOf(0, raw.size - byteLength)
        val length = raw.size - from
        raw.copyInto(out, byteLength - length, from, raw.size)
        return out
    }

    /** SHA-256 over the concatenation of [parts]. */
    fun hash(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        parts.forEach(digest::update)
        return digest.digest()
    }

    /** [hash] read back as a non-negative big-endian integer. */
    fun hashToInt(vararg parts: ByteArray): BigInteger = BigInteger(1, hash(*parts))

    /** `k = H(N | PAD(g))` — depends only on the group. */
    fun multiplier(group: SrpGroup): BigInteger =
        hashToInt(pad(group.modulus, group.byteLength), pad(group.generator, group.byteLength))

    /**
     * `x = KDF(identity ":" password, salt)`, as raw bytes (§23.3 rule 3).
     *
     * RFC 5054's bare-hash `x` would make a leaked verifier *cheaper* to attack
     * offline than the Argon2id hashes AXIAM stores today, which would make
     * adopting SRP a net regression at rest — so the KDF is memory-hard, and
     * the server dictates which one per exchange.
     *
     * [identity] is the one the server named in the challenge, never what the
     * human typed (§23.3 rule 2).
     *
     * @throws NetworkError if [SrpKdfParams.kdf] is not one this SDK implements.
     */
    fun deriveX(identity: String, password: CharArray, salt: ByteArray, params: SrpKdfParams): ByteArray {
        val secret = "$identity:".toCharArray() + password
        try {
            return when (params.kdf) {
                SrpKdfParams.ARGON2ID -> argon2id(secret, salt, params)
                SrpKdfParams.PBKDF2_SHA256 -> pbkdf2(secret, salt, params)
                // Never substitute the other KDF: it derives a different x and
                // surfaces as "invalid password", the single most misleading
                // failure this code could produce.
                else -> throw NetworkError(
                    "SRP: this SDK does not implement KDF '${params.kdf}'; " +
                        "it implements argon2id and pbkdf2_sha256",
                )
            }
        } finally {
            secret.fill(' ')
        }
    }

    private fun argon2id(secret: CharArray, salt: ByteArray, params: SrpKdfParams): ByteArray {
        // Argon2 takes bytes, and the UTF-8 encoding of the identity is what
        // §23.3 rule 2 pins — which is why the non-ASCII vector exists.
        val utf8 = String(secret).toByteArray(Charsets.UTF_8)
        try {
            val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(maxOf(1, params.iterations))
                .withMemoryAsKB(maxOf(8, params.memoryKib))
                .withParallelism(maxOf(1, params.parallelism))
                .withSalt(salt)
                .build()
            val generator = Argon2BytesGenerator().apply { init(parameters) }
            val out = ByteArray(32)
            generator.generateBytes(utf8, out)
            return out
        } finally {
            utf8.fill(0)
        }
    }

    private fun pbkdf2(secret: CharArray, salt: ByteArray, params: SrpKdfParams): ByteArray {
        // PBEKeySpec's char[] path encodes as UTF-8, which is what the contract
        // pins — the identity's encoding must match the Argon2id path byte for
        // byte, or the two KDFs would disagree about the same account.
        val spec = PBEKeySpec(secret, salt, maxOf(1, params.iterations), 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * `v = g^x mod N` — the verifier the server stores instead of a password
     * hash.
     */
    fun computeVerifier(group: SrpGroup, x: ByteArray): String {
        val reduced = BigInteger(1, x).mod(group.modulus)
        return toHex(pad(group.generator.modPow(reduced, group.modulus), group.byteLength))
    }

    /**
     * 32 fresh bytes from the platform CSPRNG, for an enrolment salt
     * (§23.3 rule 11).
     *
     * A reused salt would make every verifier in a tenant equally attackable
     * with one precomputation.
     */
    fun generateSalt(): ByteArray = ByteArray(32).also(random::nextBytes)

    /**
     * A fresh client ephemeral `a`, at least 256 bits, from the platform
     * CSPRNG (§23.3 rule 7).
     *
     * Reusing `a` across logins leaks the relationship between two session
     * secrets, which is why [SrpClientSession.begin] offers no way to supply
     * one.
     */
    internal fun generateEphemeral(): BigInteger {
        val raw = ByteArray(32).also(random::nextBytes)
        // Set the top bit so a is unambiguously >= 2^255.
        raw[0] = (raw[0].toInt() or 0x80).toByte()
        return BigInteger(1, raw)
    }

    /**
     * Constant-time comparison of the server's `M2` against the expected one
     * (§23.3 rule 6).
     */
    fun verifyServerProof(expected: String, actual: String?): Boolean {
        if (actual == null || actual.length != expected.length) return false
        return MessageDigest.isEqual(
            expected.lowercase().toByteArray(Charsets.US_ASCII),
            actual.lowercase().toByteArray(Charsets.US_ASCII),
        )
    }

    /** Lowercase hex, the encoding every SRP field uses on the wire. */
    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /**
     * Parses a lowercase-hex wire field.
     *
     * @throws NetworkError if [hex] is not valid hex.
     */
    fun fromHex(hex: String, field: String): ByteArray {
        if (hex.length % 2 != 0 || hex.any { it !in "0123456789abcdefABCDEF" }) {
            throw NetworkError("SRP: the server's $field is not valid hex")
        }
        return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
