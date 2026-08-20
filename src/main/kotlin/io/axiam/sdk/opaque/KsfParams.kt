package io.axiam.sdk.opaque

import com.sun.jna.Pointer
import io.axiam.sdk.errors.NetworkError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive

/**
 * The key-stretching function and cost a `/start` response names (CONTRACT.md
 * §23.4).
 *
 * Fields are nullable on purpose: they arrive flat, and a field that does not
 * apply to the named function is **absent, not zero**. Reading a missing
 * [memoryKib] as `0` would stretch at the wrong cost and fail against a record
 * that is perfectly good (§23.4 rule 5).
 *
 * These are never cached across exchanges and never defaulted locally. A
 * credential enrolled under one cost keeps working after a tenant raises its
 * policy, so a client that guessed would derive a different randomized password
 * and report "invalid password" for one that is entirely correct (§23.4 rule 2).
 *
 * @property ksf the wire name of the function: `argon2id` or `scrypt`.
 * @property memoryKib Argon2id's memory cost in KiB.
 * @property iterations Argon2id's time cost.
 * @property parallelism Argon2id's lane count.
 * @property logN scrypt's base-2 CPU/memory cost.
 * @property r scrypt's block size.
 * @property p scrypt's parallelisation parameter.
 */
public data class KsfParams(
    val ksf: String,
    val memoryKib: Int? = null,
    val iterations: Int? = null,
    val parallelism: Int? = null,
    val logN: Int? = null,
    val r: Int? = null,
    val p: Int? = null,
) {
    public companion object {
        /** The wire name of the memory-hard function AXIAM asks for by default. */
        public const val ARGON2ID: String = "argon2id"

        /** The wire name of the alternative AXIAM accepts. */
        public const val SCRYPT: String = "scrypt"

        /**
         * Reads the flat key-stretching fields of a `/start` response,
         * preserving absence.
         */
        public fun fromWire(wire: JsonObject): KsfParams = KsfParams(
            ksf = wire["ksf"]?.jsonPrimitive?.content ?: "",
            memoryKib = wire["memory_kib"]?.jsonPrimitive?.int,
            iterations = wire["iterations"]?.jsonPrimitive?.int,
            parallelism = wire["parallelism"]?.jsonPrimitive?.int,
            logN = wire["log_n"]?.jsonPrimitive?.int,
            r = wire["r"]?.jsonPrimitive?.int,
            p = wire["p"]?.jsonPrimitive?.int,
        )
    }

    /**
     * Builds the library's key-stretching handle from what the *server* named.
     *
     * An unrecognised function is refused, never substituted: substituting
     * produces a well-formed randomized password no AXIAM server agrees with,
     * which surfaces to the user as a wrong password (§23.4 rule 3).
     *
     * The returned handle must be released with `ksf_free`.
     */
    internal fun build(lib: OpaqueNative): Pointer {
        val handle = when (ksf) {
            ARGON2ID -> lib.axiam_opaque_ksf_argon2id(
                require("memory_kib", memoryKib, 8192, 1_048_576),
                require("iterations", iterations, 1, 10),
                require("parallelism", parallelism, 1, 16),
            )
            SCRYPT -> lib.axiam_opaque_ksf_scrypt(
                require("log_n", logN, 14, 20).toByte(),
                require("r", r, 1, 16),
                require("p", p, 1, 16),
            )
            else -> throw NetworkError(
                "OPAQUE: this SDK cannot perform the key-stretching function the server " +
                    "named (`$ksf`)",
            )
        }
        return handle ?: throw NetworkError(
            "OPAQUE: " + Opaque.lastError(lib, "invalid KSF parameters"),
        )
    }

    /**
     * One cost the named function needs: present, and inside the band this SDK
     * will act on.
     *
     * A server is trusted to name its own policy, not to name a cost that would
     * wedge every device an account owns. The library range-checks too; doing it
     * here as well means the refusal names the field.
     */
    private fun require(field: String, value: Int?, low: Int, high: Int): Int {
        if (value == null) {
            throw NetworkError("OPAQUE: the server named ksf `$ksf` without `$field`")
        }
        if (value < low || value > high) {
            throw NetworkError(
                "OPAQUE: the server named $field=$value for `$ksf`, outside the accepted " +
                    "$low..$high",
            )
        }
        return value
    }
}
