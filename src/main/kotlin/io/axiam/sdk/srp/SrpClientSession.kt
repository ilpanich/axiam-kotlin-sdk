package io.axiam.sdk.srp

import io.axiam.sdk.errors.NetworkError
import java.math.BigInteger

/**
 * One SRP exchange's client half: the ephemeral secret `a` held between the
 * challenge request and the proof that answers it (CONTRACT.md §23.2).
 *
 * A session is single-use. `a` is drawn fresh per exchange and there is no way
 * to supply one through [begin], because reusing it across logins leaks the
 * relationship between two session secrets (§23.3 rule 7).
 */
class SrpClientSession private constructor(
    /** The group this exchange runs in. */
    val group: SrpGroup,
    private val ephemeral: BigInteger,
) {

    /** `A = g^a mod N`, lowercase hex — sent with the challenge request. */
    val clientPublic: String =
        Srp.toHex(Srp.pad(group.generator.modPow(ephemeral, group.modulus), group.byteLength))

    /**
     * Completes the exchange: `S`, `K`, `M1` and the `M2` the server must
     * return.
     *
     * @param identity the identity from the challenge response, never what the
     *   user typed (§23.3 rule 2).
     * @param saltHex the `salt` field of the challenge response.
     * @param serverPublicHex the `b_pub` field of the challenge response.
     * @param x the KDF output from [Srp.deriveX].
     * @throws NetworkError if `B mod N == 0`, if `u` would be zero, or if a hex
     *   field is malformed.
     */
    fun finish(identity: String, saltHex: String, serverPublicHex: String, x: ByteArray): SrpProofs {
        val salt = Srp.fromHex(saltHex, "salt")
        val n = group.modulus
        val serverPublic = BigInteger(1, Srp.fromHex(serverPublicHex, "b_pub"))

        // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable
        // and the exchange would authenticate against a server that never knew
        // the verifier. A broken or hostile server, not a wrong password.
        if (serverPublic.mod(n).signum() == 0) {
            throw NetworkError("SRP: the server sent an invalid public value (B mod N == 0)")
        }

        val paddedA = Srp.fromHex(clientPublic, "client_public")
        val paddedB = Srp.pad(serverPublic, group.byteLength)

        // u = H(PAD(A) | PAD(B))
        val u = Srp.hashToInt(paddedA, paddedB)
        if (u.signum() == 0) {
            throw NetworkError("SRP: the server's parameters produce u == 0")
        }

        val xInt = BigInteger(1, x).mod(n)
        val k = Srp.multiplier(group)

        // S = (B - k*g^x)^(a + u*x) mod N
        val kgx = k.multiply(group.generator.modPow(xInt, n)).mod(n)
        val base = serverPublic.mod(n).subtract(kgx).mod(n)
        val sharedSecret = base.modPow(ephemeral.add(u.multiply(xInt)), n)

        val paddedS = Srp.pad(sharedSecret, group.byteLength)
        val sessionKey = Srp.hash(paddedS)
        try {
            // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
            val hn = Srp.hash(Srp.pad(n, group.byteLength))
            val hg = Srp.hash(Srp.pad(group.generator, group.byteLength))
            val hxor = ByteArray(hn.size) { (hn[it].toInt() xor hg[it].toInt()).toByte() }
            val hi = Srp.hash(identity.toByteArray(Charsets.UTF_8))
            val m1 = Srp.hash(hxor, hi, salt, paddedA, paddedB, sessionKey)

            // M2 = H(PAD(A) | M1 | K)
            return SrpProofs(Srp.toHex(m1), Srp.toHex(Srp.hash(paddedA, m1, sessionKey)))
        } finally {
            // §23.3 rule 8: clear what can be cleared.
            paddedS.fill(0)
            sessionKey.fill(0)
        }
    }

    companion object {
        /**
         * Starts an exchange in [group]: draws a fresh `a` and computes
         * `A = g^a mod N`.
         */
        fun begin(group: SrpGroup): SrpClientSession = SrpClientSession(group, Srp.generateEphemeral())

        /**
         * Starts an exchange with `a` pinned to a supplied value.
         *
         * For the §23.7 cross-language vectors **only**: they fix `a` so every
         * intermediate is reproducible. Never call this from application code —
         * a predictable `a` defeats the protocol.
         */
        fun withFixedEphemeral(group: SrpGroup, ephemeral: BigInteger): SrpClientSession =
            SrpClientSession(group, ephemeral)
    }
}
