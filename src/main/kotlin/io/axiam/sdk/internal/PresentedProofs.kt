package io.axiam.sdk.internal

/**
 * What the caller proved about **this** connection and **this** request, for
 * [JwksVerifier.verifyTokenBinding].
 *
 * A data class rather than two string parameters on purpose: two same-typed
 * nullable thumbprints are exactly the pair a positional call transposes
 * silently, and transposing them would check each proof against the wrong
 * confirmation.
 *
 * @property certificateThumbprint the peer certificate's RFC 8705 `x5t#S256`,
 *   taken from the TLS connection or from a *trusted* terminating proxy over a
 *   channel your application controls — **never** from a caller-settable
 *   header, which would make the whole mechanism decorative.
 * @property dpopThumbprint the `jkt` of an **already verified** DPoP proof.
 *   Supply it only after checking the proof's signature, `htm`, `htu`, `iat`
 *   and `jti` for this request — [DpopVerifier.verifyProof] does all ten
 *   §21.7.2 checks and returns exactly this value. A thumbprint lifted off an
 *   unverified proof would let a proof captured from any other endpoint
 *   authorize this one.
 */
data class PresentedProofs(
    val certificateThumbprint: String? = null,
    val dpopThumbprint: String? = null,
) {
    companion object {
        /** Neither proof — the ordinary bearer case. */
        fun none(): PresentedProofs = PresentedProofs()

        /** Only a client certificate was presented. */
        fun certificate(thumbprint: String): PresentedProofs =
            PresentedProofs(certificateThumbprint = thumbprint)

        /** Only a verified DPoP proof was presented. */
        fun dpop(thumbprint: String): PresentedProofs =
            PresentedProofs(dpopThumbprint = thumbprint)
    }
}
