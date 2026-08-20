package io.axiam.sdk.opaque

import com.sun.jna.Pointer
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.NetworkError
import java.lang.ref.Cleaner
import java.util.concurrent.atomic.AtomicReference

/**
 * One in-flight OPAQUE exchange, owning a native state handle.
 *
 * The handle is **single-use**: the library consumes it in `finish` whether
 * that succeeds or fails. This class takes it out of a one-shot slot, so a
 * second `finish` raises a Kotlin exception rather than handing a dangling
 * pointer across the ABI, and registers a [Cleaner] so an exchange the caller
 * abandoned — a login started and never completed — is released rather than
 * leaked. [close] does the same thing deterministically, which is what a caller
 * who knows the exchange is over should use (`use { ... }`).
 */
public sealed class OpaqueExchange protected constructor(
    internal val lib: OpaqueNative,
    handle: Pointer,
    /** The first protocol message, hex — `RegistrationRequest` or `KE1`. */
    internal val firstMessage: String,
    registration: Boolean,
) : AutoCloseable {

    private val state = Handle(lib, handle, registration)

    // The action must not capture `this`, or the Cleaner keeps alive the very
    // object it is meant to notice becoming unreachable.
    private val cleanable: Cleaner.Cleanable = CLEANER.register(this, state)

    /** Spends the handle, or refuses if it is already spent. */
    internal fun consume(): Pointer = state.take()
        ?: throw NetworkError("OPAQUE: this exchange has already been completed")

    /**
     * Releases the exchange if it was never finished. Idempotent, and a no-op
     * once `finish` has spent the handle.
     */
    override fun close() {
        cleanable.clean()
    }

    /** The native handle, in a form the [Cleaner] can hold on its own. */
    private class Handle(
        private val lib: OpaqueNative,
        handle: Pointer,
        private val registration: Boolean,
    ) : Runnable {
        private val slot = AtomicReference<Pointer?>(handle)

        fun take(): Pointer? = slot.getAndSet(null)

        override fun run() {
            val abandoned = take() ?: return
            if (registration) lib.axiam_opaque_registration_free(abandoned)
            else lib.axiam_opaque_login_free(abandoned)
        }
    }

    private companion object {
        private val CLEANER: Cleaner = Cleaner.create()
    }
}

/** One in-flight enrolment (CONTRACT.md §23). */
public class RegistrationExchange internal constructor(
    lib: OpaqueNative,
    handle: Pointer,
    request: String,
) : OpaqueExchange(lib, handle, request, registration = true) {

    /** The hex `RegistrationRequest` to send to `register/start`. */
    public val request: String get() = firstMessage

    /**
     * Seals the envelope under the server's oblivious PRF, returning the hex
     * `RegistrationRecord`.
     *
     * @param password the plaintext being enrolled; every copy this SDK makes
     *   is cleared, but not the caller's.
     * @throws NetworkError if the exchange is already spent, the key-stretching
     *   function is one this SDK cannot ask for, or the library refuses the
     *   response.
     */
    public fun finish(password: CharArray, registrationResponse: String, ksf: KsfParams): String {
        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. `build` refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: `close()` still releases it, and a caller who fixes the
        // parameters can retry.
        val ksfHandle = ksf.build(lib)
        val encoded = Opaque.nulTerminatedUtf8(password)
        try {
            val state = consume()
            val record = lib.axiam_opaque_registration_finish(
                state,
                encoded,
                Opaque.nulTerminatedAscii(registrationResponse),
                ksfHandle,
                null,
            ) ?: throw NetworkError(
                "OPAQUE: " + Opaque.lastError(lib, "the envelope could not be sealed"),
            )
            return Opaque.take(lib, record)
        } finally {
            lib.axiam_opaque_ksf_free(ksfHandle)
            encoded.fill(0)
        }
    }
}

/** One in-flight login (CONTRACT.md §23). */
public class LoginExchange internal constructor(
    lib: OpaqueNative,
    handle: Pointer,
    ke1: String,
) : OpaqueExchange(lib, handle, ke1, registration = false) {

    /** The hex `KE1` to send to `login/start`. */
    public val ke1: String get() = firstMessage

    /**
     * Opens the envelope, producing `KE3`.
     *
     * A failure here is the **whole** of the client's authentication check, and
     * covers both halves of the mutual authentication: the envelope only opens
     * under the right password, and `KE2`'s MAC only verifies if the server
     * actually holds the record. Nothing may be sent afterwards (§23.4 rule 7).
     *
     * That case is an [AuthError], unlike every other `null` return in this
     * package. The distinction is the point: a wrong password, an account that
     * does not exist and a server that does not hold the record are
     * indistinguishable by design and are all authentication failures, whereas
     * a key-stretching function this build cannot perform is a configuration
     * problem, and reporting it as "invalid password" would send an operator
     * looking in the wrong place.
     *
     * @param password the account password; every copy this SDK makes is
     *   cleared, but not the caller's.
     * @throws AuthError when the envelope does not open or `KE2` does not verify.
     * @throws NetworkError if the exchange is already spent, or the
     *   key-stretching function is one this SDK cannot ask for.
     */
    public fun finish(password: CharArray, ke2: String, ksf: KsfParams): String {
        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. `build` refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: `close()` still releases it, and a caller who fixes the
        // parameters can retry.
        val ksfHandle = ksf.build(lib)
        val encoded = Opaque.nulTerminatedUtf8(password)
        try {
            val state = consume()
            val ke3 = lib.axiam_opaque_login_finish(
                state,
                encoded,
                Opaque.nulTerminatedAscii(ke2),
                ksfHandle,
                null,
                null,
            ) ?: throw AuthError(
                "invalid credentials: " +
                    Opaque.lastError(lib, "the OPAQUE envelope did not open"),
            )
            return Opaque.take(lib, ke3)
        } finally {
            lib.axiam_opaque_ksf_free(ksfHandle)
            encoded.fill(0)
        }
    }
}
