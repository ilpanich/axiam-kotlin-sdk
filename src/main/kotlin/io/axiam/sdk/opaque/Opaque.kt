package io.axiam.sdk.opaque

import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import io.axiam.sdk.errors.NetworkError
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

/**
 * Entry points into `libaxiam_opaque_ffi` (CONTRACT.md §23).
 *
 * There is no cryptography in this object, or anywhere in this package. That is
 * deliberate and is what §23.1 requires: OPAQUE needs an oblivious PRF,
 * `hash_to_curve`, `expand_message_xmd`, an envelope construction and a
 * three-message AKE, and eleven independent implementations of that is eleven
 * chances to be subtly and silently wrong. The SRP-6a this replaces was
 * arithmetic every language can express, which is why `io.axiam.sdk.srp`
 * existed.
 */
public object Opaque {

    /**
     * Whether this installation can perform OPAQUE (§23.2).
     *
     * Reports rather than throwing, and is genuinely able to answer `false`:
     * both JNA and the shared library are optional. Ask before a login rather
     * than discovering the gap mid-exchange.
     */
    public fun available(): Boolean {
        val lib = OpaqueLibrary.load() ?: return false
        return lib.axiam_opaque_available() != 0
    }

    /**
     * Blinds [password] to open an enrolment. The returned exchange's
     * `request` goes to `register/start`.
     *
     * @throws NetworkError if the library is unavailable or refuses.
     */
    public fun startRegistration(password: CharArray): RegistrationExchange {
        val lib = OpaqueLibrary.require()
        val encoded = nulTerminatedUtf8(password)
        val out = PointerByReference()
        try {
            val handle = lib.axiam_opaque_registration_start(encoded, out)
                ?: throw NetworkError(
                    "OPAQUE: " + lastError(lib, "registration could not be started"),
                )
            return RegistrationExchange(lib, handle, take(lib, out.value))
        } finally {
            encoded.fill(0)
        }
    }

    /**
     * Blinds [password] to open a login. The returned exchange's `ke1` goes to
     * `login/start`.
     *
     * @throws NetworkError if the library is unavailable or refuses.
     */
    public fun startLogin(password: CharArray): LoginExchange {
        val lib = OpaqueLibrary.require()
        val encoded = nulTerminatedUtf8(password)
        val out = PointerByReference()
        try {
            val handle = lib.axiam_opaque_login_start(encoded, out)
                ?: throw NetworkError("OPAQUE: " + lastError(lib, "login could not be started"))
            return LoginExchange(lib, handle, take(lib, out.value))
        } finally {
            encoded.fill(0)
        }
    }

    /**
     * Takes ownership of a returned string, freeing the Rust allocation.
     *
     * Called on every path that receives one, including the error paths: a
     * binding that frees only on success leaks once per failed login, which is
     * the login rate an installation under attack sees.
     */
    internal fun take(lib: OpaqueNative, ptr: Pointer?): String {
        if (ptr == null) {
            throw NetworkError("OPAQUE: " + lastError(lib, "the library returned no value"))
        }
        try {
            return ptr.getString(0, "UTF-8")
        } finally {
            lib.axiam_opaque_string_free(ptr)
        }
    }

    /**
     * The library's description of the last failure, or [fallback].
     *
     * The returned pointer is borrowed — library-owned, not freed here. A
     * failure with nothing behind it is a library bug, but a caller still
     * deserves a sentence rather than an empty one.
     */
    internal fun lastError(lib: OpaqueNative, fallback: String): String {
        val raw = lib.axiam_opaque_last_error() ?: return fallback
        return raw.getString(0, "UTF-8").ifEmpty { fallback }
    }

    /**
     * Encodes a password as NUL-terminated UTF-8, without an intermediate
     * [String].
     *
     * UTF-8 explicitly rather than through JNA's `String` mapping, which uses
     * the platform charset unless `jna.encoding` says otherwise: a password
     * that encoded differently under a different default locale would derive a
     * randomized password no AXIAM server agrees with, and would surface as a
     * wrong password on that machine only.
     *
     * No `String` because a `String` cannot be cleared. The caller clears the
     * returned array.
     */
    internal fun nulTerminatedUtf8(password: CharArray): ByteArray {
        val encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password))
        val out = ByteArray(encoded.remaining() + 1)
        encoded.get(out, 0, out.size - 1)
        if (encoded.hasArray()) {
            encoded.array().fill(0)
        }
        return out
    }

    /**
     * Encodes a hex protocol message as a NUL-terminated byte array.
     *
     * Separate from [nulTerminatedUtf8] because these are not secrets and need
     * no clearing — and because passing them through the same helper would
     * suggest they do.
     */
    internal fun nulTerminatedAscii(hex: String): ByteArray {
        val raw = hex.toByteArray(StandardCharsets.UTF_8)
        return raw.copyOf(raw.size + 1)
    }
}
