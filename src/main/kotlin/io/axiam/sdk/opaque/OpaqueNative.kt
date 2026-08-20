package io.axiam.sdk.opaque

import com.sun.jna.Library
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference

/**
 * The `libaxiam_opaque_ffi` C ABI, exactly as `include/axiam/opaque.h` declares
 * it.
 *
 * An interface rather than a set of external functions for two reasons. It is
 * what JNA binds, and — less obviously but more usefully — it is what a test
 * can implement in plain Kotlin. The contract this ABI carries is about
 * *ownership*: who frees a returned string, when a state handle is spent, what
 * a `null` means. Those are the rules a binding gets wrong, and they can be
 * exercised exhaustively against a stand-in without the real shared library
 * present.
 *
 * Strings cross as [ByteArray], NUL-terminated and UTF-8, never as [String].
 * JNA's `String` mapping encodes with the platform charset unless
 * `jna.encoding` is set, and a password that round-tripped differently on a
 * machine with a different default locale would produce a randomized password
 * no AXIAM server agrees with — surfacing as a wrong password on that machine
 * only. The conformance vectors require UTF-8.
 */
internal interface OpaqueNative : Library {

    /** Releases a string this library returned. Rust allocated it; Rust frees it. */
    fun axiam_opaque_string_free(ptr: Pointer)

    /** Describes the last failure. The pointer is borrowed — library-owned, never freed here. */
    fun axiam_opaque_last_error(): Pointer?

    /** Nonzero when this build can perform OPAQUE. */
    fun axiam_opaque_available(): Int

    /** Builds an Argon2id handle, or returns `null` when the parameters are refused. */
    fun axiam_opaque_ksf_argon2id(memoryKib: Int, iterations: Int, parallelism: Int): Pointer?

    /** Builds a scrypt handle, or returns `null` when the parameters are refused. */
    fun axiam_opaque_ksf_scrypt(logN: Byte, r: Int, p: Int): Pointer?

    /** Releases a key-stretching handle. */
    fun axiam_opaque_ksf_free(ptr: Pointer)

    /** Begins an enrolment, writing the hex `RegistrationRequest` to [outRequest]. */
    fun axiam_opaque_registration_start(password: ByteArray, outRequest: PointerByReference): Pointer?

    /**
     * Completes an enrolment, **consuming** [state] whether it succeeds or
     * fails. Returns the hex `RegistrationRecord`, or `null`.
     */
    fun axiam_opaque_registration_finish(
        state: Pointer,
        password: ByteArray,
        registrationResponse: ByteArray,
        ksf: Pointer,
        outExportKey: PointerByReference?,
    ): Pointer?

    /** Releases enrolment state that was never finished. */
    fun axiam_opaque_registration_free(ptr: Pointer)

    /** Begins a login, writing the hex `KE1` to [outKe1]. */
    fun axiam_opaque_login_start(password: ByteArray, outKe1: PointerByReference): Pointer?

    /**
     * Completes a login, **consuming** [state]. Returns the hex `KE3`, or
     * `null`.
     *
     * A `null` return is the whole of the client's authentication check, and it
     * covers both halves of the mutual authentication: the envelope only opens
     * under the right password, and `KE2`'s MAC only verifies if the server
     * actually holds the record. Per CONTRACT.md §23.4 rule 7 nothing may be
     * sent to `login/finish` after it.
     */
    fun axiam_opaque_login_finish(
        state: Pointer,
        password: ByteArray,
        ke2: ByteArray,
        ksf: Pointer,
        outSessionKey: PointerByReference?,
        outExportKey: PointerByReference?,
    ): Pointer?

    /** Releases login state that was never finished. */
    fun axiam_opaque_login_free(ptr: Pointer)
}
