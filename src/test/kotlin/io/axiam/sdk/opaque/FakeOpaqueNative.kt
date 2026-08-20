package io.axiam.sdk.opaque

import com.sun.jna.Memory
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference

/**
 * An in-process stand-in for `libaxiam_opaque_ffi`.
 *
 * CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no
 * cryptography to test. What there is — and what this fake exists to exercise —
 * is the ABI's *contract*:
 *
 * - every returned string is heap-allocated and must be freed exactly once with
 *   `string_free`;
 * - a state handle is CONSUMED by its `finish`, success or failure;
 * - a `null` return means failure, described by `last_error`.
 *
 * Requiring the real shared library would give a suite that runs only where a
 * per-platform release asset happens to be installed — and it would be testing
 * `opaque-ke` rather than this binding. Cross-implementation agreement is
 * verified upstream by the conformance vectors.
 *
 * Every value it returns is hex, as the real ABI's are: a fake that handed back
 * raw bytes would let a binding bug survive.
 */
internal class FakeOpaqueNative : OpaqueNative {

    private val allocations = mutableMapOf<Long, Memory>()
    private val states = mutableMapOf<Long, String>()
    private val failing = mutableSetOf<String>()
    private val failMessages = mutableMapOf<String, String>()

    private var nextHandle = 0x1000L
    private var lastError = ""
    private var lastErrorBuffer: Memory? = null

    /** Addresses passed to `string_free`, in order. A leak never appears here; a double free appears twice. */
    val freed: MutableList<Long> = mutableListOf()

    /** Key-stretching handles built and not yet released. Must be zero after any `finish`. */
    var ksfAlive: Int = 0
        private set

    /** What `axiam_opaque_available` answers. */
    var availableValue: Int = 1

    /** State handles neither consumed nor released. */
    val statesAlive: Int get() = states.size

    /** Allocations handed out and never freed. */
    val allocationsAlive: Int get() = allocations.size

    /** Makes an entry point return `null` instead of working. */
    fun fail(entryPoint: String) {
        failing += entryPoint
    }

    /**
     * Overrides what `last_error` reports for a failing entry point. An empty
     * string models a library that failed without saying why — a bug, but one
     * the binding still has to produce a sentence for.
     */
    fun failMessage(entryPoint: String, message: String) {
        failMessages[entryPoint] = message
    }

    // -- helpers -------------------------------------------------------

    private fun allocateHex(payload: String): Pointer {
        val hex = payload.toByteArray(Charsets.UTF_8)
            .joinToString("") { "%02x".format(it) }
            .toByteArray(Charsets.UTF_8)
        val memory = Memory(hex.size + 1L)
        memory.write(0, hex, 0, hex.size)
        memory.setByte(hex.size.toLong(), 0)
        allocations[Pointer.nativeValue(memory)] = memory
        return memory
    }

    private fun read(nulTerminated: ByteArray): String {
        var length = nulTerminated.size
        while (length > 0 && nulTerminated[length - 1] == 0.toByte()) length--
        return String(nulTerminated, 0, length, Charsets.UTF_8)
    }

    private fun newState(kind: String): Pointer {
        nextHandle += 0x10
        states[nextHandle] = kind
        return Pointer(nextHandle)
    }

    private fun consume(handle: Pointer, kind: String) {
        val address = Pointer.nativeValue(handle)
        val actual = states.remove(address)
        check(actual == kind) {
            "handle 0x${address.toString(16)} was not a live $kind (was $actual)"
        }
    }

    private fun failed(entryPoint: String, message: String): Boolean {
        if (entryPoint !in failing) return false
        lastError = failMessages[entryPoint] ?: message
        return true
    }

    // -- the ABI -------------------------------------------------------

    override fun axiam_opaque_string_free(ptr: Pointer) {
        val address = Pointer.nativeValue(ptr)
        checkNotNull(allocations.remove(address)) {
            "free of 0x${address.toString(16)}, which this library never allocated (or already freed)"
        }
        freed += address
    }

    override fun axiam_opaque_last_error(): Pointer? {
        if (lastError.isEmpty()) return null
        val raw = lastError.toByteArray(Charsets.UTF_8)
        // Borrowed, not freed by the caller -- so it is held here rather than
        // registered as an allocation.
        val buffer = Memory(raw.size + 1L)
        buffer.write(0, raw, 0, raw.size)
        buffer.setByte(raw.size.toLong(), 0)
        lastErrorBuffer = buffer
        return buffer
    }

    override fun axiam_opaque_available(): Int = availableValue

    override fun axiam_opaque_ksf_argon2id(memoryKib: Int, iterations: Int, parallelism: Int): Pointer? {
        if (failed("ksf_argon2id", "argon2id parameters rejected")) return null
        ksfAlive++
        return Pointer(0xA0000L + memoryKib + iterations + parallelism)
    }

    override fun axiam_opaque_ksf_scrypt(logN: Byte, r: Int, p: Int): Pointer? {
        if (failed("ksf_scrypt", "scrypt parameters rejected")) return null
        ksfAlive++
        return Pointer(0xB0000L + logN + r + p)
    }

    override fun axiam_opaque_ksf_free(ptr: Pointer) {
        ksfAlive--
    }

    override fun axiam_opaque_registration_start(
        password: ByteArray,
        outRequest: PointerByReference,
    ): Pointer? {
        if (failed("registration_start", "registration could not be started")) return null
        outRequest.value = allocateHex("req:" + read(password))
        return newState("registration")
    }

    override fun axiam_opaque_registration_finish(
        state: Pointer,
        password: ByteArray,
        registrationResponse: ByteArray,
        ksf: Pointer,
        outExportKey: PointerByReference?,
    ): Pointer? {
        consume(state, "registration")
        if (failed("registration_finish", "the envelope could not be sealed")) return null
        return allocateHex(
            "record:${read(password)}:${read(registrationResponse)}:" +
                Pointer.nativeValue(ksf).toString(16),
        )
    }

    override fun axiam_opaque_registration_free(ptr: Pointer) = consume(ptr, "registration")

    override fun axiam_opaque_login_start(password: ByteArray, outKe1: PointerByReference): Pointer? {
        if (failed("login_start", "login could not be started")) return null
        outKe1.value = allocateHex("ke1:" + read(password))
        return newState("login")
    }

    override fun axiam_opaque_login_finish(
        state: Pointer,
        password: ByteArray,
        ke2: ByteArray,
        ksf: Pointer,
        outSessionKey: PointerByReference?,
        outExportKey: PointerByReference?,
    ): Pointer? {
        consume(state, "login")
        if (failed("login_finish", "the envelope did not open")) return null
        return allocateHex(
            "ke3:${read(password)}:${read(ke2)}:" + Pointer.nativeValue(ksf).toString(16),
        )
    }

    override fun axiam_opaque_login_free(ptr: Pointer) = consume(ptr, "login")
}

/** Decodes one of [FakeOpaqueNative]'s hex payloads. */
internal fun decodeHex(hex: String): String =
    String(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), Charsets.UTF_8)

/** Installs a fake library and returns it for configuration. */
internal fun installFakeOpaque(): FakeOpaqueNative =
    FakeOpaqueNative().also { OpaqueLibrary.setForTests(it) }

/**
 * Installs "no library at all" — the state of an installation that never
 * downloaded the artifact, or that lacks JNA.
 */
internal fun installAbsentOpaque() = OpaqueLibrary.setForTests(null)

/** Restores the real loader. */
internal fun resetOpaque() = OpaqueLibrary.resetForTests()
