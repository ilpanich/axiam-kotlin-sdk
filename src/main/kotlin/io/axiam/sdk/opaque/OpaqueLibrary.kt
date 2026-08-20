package io.axiam.sdk.opaque

import com.sun.jna.Native
import io.axiam.sdk.errors.NetworkError

/**
 * Loads `libaxiam_opaque_ffi` once per process, memoizing failure as well as
 * success.
 *
 * Two independent things can be absent, and both are normal:
 *
 * - **JNA.** `net.java.dev.jna:jna` is `compileOnly` here, so it does not reach
 *   a consumer's classpath. A REST/gRPC/AMQP consumer whose tenant does not use
 *   OPAQUE should not be made to carry a native-access library — the same
 *   posture this SDK already takes for Ktor and the RabbitMQ client.
 * - **The shared library.** It is a Rust `cdylib` published as a per-platform
 *   asset of the AXIAM release, not an artifact on Maven Central.
 *
 * Either absence makes [Opaque.available] report `false` rather than throwing,
 * so an application chooses the password path up front instead of discovering
 * the gap mid-login. Memoizing the failure matters as much as memoizing the
 * success: retrying `dlopen` on every login is a per-request filesystem walk
 * for a file that is not going to appear.
 */
internal object OpaqueLibrary {

    /** Overrides the search: an absolute path to the shared library. */
    const val LIBRARY_PROPERTY: String = "axiam.opaque.library"

    /** The environment-variable form of [LIBRARY_PROPERTY]. */
    const val LIBRARY_ENV: String = "AXIAM_OPAQUE_LIBRARY"

    /**
     * The base name JNA expands per platform: `libaxiam_opaque_ffi.so`,
     * `libaxiam_opaque_ffi.dylib`, `axiam_opaque_ffi.dll`.
     */
    private const val LIBRARY_NAME = "axiam_opaque_ffi"

    private val lock = Any()
    private var library: OpaqueNative? = null
    private var attempted = false

    /** The library, or `null` when it — or JNA — is not present. */
    fun load(): OpaqueNative? = synchronized(lock) {
        if (attempted) return library
        attempted = true
        library = attemptLoad()
        library
    }

    private fun attemptLoad(): OpaqueNative? = try {
        val override = System.getProperty(LIBRARY_PROPERTY) ?: System.getenv(LIBRARY_ENV)
        val target = if (override.isNullOrBlank()) LIBRARY_NAME else override
        Native.load(target, OpaqueNative::class.java)
    } catch (_: NoClassDefFoundError) {
        // JNA itself is absent, which is the compileOnly case.
        null
    } catch (_: UnsatisfiedLinkError) {
        // JNA is here and the shared library is not -- or it loaded and is
        // missing our symbols, which means some other library of the same name
        // is on the search path and must be treated as absent rather than
        // called into.
        null
    } catch (_: RuntimeException) {
        null
    }

    /**
     * The library, or a refusal naming the artifact.
     *
     * Never an [io.axiam.sdk.errors.AuthError]: absent is a deployment fact,
     * and reporting it as a credential failure would send a user off to reset a
     * password that works.
     */
    fun require(): OpaqueNative = load() ?: throw NetworkError(
        "OPAQUE is not available: the shared library `libaxiam_opaque_ffi` could not be " +
            "loaded. Download the asset for your platform from the axiam release page, then " +
            "put it on java.library.path or set -D$LIBRARY_PROPERTY=/path/to/it (or the " +
            "$LIBRARY_ENV environment variable). This SDK's `jna` dependency is compileOnly, " +
            "so also check that net.java.dev.jna:jna is on the classpath.",
    )

    /** Installs a binding, bypassing the loader. Test-only. */
    fun setForTests(stub: OpaqueNative?) = synchronized(lock) {
        library = stub
        attempted = true
    }

    /** Forgets the memoized load. Test-only. */
    fun resetForTests() = synchronized(lock) {
        library = null
        attempted = false
    }
}
