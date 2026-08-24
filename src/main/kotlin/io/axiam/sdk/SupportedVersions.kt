package io.axiam.sdk

/**
 * The range of Kotlin and JVM versions this SDK is built and tested against.
 *
 * This SDK has two independent version axes, and each has a floor and a newest:
 *
 * - **JVM** — the SDK emits [MIN_JVM_TARGET] bytecode and is additionally *run*
 *   against [NEWEST_TESTED_JVM]. The bytecode level enforces the lower bound by
 *   itself: an older JVM refuses to load the class files at all. Nothing
 *   enforces the upper one — those class files load happily on a much newer JVM
 *   whether or not anybody ever ran them there.
 *
 * - **Kotlin** — the SDK is *published* compiled by [MIN_KOTLIN_VERSION] and is
 *   additionally *compiled* by [NEWEST_TESTED_KOTLIN]. Kotlin metadata is
 *   forward-compatible, so a library built with 2.1 can be consumed by any
 *   later compiler; compiling with a newer one instead raises the floor for
 *   every consumer below it. The published compiler therefore stays at the
 *   floor, and the newest leg proves the forward direction still holds.
 *
 * Both floors are the versions a consumer must at least have. Both "newest"
 * values are the versions a green build actually covers — beyond them the SDK
 * is expected to work but is not yet proven.
 *
 * `VersionPolicyTest` asserts every one of these against `build.gradle.kts`,
 * `gradle.properties` and the CI matrix, so none of them can go stale.
 *
 * @see <a href="https://github.com/ilpanich/axiam-kotlin-sdk#supported-kotlin-and-jvm-versions">Supported Kotlin and JVM versions</a>
 */
public object SupportedVersions {

    /**
     * The minimum JVM feature version required to run this SDK.
     *
     * Mirrors `jvmTarget` in `build.gradle.kts`. A JVM older than this fails
     * with `UnsupportedClassVersionError` at class-load time.
     */
    public const val MIN_JVM_TARGET: Int = 17

    /**
     * The newest JVM feature version this SDK has a green build against.
     *
     * Mirrors the upper CI leg, where the JVM 17 bytecode is executed on a
     * JDK 25 runtime.
     */
    public const val NEWEST_TESTED_JVM: Int = 25

    /**
     * The Kotlin compiler version this SDK is published with, and therefore the
     * minimum a consumer's compiler must be.
     *
     * Mirrors `kotlinVersion` in `gradle.properties`. A consumer on an older
     * Kotlin cannot read this library's `@Metadata` and fails at compile time.
     */
    public const val MIN_KOTLIN_VERSION: String = "2.1.0"

    /**
     * The newest Kotlin compiler this SDK's sources are known to compile under.
     *
     * Mirrors the upper CI leg. This is the forward-compatibility claim: a
     * consumer on this Kotlin can build against the published artifact.
     */
    public const val NEWEST_TESTED_KOTLIN: String = "2.4.10"
}
