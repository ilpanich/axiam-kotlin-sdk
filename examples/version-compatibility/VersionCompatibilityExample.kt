package io.axiam.sdk.examples.versioncompatibility

import io.axiam.sdk.SupportedVersions

/**
 * Reports the running JVM and the compiling Kotlin against the ranges this SDK
 * is built and tested against. Imports ONLY public SDK entry points.
 *
 * This SDK has two version axes, and each behaves the same way: the floor
 * enforces itself, the ceiling does not.
 *
 * - **JVM** — a JVM older than [SupportedVersions.MIN_JVM_TARGET] refuses to
 *   load the SDK's class files at all, with `UnsupportedClassVersionError`.
 *   Nothing stops those class files from loading on a much newer JVM, though,
 *   and a removed internal or a strengthened module boundary shows up only at
 *   execution.
 * - **Kotlin** — a compiler older than [SupportedVersions.MIN_KOTLIN_VERSION]
 *   cannot read the SDK's `@Metadata` and fails the consumer's build. Nothing
 *   stops a much newer compiler from reading it, and metadata that a future
 *   compiler mis-reads fails the same way.
 *
 * So the useful half of this check is the upper one, on both axes: it reports
 * when you are past everything a green build covers. That is not an error — the
 * SDK is expected to work there — but it is worth knowing before you go looking
 * for a bug that is really a version gap.
 *
 * Run (from the repo root):
 * ```
 * kotlinc -classpath build/libs/axiam-sdk-kotlin-*.jar \
 *   examples/version-compatibility/VersionCompatibilityExample.kt -include-runtime -d vc.jar
 * java -jar vc.jar
 * ```
 */
object VersionCompatibilityExample {

    @JvmStatic
    fun main(args: Array<String>) {
        val runningJvm = Runtime.version().feature()

        // KotlinVersion.CURRENT is the version of the compiler that built THIS
        // file, not the one that built the SDK — which is the point: it is the
        // consumer's compiler, and the forward-compatibility question is
        // whether it can read the SDK's metadata.
        val compilingKotlin = KotlinVersion.CURRENT

        println("running JVM:          $runningJvm (${System.getProperty("java.vm.name")})")
        println("compiling Kotlin:     $compilingKotlin")
        println("SDK JVM target:       ${SupportedVersions.MIN_JVM_TARGET}")
        println("newest tested JVM:    ${SupportedVersions.NEWEST_TESTED_JVM}")
        println("SDK published Kotlin: ${SupportedVersions.MIN_KOTLIN_VERSION}")
        println("newest tested Kotlin: ${SupportedVersions.NEWEST_TESTED_KOTLIN}")

        var untested = false

        when {
            runningJvm < SupportedVersions.MIN_JVM_TARGET -> {
                // Practically unreachable — this class could not have loaded.
                System.err.println(
                    "UNSUPPORTED: JVM $runningJvm is below the SDK's JVM " +
                        "${SupportedVersions.MIN_JVM_TARGET} bytecode level.",
                )
                kotlin.system.exitProcess(1)
            }

            runningJvm > SupportedVersions.NEWEST_TESTED_JVM -> {
                println(
                    "UNTESTED (JVM): $runningJvm is newer than " +
                        "${SupportedVersions.NEWEST_TESTED_JVM}, the newest runtime with a " +
                        "green build. Expected to work, not yet proven.",
                )
                untested = true
            }

            else -> println("SUPPORTED (JVM): $runningJvm is inside the tested range.")
        }

        val newestTestedKotlin = parseKotlinVersion(SupportedVersions.NEWEST_TESTED_KOTLIN)
        if (compilingKotlin > newestTestedKotlin) {
            println(
                "UNTESTED (Kotlin): $compilingKotlin is newer than " +
                    "${SupportedVersions.NEWEST_TESTED_KOTLIN}, the newest compiler the SDK's " +
                    "sources are built with. Metadata is forward-compatible, so this is " +
                    "expected to work.",
            )
            untested = true
        } else {
            println("SUPPORTED (Kotlin): $compilingKotlin is inside the tested range.")
        }

        if (!untested) {
            println("Both axes are inside a range covered by a green build.")
        }
    }

    /** Parses a `major.minor.patch` string into a comparable [KotlinVersion]. */
    private fun parseKotlinVersion(version: String): KotlinVersion {
        val parts = version.split('.').mapNotNull(String::toIntOrNull)
        require(parts.size >= 2) { "cannot parse \"$version\" as a Kotlin version" }
        return KotlinVersion(parts[0], parts[1], parts.getOrElse(2) { 0 })
    }
}
