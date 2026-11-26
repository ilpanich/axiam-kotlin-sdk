package io.axiam.sdk

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Language-version support policy — both axes.
 *
 * "Which versions does this SDK support?" is declared across four files that
 * nothing compares:
 *
 * - `jvmTarget` in `build.gradle.kts` — the bytecode level in every class file;
 * - `kotlinFloor` in `gradle.properties` — the Kotlin the published
 *   `@Metadata` and `kotlin-stdlib` dependency are pinned to (the compiler
 *   that runs the build, `kotlinVersion`, is a separate and newer build tool);
 * - the `include:` matrix in `.github/workflows/sdk-ci-kotlin.yml` — the only
 *   declaration that is ever executed;
 * - [SupportedVersions] — the only one a consumer can read.
 *
 * Before this test existed, CI ran one JDK (17) and one Kotlin (2.1.0). The
 * build file even claimed the wider range in a comment — *"a strict
 * toolchain(17) is intentionally NOT pinned so the build runs on either JDK 17
 * or a newer JDK"* — which was true, untested, and had no way of becoming
 * false loudly.
 *
 * Both floors enforce themselves downward and neither enforces itself upward.
 * An old JVM refuses to load the class files; an old Kotlin compiler refuses to
 * read the metadata. But JVM 17 bytecode loads on JDK 27 whether or not anybody
 * ran it there, and 2.2-compiled metadata is read by a 2.4 compiler whether or
 * not anybody ever compiled against it. The upper half of both claims is
 * exactly what the newest CI leg exists to prove.
 */
class VersionPolicyTest {

    private companion object {
        /** `jvmTarget.set(JvmTarget.JVM_17)` in build.gradle.kts. */
        val JVM_TARGET = Regex("""JvmTarget\.JVM_(\d+)""")

        /** `kotlinFloor=2.2.21` in gradle.properties. */
        val KOTLIN_FLOOR = Regex("""(?m)^kotlinFloor=(.+)$""")

        /** `java: '17'` inside the CI matrix's include: entries. */
        val CI_JAVA = Regex("""(?m)^\s*java:\s*'([^']+)'\s*$""")

        /** `kotlin: '2.2.21'` inside the CI matrix's include: entries. */
        val CI_KOTLIN = Regex("""(?m)^\s*kotlin:\s*'([^']+)'\s*$""")
    }

    /**
     * Walks up from the working directory to the project root. Gradle runs
     * tests with the project directory as the working directory, so this
     * normally succeeds immediately.
     */
    private fun repoRoot(): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            if (File(dir, "settings.gradle.kts").isFile && File(dir, ".github").isDirectory) {
                return dir
            }
            dir = dir.parentFile
        }
        error("could not locate the project root from ${File("").absolutePath}")
    }

    private fun read(relative: String): String = File(repoRoot(), relative).readText()

    /** The bytecode level declared in build.gradle.kts. */
    private fun declaredJvmTarget(): Int {
        val match = JVM_TARGET.find(read("build.gradle.kts"))
        assertTrue(match != null, "build.gradle.kts declares no JvmTarget.JVM_<n>")
        return match!!.groupValues[1].toInt()
    }

    /** The Kotlin floor the artifact is published against, from gradle.properties. */
    private fun declaredKotlinFloor(): String {
        val match = KOTLIN_FLOOR.find(read("gradle.properties"))
        assertTrue(match != null, "gradle.properties declares no kotlinFloor")
        return match!!.groupValues[1].trim()
    }

    private fun ciJavaLegs(): List<Int> =
        CI_JAVA.findAll(read(".github/workflows/sdk-ci-kotlin.yml"))
            .map { it.groupValues[1].toInt() }
            .toList()
            .sorted()

    private fun ciKotlinLegs(): List<String> =
        CI_KOTLIN.findAll(read(".github/workflows/sdk-ci-kotlin.yml"))
            .map { it.groupValues[1] }
            .toList()

    @Test
    fun `MIN_JVM_TARGET matches the jvmTarget the build actually emits`() {
        assertEquals(
            declaredJvmTarget(),
            SupportedVersions.MIN_JVM_TARGET,
            "SupportedVersions.MIN_JVM_TARGET has drifted from build.gradle.kts's jvmTarget",
        )
    }

    @Test
    fun `MIN_KOTLIN_VERSION matches the Kotlin floor the artifact is published against`() {
        assertEquals(
            declaredKotlinFloor(),
            SupportedVersions.MIN_KOTLIN_VERSION,
            "SupportedVersions.MIN_KOTLIN_VERSION has drifted from gradle.properties",
        )
    }

    @Test
    fun `CI runs the JVM floor, so the bytecode level is a promise something keeps`() {
        val floor = declaredJvmTarget()
        assertTrue(
            ciJavaLegs().contains(floor),
            "the build emits JVM $floor bytecode but no CI leg runs that JDK: ${ciJavaLegs()}",
        )
    }

    @Test
    fun `CI compiles with the floor Kotlin, not only a newer one`() {
        val floor = declaredKotlinFloor()
        assertTrue(
            ciKotlinLegs().contains(floor),
            "the artifact is published against Kotlin $floor but no CI leg compiles with it: ${ciKotlinLegs()}",
        )
    }

    @Test
    fun `the compiled metadata is the floor's, whichever compiler wrote it`() {
        // The build compiles with the newest Kotlin plugin but pins
        // languageVersion to the floor, which is what decides the @Metadata
        // version a consumer's compiler must be able to read. Read it back from
        // a class this build produced rather than trusting the build script.
        val metadata = SupportedVersions::class.java.getAnnotation(Metadata::class.java)
        val written = metadata.metadataVersion.take(2).joinToString(".")
        assertEquals(
            SupportedVersions.MIN_KOTLIN_VERSION.substringBeforeLast('.'),
            written,
            "the SDK's classes carry Kotlin $written metadata, not the floor's — " +
                "consumers on ${SupportedVersions.MIN_KOTLIN_VERSION} could not read them",
        )
    }

    @Test
    fun `the kotlin-stdlib on the classpath is the floor's`() {
        // coreLibrariesVersion pins the stdlib the POM declares to the floor. A
        // newer one here means a dependency dragged it up, which would raise the
        // floor for every consumer at resolution time.
        assertEquals(
            SupportedVersions.MIN_KOTLIN_VERSION,
            KotlinVersion.CURRENT.toString(),
            "kotlin-stdlib ${KotlinVersion.CURRENT} is on the classpath, not the floor's",
        )
    }

    @Test
    fun `the CI matrix is exactly two legs, floor and newest, on both axes`() {
        val javaLegs = ciJavaLegs()
        val kotlinLegs = ciKotlinLegs()

        assertEquals(2, javaLegs.size, "expected exactly 2 JDK legs, got $javaLegs")
        assertEquals(2, kotlinLegs.size, "expected exactly 2 Kotlin legs, got $kotlinLegs")

        assertEquals(
            SupportedVersions.MIN_JVM_TARGET,
            javaLegs.first(),
            "the lower JDK leg is not the declared jvmTarget",
        )
        assertEquals(
            SupportedVersions.NEWEST_TESTED_JVM,
            javaLegs.last(),
            "the upper JDK leg does not match SupportedVersions.NEWEST_TESTED_JVM",
        )
        assertEquals(
            SupportedVersions.MIN_KOTLIN_VERSION,
            kotlinLegs.first(),
            "the first Kotlin leg is not the declared Kotlin floor",
        )
        assertEquals(
            SupportedVersions.NEWEST_TESTED_KOTLIN,
            kotlinLegs.last(),
            "the second Kotlin leg does not match SupportedVersions.NEWEST_TESTED_KOTLIN",
        )
    }

    @Test
    fun `no CI leg runs a JVM too old to load the SDK`() {
        val floor = declaredJvmTarget()
        ciJavaLegs().forEach { leg ->
            assertTrue(
                leg >= floor,
                "CI runs JDK $leg, below the JVM $floor bytecode level — that JVM cannot load the SDK",
            )
        }
    }

    @Test
    fun `the running JVM is inside the declared range`() {
        // Runs on each matrix leg, closing the loop from the executing side.
        val running = Runtime.version().feature()
        assertTrue(
            running >= SupportedVersions.MIN_JVM_TARGET,
            "tests are running on JDK $running, below the declared floor " +
                "${SupportedVersions.MIN_JVM_TARGET}",
        )
        assertTrue(
            running <= SupportedVersions.NEWEST_TESTED_JVM,
            "tests are running on JDK $running, above the newest declared " +
                "${SupportedVersions.NEWEST_TESTED_JVM} — add the CI leg and raise the constant",
        )
    }

    @Test
    fun `the test JVM is the one the build asked for`() {
        // Set only when -PtestJavaVersion is passed (i.e. in CI). Locally,
        // tests run on Gradle's own JVM and there is nothing to verify.
        val expected = System.getProperty("axiam.expectedTestJvm")?.toIntOrNull() ?: return

        assertEquals(
            expected,
            Runtime.version().feature(),
            "the build requested a JDK $expected test launcher but the suite is running on " +
                "${Runtime.version().feature()} — the toolchain fell back to Gradle's own JVM, " +
                "so this leg is testing nothing it was added to test",
        )
    }
}
