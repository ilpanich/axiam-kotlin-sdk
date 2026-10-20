package io.axiam.sdk

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

/** The change log's first released heading is the version `gradle.properties` builds. */
class ReleaseVersionTest {

    @Test
    fun `the first released change-log heading equals gradle properties version`() {
        val version = File("gradle.properties").readLines()
            .first { it.startsWith("version=") }.removePrefix("version=").trim()
        val heading = Regex("""^## \[(\d+\.\d+\.\d+)]""")
        val released = File("CHANGELOG.md").readLines().firstNotNullOf { heading.find(it)?.groupValues?.get(1) }
        assertEquals(version, released)
    }
}
