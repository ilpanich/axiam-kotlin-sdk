package io.axiam.sdk

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The change log and the version `gradle.properties` builds agree.
 *
 * Between releases the change log opens with `## [Unreleased]`: the version then names the pending
 * release and must be newer than every released heading. At release `[Unreleased]` is renamed to the
 * version, and the first heading must equal it.
 */
class ReleaseVersionTest {

    private val version = File("gradle.properties").readLines()
        .first { it.startsWith("version=") }.removePrefix("version=").trim()
    private val headings = File("CHANGELOG.md").readLines()
        .mapNotNull { Regex("""^## \[([^\]]+)]""").find(it)?.groupValues?.get(1) }

    @Test
    fun `the change-log headings agree with the gradle properties version`() {
        val released = headings.filter { Regex("""\d+\.\d+\.\d+""").matches(it) }
        if (headings.first() == "Unreleased") {
            assertTrue(
                compare(version, released.first()) > 0,
                "version $version must be newer than the latest released heading ${released.first()}",
            )
        } else {
            assertEquals(version, released.first())
        }
    }

    @Test
    fun `only the first heading may be Unreleased`() {
        assertTrue(headings.drop(1).none { it == "Unreleased" }, "a second [Unreleased] heading")
    }

    private fun compare(a: String, b: String): Int {
        val x = a.split('.').map(String::toInt)
        val y = b.split('.').map(String::toInt)
        return x.zip(y).map { (p, q) -> p.compareTo(q) }.firstOrNull { it != 0 } ?: 0
    }
}
