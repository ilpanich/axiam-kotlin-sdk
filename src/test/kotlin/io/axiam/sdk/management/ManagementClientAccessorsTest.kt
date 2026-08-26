package io.axiam.sdk.management

import io.axiam.sdk.AxiamClient
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.reflect.full.declaredMemberFunctions

/**
 * CONTRACT.md §27.2/§27.3 — the namespace handles sit on the client.
 *
 * §27.3's Kotlin row is `client.serviceAccounts.rotateSecret(id)` — a property — and
 * §27.2 rule 4 makes the single `management()` accessor the *additional* one. Both forms
 * therefore exist, and rule 4 requires that "where an SDK offers both, the two MUST
 * return equivalent handles".
 *
 * Equivalent means the same *request*, not merely the same type: a direct accessor that
 * built a handle with a default scope instead of the client's would return the right type
 * and address the wrong organization. So the assertions below compare what each form
 * actually put on the wire.
 */
class ManagementClientAccessorsTest : ManagementTestBase() {

    /** Every namespace the aggregate exposes is also a property on the client. */
    @Test
    fun `every namespace is reachable both ways`() {
        val onAggregate = ManagementApi::class.declaredMemberFunctions
            .map { it.name }
            .filter { it != "manifest" }
            .sorted()

        // Java reflection over the compiled getters rather than kotlin-reflect over the
        // properties: a Kotlin `val` on the client is a `getFoo()` on the class, and asking
        // the JVM what it actually emitted is the assertion that a consumer's call site
        // depends on.
        val getters: Set<String> = AxiamClient::class.java.methods.map { it.name }.toSet()

        assertTrue(onAggregate.isNotEmpty(), "the aggregate declares no namespaces")
        for (name in onAggregate) {
            val getter = "get" + name.replaceFirstChar { it.uppercaseChar() }
            assertTrue(
                getter in getters,
                "§27.3 puts `$name` on the client as a property, not only behind management()",
            )
        }
        // 24 namespaces. Pinned so a partial regeneration that dropped one fails here
        // rather than quietly shipping 23.
        assertEquals(24, onAggregate.size)
    }

    /** Both forms reach the same route with the client's own scope. */
    @Test
    fun `the two forms issue the same request`() = runTest {
        val route = mount("GET", "/api/v1/roles", 200, pageOf(null))

        client.roles.list(null)
        assertEquals(1, route.calls())
        val direct = route.last()

        client.management().roles().list(null)
        assertEquals(2, route.calls())
        val viaAggregate = route.last()

        assertEquals(direct.method, viaAggregate.method)
        assertEquals(direct.path, viaAggregate.path)
        assertEquals(direct.query, viaAggregate.query)
    }

    /**
     * A direct accessor carries the client's implicit `{org_id}`, not a bare default.
     *
     * This is the failure the equivalence rule exists to prevent: a forwarding accessor
     * that constructed its own handle would compile, return the right type, and address
     * the wrong organization.
     */
    @Test
    fun `a direct accessor carries the client's own scope`() = runTest {
        val route = mount("GET", "/api/v1/organizations/$ORG_ID/ca-certificates", 200, pageOf(null))

        client.caCertificates.list(null)

        assertEquals(1, route.calls())
        assertTrue(route.last().path.contains(ORG_ID.toString()), route.last().path)
    }

    /** Re-scoping a directly-reached handle still returns a new one (§27.4 rule 3). */
    @Test
    fun `a direct accessor still rescopes`() = runTest {
        val other = UUID.fromString("44444444-4444-4444-8444-444444444444")
        val mine = mount("GET", "/api/v1/organizations/$ORG_ID/ca-certificates", 200, pageOf(null))
        val theirs = mount("GET", "/api/v1/organizations/$other/ca-certificates", 200, pageOf(null))

        val handle = client.caCertificates
        handle.inOrg(other).list(null)
        handle.list(null)

        assertEquals(1, theirs.calls())
        assertEquals(1, mine.calls())
    }

    /** Acquiring a handle either way performs no I/O (§27.2 rule 1). */
    @Test
    fun `acquiring a handle performs no I O`() {
        val before = server.requestCount

        assertNotNull(client.roles)
        assertNotNull(client.serviceAccounts)
        assertNotNull(client.management().certificates())

        assertEquals(before, server.requestCount)
    }
}
