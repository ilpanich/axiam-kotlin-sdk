package io.axiam.sdk.examples.restauthz

import io.axiam.sdk.AccessCheck
import io.axiam.sdk.AccessResult
import io.axiam.sdk.AxiamClient
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates REST authorization checks (CONTRACT.md §1): the browser/UI alias
 * [AxiamClient.can], the single-check [AxiamClient.checkAccess], and the
 * order-preserving [AxiamClient.batchCheck]. Imports ONLY public SDK entry
 * points.
 *
 * The client is constructed with BOTH a tenant slug (§5) and organization
 * context (§5.1) so that the [AxiamClient.login] establishing the §4
 * cookie-jar session every subsequent authz call rides on succeeds.
 *
 * Run (from the repo root):
 * ```
 * AXIAM_BASE_URL=... AXIAM_TENANT_SLUG=... AXIAM_ORG_SLUG=... \
 * AXIAM_EMAIL=... AXIAM_PASSWORD=... \
 *   ./gradlew runRestAuthzExample
 * ```
 */
object RestAuthzExample {

    @JvmStatic
    fun main(args: Array<String>) = runBlocking {
        val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
        val tenantSlug = env("AXIAM_TENANT_SLUG", "acme")
        val orgSlug = env("AXIAM_ORG_SLUG", "acme")
        val email = env("AXIAM_EMAIL", "user@example.com")
        val password = env("AXIAM_PASSWORD", "changeme")

        // §5.1: login requires organization context in addition to the tenant —
        // supply .orgSlug(...) (or .orgId(UUID)), else login fails with HTTP 400
        // "must provide org_id or org_slug".
        AxiamClient.builder(baseUrl, tenantSlug).orgSlug(orgSlug).build().use { client ->
            // login() establishes the httpOnly session cookies every subsequent
            // authz call rides on (§4 cookie-jar requirement).
            client.login(email, password)

            // can(action, resourceId) — browser/UI alias for checkAccess(...),
            // returning a plain boolean. Argument order is (action, resource[, scope]).
            val allowed: Boolean = client.can("read", "documents/123")
            println("can read documents/123: $allowed")

            // checkAccess(action, resourceId, scope) — single evaluated check
            // with an optional sub-resource scope.
            val single: AccessResult = client.checkAccess("write", "documents/123", "draft")
            println("checkAccess write documents/123 (scope=draft): allowed=${single.allowed} reason=${single.reason}")

            // batchCheck(checks) — results are returned in the SAME order as input.
            val batch: List<AccessResult> = client.batchCheck(
                listOf(
                    AccessCheck("read", "documents/123"),
                    AccessCheck("delete", "documents/123"),
                ),
            )
            batch.forEachIndexed { i, result ->
                println("batchCheck[$i]: allowed=${result.allowed} reason=${result.reason}")
            }
        }
    }

    private fun env(key: String, fallback: String): String {
        val v = System.getenv(key)
        return if (v.isNullOrBlank()) fallback else v
    }
}
