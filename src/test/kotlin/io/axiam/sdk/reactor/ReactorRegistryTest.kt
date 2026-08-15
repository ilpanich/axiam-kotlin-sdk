package io.axiam.sdk.reactor

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §22.5 (the registry and its allow-lists), §22.7 (the hot-path
 * exclusion) and §22.8 (failure-policy composition).
 */
class ReactorRegistryTest {

    // ---- §22.5 the namespace-prefix rule -----------------------------------

    @Test
    fun `token pre_issue admits the ext namespace and nothing else`() {
        val spec = requireNotNull(ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE))

        assertTrue(spec.patchFieldAllowed("ext.department"))
        assertTrue(spec.patchFieldAllowed("ext.a.b.c"))

        // `ext.` names the namespace, not a claim: admitting it would let a
        // reactor set a claim literally called `ext.`.
        assertFalse(spec.patchFieldAllowed("ext."))
        assertFalse(spec.patchFieldAllowed("ext"))
        // A prefix match on the string is not a match on the namespace.
        assertFalse(spec.patchFieldAllowed("extra"))
        assertFalse(spec.patchFieldAllowed("external_id"))
        // Nor is a suffix match.
        assertFalse(spec.patchFieldAllowed("evil.ext.department"))
    }

    @Test
    fun `no standard claim is reachable from token pre_issue`() {
        val spec = requireNotNull(ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE))
        for (claim in listOf("iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "scp", "azp", "act", "client_id")) {
            assertFalse(
                spec.patchFieldAllowed(claim),
                "a hook that can rewrite '$claim' is a hook that can mint a token for anyone",
            )
        }
    }

    @Test
    fun `user events admit profile fields and refuse credentials and bare metadata`() {
        for (event in listOf(ReactorEvents.USER_PRE_CREATE, ReactorEvents.USER_PRE_UPDATE)) {
            val spec = requireNotNull(ReactorEvents.spec(event))
            assertTrue(spec.patchFieldAllowed("username"))
            assertTrue(spec.patchFieldAllowed("email"))
            assertTrue(spec.patchFieldAllowed("metadata.source"))

            assertFalse(spec.patchFieldAllowed("metadata"), "bare `metadata` is not in the namespace")
            assertFalse(spec.patchFieldAllowed("metadata."), "the namespace is not a field")
            for (forbidden in listOf("password", "password_hash", "tenant_id", "id", "roles", "is_admin")) {
                assertFalse(spec.patchFieldAllowed(forbidden), "$event must refuse $forbidden")
            }
        }
    }

    @Test
    fun `veto-only events accept no patch field at all`() {
        for (event in listOf(ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.GRANT_PRE_ASSIGN)) {
            val spec = requireNotNull(ReactorEvents.spec(event))
            assertFalse(spec.mutable, "$event is veto-only")
            assertTrue(spec.mutableFields.isEmpty())
            for (field in listOf("anything", "username", "ext.department", "role")) {
                assertFalse(spec.patchFieldAllowed(field))
            }
        }
    }

    @Test
    fun `the registry matches the server's five entries`() {
        assertEquals(
            listOf("token.pre_issue", "login.post_auth", "user.pre_create", "user.pre_update", "grant.pre_assign"),
            ReactorEvents.REGISTRY.map { it.name },
        )
        assertTrue(ReactorEvents.REGISTRY.all { it.interceptable }, "all five v1 events are interceptable")
        assertTrue(ReactorEvents.REGISTRY.all { it.description.isNotBlank() })
        assertNull(ReactorEvents.spec("not.an.event"))
        assertNull(ReactorEvents.spec(null))
        assertNotNull(ReactorEvents.spec(ReactorEvents.GRANT_PRE_ASSIGN))
    }

    // ---- §22.7 hot-path exclusion (MUST NOT) -------------------------------

    /**
     * Asserted against the list, not against a comment: `authz.check`,
     * `authz.check_batch` and `token.introspect` appear in no event constant this
     * SDK exposes, and in no registry row.
     */
    @Test
    fun `the hot-path operations are absent from every event constant`() {
        val excluded = listOf("authz.check", "authz.check_batch", "token.introspect")

        val constants = ReactorEvents::class.java.declaredFields
            .filter { java.lang.reflect.Modifier.isStatic(it.modifiers) && it.type == String::class.java }
            .map { it.isAccessible = true; it.get(null) as String }
        assertEquals(5, constants.size, "five event constants, no more")

        for (name in excluded) {
            assertFalse(constants.contains(name), "$name must not be exposed as a reactor event")
            assertNull(ReactorEvents.spec(name), "$name must not resolve to a registry spec")
            assertFalse(
                ReactorEvents.REGISTRY.any { it.name == name },
                "$name must not be hookable: a reactor round trip is milliseconds and the check " +
                    "path's budget is microseconds",
            )
        }
    }

    // ---- §22.8 failure-policy composition ----------------------------------

    @Test
    fun `the strictest default wins in either array order`() {
        assertEquals(
            FailurePolicy.FAIL_OPEN,
            ReactorEvents.defaultFailurePolicyFor(listOf(ReactorEvents.TOKEN_PRE_ISSUE)),
        )
        assertEquals(
            FailurePolicy.FAIL_CLOSED,
            ReactorEvents.defaultFailurePolicyFor(listOf(ReactorEvents.LOGIN_POST_AUTH)),
        )

        // A reactor registered for both can veto a login, so it inherits
        // fail_closed — and the order of the array must not decide that.
        assertEquals(
            FailurePolicy.FAIL_CLOSED,
            ReactorEvents.defaultFailurePolicyFor(
                listOf(ReactorEvents.TOKEN_PRE_ISSUE, ReactorEvents.LOGIN_POST_AUTH),
            ),
        )
        assertEquals(
            FailurePolicy.FAIL_CLOSED,
            ReactorEvents.defaultFailurePolicyFor(
                listOf(ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.TOKEN_PRE_ISSUE),
            ),
        )

        assertEquals(FailurePolicy.FAIL_OPEN, ReactorEvents.defaultFailurePolicyFor(emptyList()))
        assertEquals(FailurePolicy.FAIL_OPEN, ReactorEvents.defaultFailurePolicyFor(listOf("not.an.event")))
    }

    @Test
    fun `the registry's per-event defaults match the server's`() {
        assertEquals(
            FailurePolicy.FAIL_OPEN,
            ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE)!!.defaultFailurePolicy,
        )
        for (closed in listOf(
            ReactorEvents.LOGIN_POST_AUTH,
            ReactorEvents.USER_PRE_CREATE,
            ReactorEvents.USER_PRE_UPDATE,
            ReactorEvents.GRANT_PRE_ASSIGN,
        )) {
            assertEquals(FailurePolicy.FAIL_CLOSED, ReactorEvents.spec(closed)!!.defaultFailurePolicy, closed)
        }
    }

    @Test
    fun `failure policy wire forms round-trip`() {
        assertEquals("fail_open", FailurePolicy.FAIL_OPEN.wire)
        assertEquals("fail_closed", FailurePolicy.FAIL_CLOSED.wire)
        assertEquals(FailurePolicy.FAIL_CLOSED, FailurePolicy.fromWire(" FAIL_CLOSED "))
        assertEquals(FailurePolicy.FAIL_OPEN, FailurePolicy.fromWire("fail_open"))
        assertNull(FailurePolicy.fromWire("fail_sideways"))
        assertNull(FailurePolicy.fromWire(null))
    }

    // ---- §22.8 budget constants --------------------------------------------

    @Test
    fun `the budget constants are the contract's own`() {
        assertEquals(500, ReactorProtocol.DEFAULT_TIMEOUT_MS)
        assertEquals(5_000, ReactorProtocol.MAX_TIMEOUT_MS)
        assertEquals(5_000, ReactorProtocol.CHAIN_CEILING_MS)
        assertEquals(64, ReactorProtocol.DEFAULT_MAX_IN_FLIGHT_PER_TENANT)
        assertEquals(2, ReactorProtocol.KEY_VERSION)
        assertEquals(2, ReactorProtocol.MIN_ACCEPTED_KEY_VERSION)
        assertEquals(300L, ReactorProtocol.DEFAULT_FRESHNESS_SKEW.inWholeSeconds)
    }

    // ---- §22.4 decisions ----------------------------------------------------

    @Test
    fun `the decision types encode three section 22_4 rules structurally`() {
        assertEquals("allow", ReactorDecision.allow().wire)
        assertEquals("allow", ReactorDecision.allowRequiringStepUp().wire)
        assertEquals("deny", ReactorDecision.deny("nope").wire)
        assertEquals("mutate", ReactorDecision.mutate(mapOf("ext.a" to "b")).wire)

        assertFalse((ReactorDecision.allow() as ReactorDecision.Allow).requireMfa)
        assertTrue((ReactorDecision.allowRequiringStepUp() as ReactorDecision.Allow).requireMfa)
        assertEquals("nope", (ReactorDecision.deny("nope") as ReactorDecision.Deny).reason)
        assertNull((ReactorDecision.deny() as ReactorDecision.Deny).reason)

        // An empty mutation is malformed_mutation on the wire, and a type that
        // cannot represent it beats a rejection round trip.
        val failure = runCatching { ReactorDecision.mutate(emptyMap()) }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }
}
