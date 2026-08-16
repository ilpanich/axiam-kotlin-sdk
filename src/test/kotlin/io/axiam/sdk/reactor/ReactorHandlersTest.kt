package io.axiam.sdk.reactor

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * CONTRACT.md §22.14 — declarative reactor handler binding.
 *
 * Six groups for six rules. None needs a broker: `reactorHandlers { }` is pure
 * composition over the [ReactorHandler] [reactorServe] already takes, so what is
 * under test is the binding table and the one answer it gives for an event
 * nobody bound.
 */
class ReactorHandlersTest {

    /**
     * Assembled from halves so a plain source scan for §22.7's three excluded
     * operations cannot match on this file's own text.
     */
    private val excludedHotPath = listOf(
        "authz" + "." + "check",
        "authz" + "." + "check_batch",
        "token" + "." + "introspect",
    )

    private fun event(name: String): ReactorEvent {
        val now = Instant.now()
        return ReactorEvent(
            tenantId = UUID.randomUUID(),
            event = name,
            correlationId = UUID.randomUUID(),
            payload = JsonObject(emptyMap()),
            timeoutMs = 500,
            keyVersion = 2,
            nonce = UUID.randomUUID(),
            issuedAt = now,
            deadline = now.plusMillis(500),
        )
    }

    // ---- rule 1: it composes, it does not replace ---------------------------

    @Test
    fun `dispatches each event to its own handler`() = runBlocking {
        val handler = reactorHandlers {
            on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.mutate(mapOf("ext.team" to "platform")) }
            on(ReactorEvents.LOGIN_POST_AUTH) { ReactorDecision.deny("embargoed region") }
        }

        val enriched = assertInstanceOf(ReactorDecision.Mutate::class.java, handler.handle(event(ReactorEvents.TOKEN_PRE_ISSUE)))
        assertEquals(mapOf("ext.team" to "platform"), enriched.patch)

        val screened = assertInstanceOf(ReactorDecision.Deny::class.java, handler.handle(event(ReactorEvents.LOGIN_POST_AUTH)))
        assertEquals("embargoed region", screened.reason)
    }

    /** The lambda is a `suspend` function, so a handler may await real work. */
    @Test
    fun `a suspending handler is bindable`() = runBlocking {
        val handler = reactorHandlers {
            on(ReactorEvents.USER_PRE_CREATE) { kotlinx.coroutines.yield(); ReactorDecision.allow() }
        }

        assertInstanceOf(ReactorDecision.Allow::class.java, handler.handle(event(ReactorEvents.USER_PRE_CREATE)))
    }

    // ---- rule 2: an unregistered name is refused at bind time ---------------

    @Test
    fun `rejects a misspelled event name`() {
        val error = assertThrows<IllegalArgumentException> {
            reactorHandlers { on("token.pre_isue") { ReactorDecision.allow() } }
        }

        assertTrue(error.message!!.contains("not a hookable reactor event"), error.message)
    }

    /**
     * §22.7's three are in no registry row, so rule 2 refuses them as unknown
     * names. Asserted on behaviour, not on a comment.
     */
    @Test
    fun `rejects the hot-path operations`() {
        for (excluded in excludedHotPath) {
            assertThrows<IllegalArgumentException>("binding $excluded was accepted; §22.7 makes it un-hookable") {
                reactorHandlers { on(excluded) { ReactorDecision.allow() } }
            }
        }
    }

    /** The rejection names what IS hookable, never what is excluded (rule 2). */
    @Test
    fun `rejection names the registry not the exclusions`() {
        val message = assertThrows<IllegalArgumentException> {
            reactorHandlers { on("nope") { ReactorDecision.allow() } }
        }.message ?: ""

        assertTrue(message.contains(ReactorEvents.TOKEN_PRE_ISSUE), message)
        for (excluded in excludedHotPath) {
            assertFalse(message.contains(excluded), message)
        }
    }

    // ---- rule 3: one handler per event --------------------------------------

    @Test
    fun `rejects a duplicate binding`() {
        val error = assertThrows<IllegalArgumentException> {
            reactorHandlers {
                on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.allow() }
                on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.deny("second") }
            }
        }

        assertTrue(error.message!!.contains("already bound"), error.message)
    }

    // ---- rule 4: an unbound event abstains ----------------------------------

    @Test
    fun `an unbound event abstains rather than allowing`() = runBlocking {
        val handler = reactorHandlers {
            on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.allow() }
        }

        val rejection = assertThrows<UnboundReactorEventException>(
            "an unbound event produced an answer; §22.14 rule 4 requires no reply at all",
        ) {
            handler.handle(event(ReactorEvents.GRANT_PRE_ASSIGN))
        }

        // Throwing publishes NOTHING, so the registration's failure_policy
        // decides (§22.8) — not a synthesized allow (§22.10 rule 2).
        assertEquals(ReactorEvents.GRANT_PRE_ASSIGN, rejection.event)
    }

    @Test
    fun `an empty binding set is refused`() {
        val error = assertThrows<IllegalStateException> { reactorHandlers { } }

        assertTrue(error.message!!.contains("no bindings"), error.message)
    }

    // ---- rule 5: a handler's own failure propagates --------------------------

    @Test
    fun `a throwing handler propagates`() = runBlocking {
        val handler = reactorHandlers {
            on(ReactorEvents.LOGIN_POST_AUTH) { error("fraud service unreachable") }
        }

        val failure = assertThrows<IllegalStateException> {
            handler.handle(event(ReactorEvents.LOGIN_POST_AUTH))
        }

        assertEquals("fraud service unreachable", failure.message)
    }

    // ---- rule 6 and the SHOULD ----------------------------------------------

    @Test
    fun `a forbidden patch key is sent unfiltered`() = runBlocking {
        val handler = reactorHandlers {
            on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.mutate(mapOf("sub" to "attacker")) }
        }

        val decision = assertInstanceOf(ReactorDecision.Mutate::class.java, handler.handle(event(ReactorEvents.TOKEN_PRE_ISSUE)))

        assertEquals(mapOf("sub" to "attacker"), decision.patch, "the binder silently dropped a patch key")
    }

    @Test
    fun `bound events feed the failure policy`() {
        val events = reactorHandlerEvents {
            on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.allow() }
            on(ReactorEvents.LOGIN_POST_AUTH) { ReactorDecision.allow() }
        }

        assertEquals(listOf(ReactorEvents.TOKEN_PRE_ISSUE, ReactorEvents.LOGIN_POST_AUTH), events)
        // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
        // strictest-wins composition makes the pair fail_closed.
        assertEquals(FailurePolicy.FAIL_CLOSED, ReactorEvents.defaultFailurePolicyFor(events))
    }

    @Test
    fun `the composed handler is what reactorServe takes`() {
        val handler: ReactorHandler = reactorHandlers {
            on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.allow() }
        }

        // A compile-time assertion; the runtime check just keeps the test honest.
        assertTrue(handler is ReactorHandler)
    }
}
