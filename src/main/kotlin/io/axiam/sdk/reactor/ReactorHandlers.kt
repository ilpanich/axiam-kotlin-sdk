package io.axiam.sdk.reactor

/**
 * Declarative reactor handler binding — CONTRACT.md §22.14.
 *
 * [reactorServe] takes **one** [ReactorHandler] from an event to one answer,
 * which is the right shape for the wire and the wrong shape for the code. A
 * reactor registered for three events opens with a `when (event.event)`, and
 * that `when` carries two defects.
 *
 * The first is cheap: a misspelled event name is a valid string, matches no
 * branch, and is discovered as an event that never fires. The second is not. It
 * is the `else` branch, which is almost always written
 * `ReactorDecision.allow()`. That answers on behalf of code that never ran —
 * the defect §22.10 rule 2 forbids the *runtime* from committing, relocated into
 * user code where the rule does not reach it. An operator who set `fail_closed`
 * on a registration has it defeated by an `else` branch in a file they never
 * read.
 *
 * [reactorHandlers] is the declarative form:
 *
 * ```kotlin
 * val options = ReactorServeOptions(
 *     channel = channel,
 *     tenantId = tenantId,
 *     signingKey = subkey,
 *     reactorId = reactorId,
 *     handler = reactorHandlers {
 *         on(ReactorEvents.TOKEN_PRE_ISSUE) { ReactorDecision.mutate(mapOf("ext.department" to "eng")) }
 *         on(ReactorEvents.LOGIN_POST_AUTH) { event -> screen(event) }
 *     },
 * )
 * ```
 *
 * It is **pure sugar** (§22.14 rule 1): what it returns is exactly the
 * [ReactorHandler] [reactorServe] already takes. It opens nothing, verifies
 * nothing, signs nothing, and does not filter a patch (§22.10 rule 3).
 *
 * A type-safe builder rather than an annotation, which is where Kotlin diverges
 * from Java's `@OnReactorEvent`: a Kotlin handler is a `suspend` function, and
 * collecting annotated `suspend` members needs `kotlin-reflect` on every
 * consumer's runtime classpath to invoke through the hidden `Continuation`
 * parameter. A builder is Kotlin's own declarative mechanism, costs no
 * dependency, and — because the lambda is checked against
 * `suspend (ReactorEvent) -> ReactorDecision` at compile time — catches a
 * wrong-shaped handler earlier than reflection ever could.
 */
public class ReactorHandlersBuilder internal constructor() {

    private val handlers = LinkedHashMap<String, ReactorHandler>()

    /**
     * Binds [handler] to [event].
     *
     * @param event a §22.5 registry event name, e.g.
     *   [ReactorEvents.TOKEN_PRE_ISSUE].
     * @param handler the decision function for that event.
     * @throws IllegalArgumentException when [event] is outside the §22.5
     *   registry — which is how §22.7's hot-path operations are refused, since
     *   they are in no registry row — or is already bound. A second binding is a
     *   mistake, never a silent overwrite: which of the two runs is not visible
     *   from either one.
     */
    public fun on(event: String, handler: suspend (ReactorEvent) -> ReactorDecision) {
        require(ReactorEvents.spec(event) != null) {
            // The message names what IS hookable. It deliberately does not name
            // what is excluded: §22.13 requires the three hot-path operations to
            // be absent from every event constant this SDK exposes, and a list of
            // them here — even only to say they are refused — is exactly the
            // constant that would break it (§22.14 rule 2).
            "$event is not a hookable reactor event; the registry is " +
                ReactorEvents.REGISTRY.map { it.name }
        }
        require(event !in handlers) { "reactor event $event is already bound" }
        handlers[event] = ReactorHandler { handler(it) }
    }

    /** The bound event names, in binding order. */
    internal fun events(): List<String> = handlers.keys.toList()

    /**
     * Composes the bindings into the handler [reactorServe] accepts.
     *
     * @throws IllegalStateException when nothing is bound. A reactor that
     *   handles nothing would consume its queue and abstain from every event,
     *   which looks exactly like an outage.
     */
    internal fun build(): ReactorHandler {
        check(handlers.isNotEmpty()) {
            "reactorHandlers { } has no bindings; bind at least one event with on(...)"
        }
        val bound = handlers.toMap()
        return ReactorHandler { event ->
            val handler = bound[event.event]
                // §22.14 rule 4. NOT allow(): throwing publishes NO REPLY, so the
                // registration's failure_policy resolves this exactly as it
                // resolves a timeout (§22.8). This builder does not know what the
                // registration was for; the operator's policy does.
                ?: throw UnboundReactorEventException(event.event)
            // Invoked without a try/catch on purpose (§22.14 rule 5): a handler's
            // own throwable must reach ReactorServer unchanged so it publishes
            // nothing. Catching it here would satisfy the letter of §22.10 rule 2
            // while defeating it.
            handler.handle(event)
        }
    }
}

/**
 * Thrown by a [reactorHandlers]-composed handler for an event no handler was
 * bound for (CONTRACT.md §22.14 rule 4).
 *
 * Throwing is the point. [ReactorServer] publishes **no reply** for a handler
 * that threw, so the registration's `failure_policy` resolves this exactly as
 * §22.8 resolves a timeout. The alternative — answering `allow` — would answer
 * on behalf of code that never ran, which is how an operator's `fail_closed`
 * setting gets defeated from inside the library (§22.10 rule 2).
 *
 * @property event the wire event name no handler was bound for.
 */
public class UnboundReactorEventException(
    public val event: String,
) : RuntimeException("no reactor handler bound for $event")

/**
 * Builds a §22.10 handler by binding one handler per hook event
 * (CONTRACT.md §22.14).
 *
 * See [ReactorHandlersBuilder] for the rules and the reasoning.
 *
 * @param block binds handlers with [ReactorHandlersBuilder.on].
 * @return the [ReactorHandler] [reactorServe] accepts.
 * @throws IllegalArgumentException on an unregistered or duplicate event name.
 * @throws IllegalStateException when [block] binds nothing.
 */
public fun reactorHandlers(block: ReactorHandlersBuilder.() -> Unit): ReactorHandler =
    ReactorHandlersBuilder().apply(block).build()

/**
 * The event names a [reactorHandlers] block bound, in binding order.
 *
 * Pass them to [ReactorEvents.defaultFailurePolicyFor] to see what an
 * unreachable reactor costs — the strictest default among them (§22.8) —
 * derived from the code that handles the events rather than from a restatement
 * of the registration.
 *
 * @param block the same block passed to [reactorHandlers].
 * @return the bound wire event names.
 */
public fun reactorHandlerEvents(block: ReactorHandlersBuilder.() -> Unit): List<String> =
    ReactorHandlersBuilder().apply(block).events()
