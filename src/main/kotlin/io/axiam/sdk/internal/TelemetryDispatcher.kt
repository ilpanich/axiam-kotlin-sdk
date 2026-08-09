package io.axiam.sdk.internal

import io.axiam.sdk.telemetry.TelemetryEvent
import io.axiam.sdk.telemetry.TelemetryHook
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Internal §19 dispatcher. A null hook is the overwhelmingly common case and
 * costs one null check per request.
 */
internal class TelemetryDispatcher(private val hook: TelemetryHook? = null) {

    /** Whether a hook is installed. */
    val installed: Boolean get() = hook != null

    /**
     * Delivers [event], swallowing anything the caller's hook throws.
     *
     * §19.2 rule 2: telemetry is not permitted to fail an authorization check.
     * A hook that throws is the caller's bug, and letting it propagate here
     * would turn a metrics problem into an authorization failure.
     *
     * [CancellationException] is deliberately re-thrown: swallowing it would
     * break structured concurrency, leaving a cancelled coroutine running past
     * the point its scope was cancelled. That is a correctness bug, not a
     * metrics bug, so it is not the dispatcher's to absorb.
     */
    fun emit(event: TelemetryEvent) {
        val sink = hook ?: return
        try {
            sink.onEvent(event)
        } catch (e: CancellationException) {
            throw e
        } catch (@Suppress("TooGenericExceptionCaught") e: Throwable) {
            // Deliberately swallowed; see above.
        }
    }

    /**
     * Opens a §19 request pair around one **attempt**.
     *
     * Per attempt, not per logical call: §19.2 rule 5 requires a caller to be
     * able to count real wire calls from the events, which one pair per
     * operation would hide — a retried call would look like a single slow one.
     */
    fun startRequest(operation: String, method: String, pathTemplate: String, attempt: Int): Span {
        if (installed) {
            emit(TelemetryEvent.RequestStart(operation, method, pathTemplate, attempt))
        }
        return Span(this, operation, method, pathTemplate, attempt, System.nanoTime())
    }

    /** Closes a §19 request pair opened by [startRequest]. */
    internal class Span(
        private val dispatcher: TelemetryDispatcher,
        private val operation: String,
        private val method: String,
        private val pathTemplate: String,
        private val attempt: Int,
        private val startedNanos: Long,
    ) {
        /** Emits the closing `RequestEnd`. */
        fun end(status: Int?, outcome: TelemetryEvent.Outcome) {
            if (!dispatcher.installed) return
            dispatcher.emit(
                TelemetryEvent.RequestEnd(
                    operation = operation,
                    method = method,
                    pathTemplate = pathTemplate,
                    attempt = attempt,
                    status = status,
                    duration = (System.nanoTime() - startedNanos).nanoseconds,
                    outcome = outcome,
                ),
            )
        }
    }
}
