package io.axiam.sdk.telemetry

import kotlin.time.Duration

/**
 * A telemetry event (CONTRACT.md §19).
 *
 * This is a **sealed** hierarchy: no code outside this module can add a
 * variant. That is what makes §19.2 rule 3's "no event payload may carry a
 * secret" checkable rather than aspirational — every subclass below is a data
 * class with a fixed property list and no free-form map, so there is nowhere to
 * put a token in a payload bound for a metrics backend.
 *
 * Hooks are invoked on the calling coroutine, so a sink must not block: §19.2
 * rule 4 makes buffering the caller's job so they can pick the policy. Every
 * mature metrics library already buffers.
 */
public sealed interface TelemetryEvent {

    /** Why a request finished. */
    public enum class Outcome {
        /** The call returned a usable response. */
        SUCCESS,

        /** The call failed, at any layer. */
        FAILURE,
    }

    /** Whether this caller performed a §9 refresh or waited on another's. */
    public enum class RefreshRole {
        /** This caller performed the refresh. */
        LEADER,

        /** This caller waited on another coroutine's refresh. */
        FOLLOWER,
    }

    /**
     * Emitted before an outbound call leaves the SDK.
     *
     * @property operation canonical operation name, e.g. `checkAccess`.
     * @property method HTTP method.
     * @property pathTemplate the route constant — `/api/v1/authz/check`, never
     *   a URL with ids substituted in. A metric label carrying a UUID is a
     *   cardinality bomb.
     * @property attempt 1 for the first try, incrementing per §16 retry.
     */
    public data class RequestStart(
        val operation: String,
        val method: String,
        val pathTemplate: String,
        val attempt: Int,
    ) : TelemetryEvent

    /**
     * Emitted after a call completes, success or failure.
     *
     * @property operation canonical operation name.
     * @property method HTTP method.
     * @property pathTemplate the route constant; see [RequestStart.pathTemplate].
     * @property attempt the attempt this event closes.
     * @property status HTTP status, or `null` when no response arrived.
     * @property duration wall-clock time this attempt took.
     * @property outcome success or failure.
     */
    public data class RequestEnd(
        val operation: String,
        val method: String,
        val pathTemplate: String,
        val attempt: Int,
        val status: Int?,
        val duration: Duration,
        val outcome: Outcome,
    ) : TelemetryEvent

    /**
     * Emitted before each §16 retry wait.
     *
     * §16.5 requires this: a retried-then-succeeded operation is otherwise
     * invisible — the caller sees a slow success and no signal that the server
     * is failing. That silence is the standing objection to automatic retry.
     *
     * @property operation canonical operation name.
     * @property attempt the attempt that just failed.
     * @property delay the wait about to be taken, after jitter and any
     *   `Retry-After`.
     * @property reason a redacted failure description; never carries a token.
     */
    public data class Retry(
        val operation: String,
        val attempt: Int,
        val delay: Duration,
        val reason: String,
    ) : TelemetryEvent

    /**
     * Emitted around a §9 single-flight refresh.
     *
     * @property role whether this caller led or followed.
     * @property duration how long the refresh, or the wait for one, took.
     */
    public data class Refresh(
        val role: RefreshRole,
        val duration: Duration,
    ) : TelemetryEvent

    /**
     * Emitted at construction, once per caller-supplied setting the SDK clamped
     * (§19.1, §19.2 rule 6).
     *
     * Clamping rather than rejecting is the right call — rejecting would fail
     * construction for a caller whose configuration was merely optimistic, and
     * honoring would let one client become the herd §16 exists to prevent.
     * Doing it **silently** is the part that is wrong: an operator who set a
     * 60-second memo TTL believes their staleness bound is 60 seconds. It is
     * five, and their revocation reasoning is off by a factor of twelve with
     * nothing anywhere to say so.
     *
     * Not emitted for a value already within its limit: an event that fires
     * when nothing happened trains its reader to ignore it.
     *
     * @property setting the builder setting's name, e.g. `decisionMemoTtl`.
     * @property requested the value the caller asked for, rendered.
     * @property effective the value actually in force, rendered.
     * @property contractReference the §-reference for the limit, e.g.
     *   `§17.1 rule 2`.
     */
    public data class ConfigClamped(
        val setting: String,
        val requested: String,
        val effective: String,
        val contractReference: String,
    ) : TelemetryEvent
}

/**
 * A caller-supplied telemetry sink (CONTRACT.md §19).
 *
 * Install one with `AxiamClient.Builder.telemetryHook`. It receives request
 * start/end, §16 retry and §9 refresh events, so metrics can be wired without
 * this module depending on any metrics library.
 *
 * A hook that throws cannot fail the operation that fired it (§19.2 rule 2) —
 * the dispatcher swallows it. That is a backstop, not a licence.
 */
public fun interface TelemetryHook {
    /**
     * Receives one event.
     *
     * @param event the event.
     */
    public fun onEvent(event: TelemetryEvent)
}
