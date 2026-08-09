package io.axiam.sdk.examples.telemetryhook

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.telemetry.TelemetryEvent
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.runBlocking

/**
 * Demonstrates telemetry hooks (CONTRACT.md §19): wiring metrics to an AXIAM
 * client **without this module depending on any metrics library**.
 *
 * The sink below aggregates in-process so the example runs with no extra
 * dependencies; the block at the bottom shows the exact mapping onto
 * Micrometer, which is a drop-in replacement for the body. Uses ONLY public SDK
 * entry points.
 *
 * Run: `AXIAM_BASE_URL=... AXIAM_TENANT_ID=... kotlin TelemetryHookExample.kt`
 */
private val requests = ConcurrentHashMap<String, LongArray>()
private val retries = ConcurrentHashMap<String, AtomicLong>()

/** A §19 sink. Aggregates in memory; see the Micrometer mapping below. */
private fun record(event: TelemetryEvent) {
    when (event) {
        // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so
        // counting these gives the real number of wire calls — including the
        // ones a retry made on your behalf.
        is TelemetryEvent.RequestEnd -> {
            val key = "${event.operation}/${event.outcome}"
            requests.compute(key) { _, existing ->
                val stat = existing ?: longArrayOf(0, 0)
                stat[0]++
                stat[1] += event.duration.inWholeMilliseconds
                stat
            }
        }

        // §16.5 — the reason this event exists. A retried-then-succeeded
        // operation is otherwise invisible: the caller sees a slow success and
        // no signal that the server is failing. Alert on this rate, not on the
        // error rate, or a degrading server looks healthy right up until the
        // retries stop being enough.
        is TelemetryEvent.Retry ->
            retries.computeIfAbsent(event.operation) { AtomicLong() }.incrementAndGet()

        else -> Unit
    }
}

private fun report() {
    println("--- requests (per attempt) ---")
    requests.forEach { (key, stat) ->
        println("  ${key.padEnd(24)} count=${stat[0]} mean=${stat[1] / stat[0]}ms")
    }
    println("--- retries ---")
    if (retries.isEmpty()) println("  (none)")
    retries.forEach { (op, n) -> println("  ${op.padEnd(24)} ${n.get()}") }
}

fun main() = runBlocking {
    val baseUrl = System.getenv("AXIAM_BASE_URL") ?: "https://localhost:8443"
    val tenantId = System.getenv("AXIAM_TENANT_ID") ?: "acme"

    // §18: `use` closes the client. close() releases local resources and does
    // NOT log out — the server-side session outlives this object.
    AxiamClient.builder(baseUrl, tenantId)
        .telemetryHook(::record)
        .build()
        .use { client ->
            // This will usually fail against a host that is not running, which
            // is the point: a failing call still emits a RequestEnd carrying
            // the failure, and the §16 retries are visible as Retry events.
            try {
                val decision = client.checkAccess("read", "00000000-0000-0000-0000-000000000000")
                println("allowed=${decision.allowed} (${decision.reasonCode ?: "no reason code"})")
            } catch (e: Exception) {
                println("check failed as expected in this example: ${e.message}")
            }

            report()
        }
}

// ---------------------------------------------------------------------------
// The same sink, against Micrometer
// ---------------------------------------------------------------------------
//
// This module deliberately declares no micrometer/OpenTelemetry dependency —
// §19's whole point is that you choose your metrics stack. With Micrometer on
// YOUR classpath, `record` becomes:
//
//     val registry: MeterRegistry = ...
//
//     fun record(event: TelemetryEvent) {
//         when (event) {
//             is TelemetryEvent.RequestEnd ->
//                 Timer.builder("axiam.client.request")
//                     .tag("axiam.operation", event.operation)
//                     // The path TEMPLATE, never a substituted URL: a metric
//                     // label carrying a UUID is a cardinality bomb.
//                     .tag("http.route", event.pathTemplate)
//                     .tag("http.response.status_code", event.status?.toString() ?: "0")
//                     .tag("axiam.outcome", event.outcome.name)
//                     .register(registry)
//                     .record(event.duration.toJavaDuration())
//             is TelemetryEvent.Retry ->
//                 Counter.builder("axiam.client.retries")
//                     .tag("axiam.operation", event.operation)
//                     .tag("axiam.attempt", event.attempt.toString())
//                     .register(registry)
//                     .increment()
//             else -> Unit
//         }
//     }
//
// Two rules to keep in mind when writing any adapter:
//
//   * DO NOT BLOCK. Hooks run on the calling coroutine (§19.2 rule 4). Every
//     mature metrics library already buffers; if yours does not, buffer on your
//     side rather than doing I/O here.
//   * DO NOT ENRICH EVENTS FROM ELSEWHERE. TelemetryEvent is a sealed hierarchy
//     precisely so this surface cannot leak a token into a metrics backend
//     (§19.2 rule 3). Adding, say, the current Authorization header would
//     defeat that on your side of the boundary.
//
// A hook that throws is swallowed by the SDK (§19.2 rule 2) — an authorization
// check is never failed by telemetry — with ONE exception: a
// CancellationException is re-thrown. Swallowing it would break structured
// concurrency, leaving a coroutine running past the point its scope was
// cancelled, which is a correctness bug rather than a metrics one.
