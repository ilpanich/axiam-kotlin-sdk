package io.axiam.sdk.ssf

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * The event-type URIs AXIAM transmits — the six CAEP / RISC events plus the
 * two SSF stream events (CONTRACT.md §32.6).
 *
 * Event types are OPEN: a SET whose type is not among these still verifies,
 * and [SecurityEvent.eventType] carries it verbatim.
 */
object SsfEventTypes {
    /** CAEP session revoked. */
    const val SESSION_REVOKED: String = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

    /** CAEP credential change. */
    const val CREDENTIAL_CHANGE: String = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

    /** CAEP assurance level change. */
    const val ASSURANCE_LEVEL_CHANGE: String =
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

    /** RISC account disabled. */
    const val ACCOUNT_DISABLED: String = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

    /** RISC account enabled. */
    const val ACCOUNT_ENABLED: String = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"

    /** RISC account purged. */
    const val ACCOUNT_PURGED: String = "https://schemas.openid.net/secevent/risc/event-type/account-purged"

    /** SSF stream verification. */
    const val VERIFICATION: String = "https://schemas.openid.net/secevent/ssf/event-type/verification"

    /** SSF stream updated. */
    const val STREAM_UPDATED: String = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
}

/**
 * Why [SsfReceiver.verifySet] refused a SET — the step of CONTRACT.md §32.7
 * that failed.
 *
 * @property code the reason code as §32.7 spells it
 */
enum class SetFailureReason(val code: String) {
    /** Step 1: not three base64url parts, or a header / payload that is not a JSON object. */
    MALFORMED("malformed"),

    /** Step 2: `typ` absent, or not `secevent+jwt` / `application/secevent+jwt`. */
    INVALID_TYPE("invalid_type"),

    /** Steps 3–5: `alg` not `EdDSA`, no key for the `kid`, or a signature that does not verify. */
    INVALID_KEY("invalid_key"),

    /** Step 6: `iss` is not the configured issuer. */
    INVALID_ISSUER("invalid_issuer"),

    /** Step 7: `aud` does not name this receiver. */
    INVALID_AUDIENCE("invalid_audience"),

    /** Step 8: an `exp` or `sub`, a missing `jti` / `iat` / `sub_id`, or not exactly one event. */
    INVALID_REQUEST("invalid_request"),

    /** Step 9: the `jti` was already accepted within the replay window. */
    REPLAYED("replayed"),
    ;

    /**
     * The RFC 8935 §2.4 `err` a push endpoint answers with (`400 {"err": …}`),
     * and an RFC 8936 `setErrs` entry carries.
     *
     * The reason itself for `invalid_key`, `invalid_issuer`, `invalid_audience`
     * and `invalid_request`; **`invalid_request`** for [MALFORMED],
     * [INVALID_TYPE] and [REPLAYED], which are not RFC 8935 codes.
     *
     * @return the RFC 8935 error code
     */
    fun pushErrorCode(): String = when (this) {
        MALFORMED, INVALID_TYPE, REPLAYED, INVALID_REQUEST -> "invalid_request"
        INVALID_KEY, INVALID_ISSUER, INVALID_AUDIENCE -> code
    }

    /** The §32.7 spelling, e.g. `invalid_key`. */
    override fun toString(): String = code
}

/**
 * A SET refusal (CONTRACT.md §32.7): an [AuthError] whose [failureReason]
 * names the step that failed. [AuthError.reason] carries the same code as a
 * string.
 *
 * The message names the step, never a claim value or the token.
 *
 * @property failureReason why the SET was refused
 */
class SetVerificationError(
    val failureReason: SetFailureReason,
    detail: String,
) : AuthError("SET refused (${failureReason.code}): $detail", failureReason.code)

/**
 * An RFC 8936 `setErrs` entry: how a receiver tells the transmitter it refused
 * a polled SET.
 *
 * @property err the RFC 8935 §2.4 code
 * @property description optional text; AXIAM never stores it (§32.6)
 */
data class SetErr(val err: String, val description: String? = null) {
    companion object {
        /**
         * The entry for a refusal: its [SetFailureReason.pushErrorCode].
         *
         * @param reason why the SET was refused
         * @return the `setErrs` entry to send on the next poll
         */
        fun fromReason(reason: SetFailureReason): SetErr = SetErr(reason.pushErrorCode())
    }
}

/**
 * A verified Security Event Token — what [SsfReceiver.verifySet] returns
 * (CONTRACT.md §32.7).
 *
 * @property jti the SET's unique id
 * @property iat when it was issued, seconds since the epoch
 * @property iss the issuer, equal to the configured one
 * @property aud the audience as sent: one string, or an array containing yours
 * @property txn the transaction id every SET of one operation shares, if any
 * @property eventType the single `events` key — an event-type URI, see [SsfEventTypes]
 * @property event that event's value, opaque to the helper
 * @property subId the RFC 9493 subject identifier, opaque to the helper
 */
data class SecurityEvent(
    val jti: String,
    val iat: Long,
    val iss: String,
    val aud: JsonElement,
    val txn: String?,
    val eventType: String,
    val event: JsonElement,
    val subId: JsonObject,
)

/**
 * One SET a poll returned and the helper refused.
 *
 * @property jti the key the transmitter returned the SET under
 * @property reason why it was refused; pass [SetErr.fromReason] of it in the
 *   next poll's `setErrs`
 */
data class RefusedSet(val jti: String, val reason: SetFailureReason)

/**
 * Arguments to [SsfReceiver.poll]. Every member is passed through as given; a
 * `null` one is not sent.
 *
 * @property maxEvents `maxEvents` — the server clamps it to 100; `0`
 *   acknowledges and returns nothing
 * @property returnImmediately `returnImmediately` — without it the server
 *   long-polls up to 30 s
 * @property ack `ack` — the `jti`s you **processed** since the last poll
 * @property setErrs `setErrs` — the `jti`s you refuse, each with its code
 */
data class SsfPollOptions(
    val maxEvents: Int? = null,
    val returnImmediately: Boolean? = null,
    val ack: List<String>? = null,
    val setErrs: Map<String, SetErr>? = null,
)

/**
 * What [SsfReceiver.poll] returns.
 *
 * @property events the SETs that verified, in the order the transmitter listed them
 * @property moreAvailable whether the transmitter holds more
 * @property refused the SETs that did not verify
 */
data class SsfPollResult(
    val events: List<SecurityEvent>,
    val moreAvailable: Boolean,
    val refused: List<RefusedSet>,
)

/** Where the transmitter's signing keys come from (CONTRACT.md §32.7). */
sealed interface SsfKeySource {
    /**
     * The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`).
     *
     * @property uri the JWKS URL; `https`, or `http` on a loopback host
     */
    data class JwksUri(val uri: String) : SsfKeySource

    /**
     * The transmitter's SSF configuration document
     * (`/.well-known/ssf-configuration…`): its `jwks_uri` is used, and its
     * `issuer` must equal the configured issuer.
     *
     * @property url the configuration document's URL
     */
    data class DiscoveryUrl(val url: String) : SsfKeySource
}

/**
 * Remembers the `jti`s already accepted, for step 9 of §32.7.
 *
 * Pluggable so a receiver running several instances can share one store.
 * [MemoryReplayStore] is the default.
 */
fun interface ReplayStore {
    /**
     * Records [jti] for [window] and returns `true`, or returns `false`
     * without recording when it is already held.
     *
     * MUST be atomic: two concurrent calls with one `jti` must not both see
     * `true`.
     *
     * @param jti the SET's id
     * @param window how long to remember it
     * @return whether the `jti` was new
     */
    fun checkAndRecord(jti: String, window: Duration): Boolean
}

/**
 * The in-memory [ReplayStore]: one process, lost on restart. Entries expire
 * after their window.
 *
 * @param clock the time source expiry is measured on
 */
class MemoryReplayStore(private val clock: Clock = Clock.systemUTC()) : ReplayStore {
    private val seen = ConcurrentHashMap<String, Instant>()

    override fun checkAndRecord(jti: String, window: Duration): Boolean = synchronized(this) {
        val now = clock.instant()
        seen.entries.removeIf { !it.value.isAfter(now) }
        if (seen.containsKey(jti)) return false
        seen[jti] = now.plus(window)
        true
    }
}

/**
 * Configuration for an [SsfReceiver] — CONTRACT.md §32.7's `{ issuer,
 * audience, jwks_uri | discovery_url, access_token_provider }`.
 *
 * @property issuer the transmitter's issuer — compared to `iss` exactly
 * @property audience this receiver's audience — the stream's `audience`
 * @property keys where the signing keys come from
 * @property accessTokenProvider the bearer [SsfReceiver.poll] presents — a
 *   client-credentials access token carrying `ssf.manage` (for example from
 *   `loginClientCredentials`); `null` for a push-only receiver. Called once
 *   per poll.
 * @property replayWindow how long a `jti` is remembered; at least
 *   [SsfReceiver.MIN_REPLAY_WINDOW], which is also the default
 * @property replayStore where accepted `jti`s are kept
 */
data class SsfReceiverConfig(
    val issuer: String,
    val audience: String,
    val keys: SsfKeySource,
    val accessTokenProvider: (suspend () -> Sensitive<String>)? = null,
    val replayWindow: Duration = SsfReceiver.MIN_REPLAY_WINDOW,
    val replayStore: ReplayStore = MemoryReplayStore(),
)
