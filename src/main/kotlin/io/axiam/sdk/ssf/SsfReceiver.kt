package io.axiam.sdk.ssf

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.ErrorMapper
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.Retry
import io.axiam.sdk.internal.Sessionless
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.time.Duration
import java.util.Base64

/**
 * The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).
 *
 * AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
 * security events as Security Event Tokens (RFC 8417) to the relying parties a
 * tenant administrator registered (the §27 `ssf` namespace,
 * `client.ssf` / `client.management().ssf()`). This class is for the
 * **relying party** that receives them — a different audience from that
 * namespace:
 *
 *  - [verifySet] verifies one compact SET — pushed to your endpoint
 *    (RFC 8935) or returned by a poll — in the contract's fixed order, and
 *    refuses at the first failure with a [SetVerificationError] whose
 *    [SetVerificationError.failureReason] names the step;
 *  - [poll] calls the stream's poll endpoint (RFC 8936), verifies every
 *    returned SET and hands back the verified and the refused apart.
 *
 * Neither transmits, signs or registers anything, and neither trusts a key it
 * did not fetch from the configured JWKS: no `jwk` or `x5c` header member is
 * honoured (§32.9). The JWKS, the SSF configuration document and the poll
 * endpoint are reached over [client]'s §6 TLS policy — on a transport that
 * carries none of the client's session (no cookie, no access token, no
 * redirect).
 *
 * @param client the client whose TLS policy fetches the keys and whose base
 *   URL is the transmitter root [poll] calls
 * @param config the receiver's issuer, audience, key source and replay policy
 * @throws ValidationError locally, when [SsfReceiverConfig.replayWindow] is
 *   below [MIN_REPLAY_WINDOW], the issuer or audience is blank, or a key
 *   source URL is neither `https` nor `http` on a loopback host
 */
class SsfReceiver(private val client: AxiamClient, config: SsfReceiverConfig) {

    private val issuer: String = config.issuer
    private val audience: String = config.audience
    private val keys: SsfKeySource = config.keys
    private val tokenProvider = config.accessTokenProvider
    private val replayWindow: Duration = config.replayWindow
    private val replayStore: ReplayStore = config.replayStore
    private val bare: OkHttpClient by lazy { Sessionless.of(client.okHttpClient()) }

    private val keyLock = Mutex()
    private var jwksUrl: HttpUrl? = null
    private var jwks: JWKSet? = null
    private var lastForcedRefetchNanos: Long? = null

    init {
        if (replayWindow < MIN_REPLAY_WINDOW) {
            throw ValidationError(
                "ssf.receiver: replay_window must be at least seven days, the transmitter's buffer " +
                    "retention (CONTRACT.md §32.7)",
            )
        }
        if (issuer.isBlank() || audience.isBlank()) {
            throw ValidationError("ssf.receiver: issuer and audience are required (CONTRACT.md §32.7)")
        }
        when (keys) {
            is SsfKeySource.JwksUri -> secureUrl("jwks_uri", keys.uri)
            is SsfKeySource.DiscoveryUrl -> secureUrl("discovery_url", keys.url)
        }
    }

    /**
     * Verifies one compact SET (CONTRACT.md §32.7), in this order, refusing at
     * the first failure with the [SetFailureReason] in brackets:
     *
     *  1. three base64url parts, a JSON-object header and payload [`malformed`];
     *  2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case
     *     [`invalid_type`];
     *  3. `alg` exactly `EdDSA` [`invalid_key`];
     *  4. the `kid` in the configured JWKS — on a miss, ONE refetch, at most
     *     once a minute [`invalid_key`];
     *  5. the Ed25519 signature [`invalid_key`];
     *  6. `iss` equal to the configured issuer [`invalid_issuer`];
     *  7. `aud` equal to, or an array containing, the audience [`invalid_audience`];
     *  8. no `exp`, no `sub`; a non-empty `jti`, a numeric `iat`, an object
     *     `sub_id`; `events` with exactly one member [`invalid_request`];
     *  9. a `jti` not seen within the replay window [`replayed`] — recorded
     *     only once steps 1–8 passed.
     *
     * A SET that verifies has been **recorded**: verifying it again is
     * `replayed`. Acknowledge a polled SET once you have processed it.
     *
     * Answering a push (RFC 8935): `202` on success; on a refusal, `400` with
     * `{"err": e.failureReason.pushErrorCode()}`.
     *
     * @param set the compact SET
     * @return the verified event
     * @throws SetVerificationError when the SET is refused
     * @throws NetworkError when the JWKS could not be fetched — which is not a
     *   verdict on the SET
     */
    suspend fun verifySet(set: String): SecurityEvent = verify(set, null)

    /**
     * Polls the stream's RFC 8936 endpoint, `{base URL}/ssf/v1/poll/{streamId}`,
     * with a bearer from [SsfReceiverConfig.accessTokenProvider].
     *
     * The body carries only the members [options] sets — `maxEvents`,
     * `returnImmediately`, `ack`, `setErrs` — exactly as given. **Nothing is
     * acknowledged on your behalf**: acknowledge, on the next call, the `jti`s
     * you processed, and pass each refused one in `setErrs`
     * ([SetErr.fromReason]). A SET you neither acknowledge nor refuse is
     * re-offered, and — having been recorded when it verified — then reads as
     * `replayed`.
     *
     * Retried per §16 on a transport failure, `408`, `429` or `5xx`; never on
     * another `4xx` (`400` → [ValidationError], `401` → [AuthError], `404` →
     * [NotFoundError], `409` → [ConflictError]). A JWKS fetch failure while
     * verifying aborts the poll with that error rather than refusing SETs it
     * could not judge.
     *
     * @param streamId the stream's id (path-escaped)
     * @param options what to send
     * @return the verified events and the refused SETs, apart
     * @throws AuthError locally, without a request, when no access-token
     *   provider was configured
     */
    suspend fun poll(streamId: String, options: SsfPollOptions = SsfPollOptions()): SsfPollResult {
        val provider = tokenProvider ?: throw AuthError(
            "ssf.poll needs an accessTokenProvider (a client-credentials token carrying " +
                "ssf.manage, CONTRACT.md §32.7)",
        )
        // The builder already refused a base URL that does not parse.
        val url = client.baseUrl().toHttpUrl().newBuilder()
            .addPathSegment("ssf").addPathSegment("v1").addPathSegment("poll").addPathSegment(streamId)
            .build()
        val body = pollBody(options).toString().toRequestBody(JSON_MEDIA)
        val token = provider()

        var lastStatus: Int? = null
        val reply: JsonObject = Retry.withRetry(
            operation = "ssf.poll",
            enabled = client.retryEnabledForHelpers(),
            telemetry = client.telemetryForHelpers(),
            random = client.jitterForHelpers(),
            // §32.7: §16 applies to transport errors and 5xx (and 408 / 429,
            // its own table) — never to another 4xx.
            retryable = { lastStatus == null || Retry.isRetryableStatus(lastStatus!!) },
        ) { _ ->
            lastStatus = null
            val request = Request.Builder().url(url).post(body)
                .header("Authorization", "Bearer ${token.expose()}")
                .header("Accept", "application/json")
                .build()
            execute(request, "ssf.poll").use { response ->
                lastStatus = response.code
                if (!response.isSuccessful) throw mapPollFailure(response)
                parseObject(response, "ssf.poll")
            }
        }

        val moreAvailable = (reply["moreAvailable"] as? JsonPrimitive)?.booleanOrNull ?: false
        val events = mutableListOf<SecurityEvent>()
        val refused = mutableListOf<RefusedSet>()
        val sets = reply["sets"] as? JsonObject
        if (sets != null) {
            for ((jti, value) in sets) {
                val compact = (value as? JsonPrimitive)?.takeIf { it.isString }?.content
                if (compact == null) {
                    refused += RefusedSet(jti, SetFailureReason.MALFORMED)
                    continue
                }
                try {
                    events += verify(compact, jti)
                } catch (e: SetVerificationError) {
                    refused += RefusedSet(jti, e.failureReason)
                }
            }
        }
        return SsfPollResult(events, moreAvailable, refused)
    }

    private suspend fun verify(set: String, expectedJti: String?): SecurityEvent {
        // 1.
        val parts = set.split('.')
        if (parts.size != 3 || decodeOrNull(parts[2]) == null) {
            throw refuse(SetFailureReason.MALFORMED, "not three base64url parts")
        }
        val header = jsonObjectOf(parts[0])
        val claims = jsonObjectOf(parts[1])
        if (header == null || claims == null) {
            throw refuse(SetFailureReason.MALFORMED, "the header or payload is not a JSON object")
        }
        // 2.
        val typ = header.string("typ")
        if (typ == null ||
            !(typ.equals("secevent+jwt", ignoreCase = true) || typ.equals("application/secevent+jwt", ignoreCase = true))
        ) {
            throw refuse(SetFailureReason.INVALID_TYPE, "typ is not secevent+jwt")
        }
        // 3.
        if (header.string("alg") != "EdDSA") {
            throw refuse(SetFailureReason.INVALID_KEY, "alg is not EdDSA")
        }
        // 4.
        val kid = header.string("kid") ?: throw refuse(SetFailureReason.INVALID_KEY, "no kid")
        val key = keyFor(kid) ?: throw refuse(SetFailureReason.INVALID_KEY, "no key for the kid in the JWKS")
        // 5.
        val verified = try {
            JWSObject.parse(set).verify(Ed25519Verifier(key.toPublicJWK()))
        } catch (_: Exception) {
            false
        }
        if (!verified) throw refuse(SetFailureReason.INVALID_KEY, "the signature does not verify")
        // 6.
        val iss = claims.string("iss")
        if (iss == null || iss != issuer) {
            throw refuse(SetFailureReason.INVALID_ISSUER, "iss is not the configured issuer")
        }
        // 7.
        val aud = claims["aud"]
        val audienceMatches = when (aud) {
            is JsonPrimitive -> aud.isString && aud.content == audience
            is JsonArray -> aud.any { it is JsonPrimitive && it.isString && it.content == audience }
            else -> false
        }
        if (aud == null || !audienceMatches) {
            throw refuse(SetFailureReason.INVALID_AUDIENCE, "aud does not name this receiver")
        }
        // 8.
        if ("exp" in claims || "sub" in claims) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "a SET carries no exp and no sub")
        }
        val jti = claims.string("jti")?.takeIf { it.isNotEmpty() }
            ?: throw refuse(SetFailureReason.INVALID_REQUEST, "no jti")
        val iat = (claims["iat"] as? JsonPrimitive)?.takeIf { !it.isString }
            ?.let { it.longOrNull ?: it.doubleOrNull?.toLong() }
            ?: throw refuse(SetFailureReason.INVALID_REQUEST, "no numeric iat")
        val subId = claims["sub_id"] as? JsonObject
            ?: throw refuse(SetFailureReason.INVALID_REQUEST, "no sub_id object")
        val events = (claims["events"] as? JsonObject)?.takeIf { it.size == 1 }
            ?: throw refuse(SetFailureReason.INVALID_REQUEST, "events must have exactly one member")
        if (expectedJti != null && expectedJti != jti) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "the poll key is not the SET's jti")
        }
        val (eventType, event) = events.entries.first()
        // 9.
        if (!replayStore.checkAndRecord(jti, replayWindow)) {
            throw refuse(SetFailureReason.REPLAYED, "the jti was already accepted")
        }
        return SecurityEvent(
            jti = jti,
            iat = iat,
            iss = iss,
            aud = aud,
            txn = claims.string("txn"),
            eventType = eventType,
            event = event,
            subId = subId,
        )
    }

    /**
     * The Ed25519 key named [kid], from the cached JWKS; on a miss, ONE forced
     * refetch — no more often than once a minute (§32.7 step 4).
     *
     * A fetch failure is a [NetworkError], never `null`: an unreachable JWKS is
     * not a verdict on the SET.
     */
    private suspend fun keyFor(kid: String): OctetKeyPair? = keyLock.withLock {
        val cached = jwks ?: fetchJwks().also { jwks = it }
        find(cached, kid)?.let { return@withLock it }
        val now = System.nanoTime()
        val last = lastForcedRefetchNanos
        if (last != null && now - last < FORCED_REFETCH_INTERVAL.toNanos()) return@withLock null
        lastForcedRefetchNanos = now
        val fresh = fetchJwks()
        jwks = fresh
        find(fresh, kid)
    }

    private fun find(set: JWKSet, kid: String): OctetKeyPair? =
        set.keys.asSequence()
            .filterIsInstance<OctetKeyPair>()
            .firstOrNull { it.keyID == kid && it.curve == Curve.Ed25519 }

    private suspend fun fetchJwks(): JWKSet {
        val url = jwksUrl ?: resolveJwksUrl().also { jwksUrl = it }
        val request = Request.Builder().url(url).get().header("Accept", "application/json").build()
        execute(request, "ssf.jwks").use { response ->
            if (!response.isSuccessful) {
                throw NetworkError("ssf.jwks: the JWKS fetch failed (HTTP ${response.code})")
            }
            val text = response.body?.string().orEmpty()
            return try {
                JWKSet.parse(text)
            } catch (e: Exception) {
                throw NetworkError("ssf.jwks: the JWKS document does not parse", e)
            }
        }
    }

    private suspend fun resolveJwksUrl(): HttpUrl = when (keys) {
        is SsfKeySource.JwksUri -> secureUrl("jwks_uri", keys.uri)
        is SsfKeySource.DiscoveryUrl -> {
            val request = Request.Builder().url(secureUrl("discovery_url", keys.url)).get()
                .header("Accept", "application/json").build()
            val document = execute(request, "ssf.configuration").use { response ->
                if (!response.isSuccessful) {
                    throw NetworkError("ssf.configuration: the SSF configuration fetch failed (HTTP ${response.code})")
                }
                parseObject(response, "ssf.configuration")
            }
            if (document.string("issuer") != issuer) {
                throw NetworkError("ssf.configuration: the document's issuer is not the configured issuer")
            }
            val uri = document.string("jwks_uri")
                ?: throw NetworkError("ssf.configuration: the document carries no jwks_uri")
            try {
                secureUrl("jwks_uri", uri)
            } catch (e: ValidationError) {
                throw NetworkError("ssf.configuration: ${e.message}", e)
            }
        }
    }

    private fun mapPollFailure(response: Response): Throwable {
        val detail = try {
            val text = response.peekBody(MAX_ERROR_PEEK_BYTES).string()
            val obj = Json.parseToJsonElement(text).jsonObject
            (obj.string("message") ?: obj.string("error"))?.let { ": $it" }.orEmpty()
        } catch (_: Exception) {
            ""
        }
        return when (response.code) {
            400, 422 -> ValidationError("ssf.poll: rejected$detail")
            404 -> NotFoundError("ssf.poll: not found$detail")
            409 -> ConflictError("ssf.poll: conflict$detail")
            else -> ErrorMapper.fromHttpStatus(response.code, "ssf.poll failed", response)
        }
    }

    private fun pollBody(options: SsfPollOptions): JsonObject = buildJsonObject {
        options.maxEvents?.let { put("maxEvents", it) }
        options.returnImmediately?.let { put("returnImmediately", it) }
        options.ack?.let { ack -> put("ack", JsonArray(ack.map { JsonPrimitive(it) })) }
        options.setErrs?.let { errs ->
            put(
                "setErrs",
                JsonObject(
                    errs.mapValues { (_, e) ->
                        buildJsonObject {
                            put("err", e.err)
                            e.description?.let { put("description", it) }
                        }
                    },
                ),
            )
        }
    }

    private suspend fun execute(request: Request, operation: String): Response = withContext(Dispatchers.IO) {
        try {
            bare.newCall(request).execute()
        } catch (e: IOException) {
            throw NetworkError("$operation request failed: ${e.javaClass.simpleName}", e)
        }
    }

    private fun parseObject(response: Response, operation: String): JsonObject {
        val text = response.body?.string().orEmpty()
        return try {
            Json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw NetworkError("$operation: the response is not a JSON object", e)
        }
    }

    private fun secureUrl(label: String, raw: String): HttpUrl {
        val url = raw.toHttpUrlOrNull()
            ?: throw ValidationError("ssf.receiver: $label is not an absolute http(s) URL (CONTRACT.md §32.7)")
        if (url.scheme == "https" || isLoopback(url.host)) return url
        throw ValidationError(
            "ssf.receiver: $label must be https (http is accepted only on a loopback host) (CONTRACT.md §32.7)",
        )
    }

    companion object {
        /**
         * The replay window's floor and default: seven days, the transmitter's
         * buffer retention (§32.6). A shorter window would forget a `jti` the
         * transmitter can still re-send.
         */
        val MIN_REPLAY_WINDOW: Duration = Duration.ofDays(7)

        /** The shortest gap between two forced JWKS refetches (§32.7 step 4). */
        val FORCED_REFETCH_INTERVAL: Duration = Duration.ofSeconds(60)

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private const val MAX_ERROR_PEEK_BYTES = 8192L

        private fun refuse(reason: SetFailureReason, detail: String) = SetVerificationError(reason, detail)

        private fun decodeOrNull(part: String): ByteArray? =
            try {
                Base64.getUrlDecoder().decode(part)
            } catch (_: IllegalArgumentException) {
                null
            }

        private fun jsonObjectOf(part: String): JsonObject? {
            val bytes = decodeOrNull(part) ?: return null
            return try {
                Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)) as? JsonObject
            } catch (_: Exception) {
                null
            }
        }

        private fun JsonObject.string(key: String): String? =
            (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        private fun isLoopback(host: String): Boolean =
            host.equals("localhost", ignoreCase = true) || host == "127.0.0.1" || host == "::1"
    }
}
