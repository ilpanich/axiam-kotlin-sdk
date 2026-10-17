package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import io.axiam.sdk.management.models.DirectoryConfig
import io.axiam.sdk.management.models.SamlServiceProvider
import io.axiam.sdk.management.models.SamlServiceProviderInput
import io.axiam.sdk.management.models.ScimTargetInput
import io.axiam.sdk.management.models.ScimTargetResponse
import io.axiam.sdk.management.models.SetDirectoryConfig
import io.axiam.sdk.management.models.SsfDeliveryMethod
import io.axiam.sdk.management.models.SsfEventType
import io.axiam.sdk.management.models.SsfStream
import io.axiam.sdk.management.models.SsfStreamInput
import io.axiam.sdk.management.models.SsfStreamStatus
import io.axiam.sdk.management.models.SsfSubjectFormat

// Read-modify-write helpers for the four §29–§32 replacement bodies.
//
// Each of these writes is a REPLACEMENT in which an omitted optional member
// takes its default rather than its stored value (§29.2, §30.2, §31.2, §32.2).
// Converting a read into the body carries every member over, so the caller
// changes only what they mean to change:
//
//     val sp = client.saml.getServiceProvider(id)
//     client.saml.updateServiceProvider(id, sp.toInput().copy(displayName = "Payroll (EU)"))
//
// The SECRET member of each input is left absent — a response never carries
// it (the server holds it write-only) and absent keeps the stored one.

/**
 * The `directory.set` body that re-states this configuration.
 *
 * `bindSecret` is absent: absent keeps the stored secret — unless the write
 * moves the connection (`url`, `start_tls`, `bind_dn`, `trust_anchors_pem`),
 * which needs the secret again (§30.3 rule 2).
 *
 * @return the replacement body
 */
fun DirectoryConfig.toInput(): SetDirectoryConfig = SetDirectoryConfig(
    baseDn = baseDn,
    bindDn = bindDn,
    bindSecret = null,
    enabled = enabled,
    groupBaseDn = groupBaseDn,
    groupFilter = groupFilter,
    groupMappings = groupMappings,
    groupMemberAttribute = groupMemberAttribute,
    groupNestingDepth = groupNestingDepth,
    jitProvisioning = jitProvisioning,
    kind = kind,
    startTls = startTls,
    syncIntervalSecs = syncIntervalSecs,
    trustAnchorsPem = trustAnchorsPem,
    url = url,
    userAttributeMap = userAttributeMap,
    userFilter = userFilter,
)

/**
 * The `saml.update_service_provider` body that re-states this registration
 * (§29.2). An enum value this SDK does not know (`UNKNOWN`) is carried over
 * as-is, and writing it is refused locally, before any request (§34.2 P12.2):
 * replace it before writing back.
 *
 * @return the replacement body
 */
fun SamlServiceProvider.toInput(): SamlServiceProviderInput = SamlServiceProviderInput(
    acsUrls = acsUrls,
    allowIdpInitiated = allowIdpInitiated,
    allowedGroups = allowedGroups,
    attributeMappings = attributeMappings,
    displayName = displayName,
    enabled = enabled,
    encryptAssertions = encryptAssertions,
    entityId = entityId,
    nameIdFormat = nameIdFormat,
    signResponses = signResponses,
    sloBinding = sloBinding,
    sloUrl = sloUrl,
    spEncryptionCertPem = spEncryptionCertPem,
    spSigningCertPem = spSigningCertPem,
    wantAuthnRequestsSigned = wantAuthnRequestsSigned,
)

/**
 * The `ssf.update_stream` body that re-states this stream (§32.2) — the **plain
 * converter**. To edit a stream you read, use [toInput] with changes instead.
 *
 * `authorizationHeader` and `clearAuthorizationHeader` are absent: absent
 * keeps the stored header — unless the update moves `endpoint_url` to another
 * origin, which needs one or the other (§32.3 rule 5).
 *
 * The body carries the `events_requested` **and** the `expected_updated_at`
 * that were read (contract 1.61). An `events_requested` of `[]` (the receiver's
 * "none") stays `[]` — omitting it would reset the stream to every allowed
 * event — and `expected_updated_at` is the response's **own string**
 * ([SsfStream.updatedAtRaw], contract 1.62), never the parsed instant rendered
 * again, so the write lands only on the version that was read and is otherwise
 * `409` (the receiver's own writes included): reload and retry.
 *
 * **The caller's duty (§32.2, contract 1.62).** This converter sends the
 * stream back as read; it cannot know that you are about to lower
 * `eventsAllowed`. If you lower it with `copy()`, **cutting `eventsRequested` to
 * the new `eventsAllowed` is yours to do, in the same call**: a requested list
 * left outside the new ceiling is refused `400`, and one left out altogether
 * *resets* the stream to every allowed event (the three meanings of
 * `events_requested`: absent resets, `[]` is none, a list is stored as given).
 * [toInput] with changes does the cut for you. Set `expectedUpdatedAt` to `null`
 * to replace whatever is stored: `null` is "none" and the key is left out.
 *
 * @return the replacement body
 */
fun SsfStream.toInput(): SsfStreamInput = SsfStreamInput(
    audience = audience,
    authorizationHeader = null,
    clearAuthorizationHeader = null,
    deliveryMethod = deliveryMethod,
    description = description,
    endpointUrl = endpointUrl,
    eventsAllowed = eventsAllowed,
    eventsRequested = eventsRequested,
    // The server's own spelling (§32.2, contract 1.62). Only a value built by
    // hand, never decoded from a response, has no raw string to send.
    expectedUpdatedAt = updatedAtRaw ?: updatedAt.toString(),
    receiverClientId = receiverClientId,
    status = status,
    statusReason = statusReason,
    subjectFormat = subjectFormat,
)

/**
 * The changes [toInput] applies over a stream that was read (§32.2, contract
 * 1.62). Every member defaults to "as read".
 *
 * The four members `ssf.update_stream` requires ([audience], [deliveryMethod],
 * [eventsAllowed], [receiverClientId]) are plain nullable values: `null` keeps
 * what was read. Every optional member is a [JsonNullable]: [JsonNullable.Absent]
 * (the default) keeps what was read, [JsonNullable.Value] replaces it, and
 * [JsonNullable.Null] is "none" — the key is **left out of the body** and `null`
 * is never sent (§27.11 rule 5), which on a replacement clears the member (a
 * `description` or `endpoint_url` back to null) or, for [expectedUpdatedAt],
 * replaces whatever is stored without the conditional.
 *
 * @property audience a new audience, or `null` to keep the one read
 * @property deliveryMethod a new delivery method, or `null` to keep the one read
 * @property eventsAllowed a new ceiling, or `null` to keep the one read
 * @property receiverClientId a new receiver client id, or `null` to keep the one read
 * @property description the description
 * @property endpointUrl the push endpoint
 * @property eventsRequested the events the receiver asked for. **Left alone
 *   ([JsonNullable.Absent]) while [eventsAllowed] is lowered, it is cut to the new
 *   ceiling;** named, it is sent as given and the server judges it. [JsonNullable.Null]
 *   leaves the key out, which *resets* the stream to every allowed event.
 * @property expectedUpdatedAt the `updated_at` the update is conditional on; as
 *   read by default, [JsonNullable.Null] for none
 * @property status the stream's status
 * @property statusReason the reason for the status
 * @property subjectFormat how users are named in the stream's SETs
 * @property authorizationHeader a push `Authorization` header to store (write-only)
 * @property clearAuthorizationHeader `true` removes the stored header
 */
data class SsfStreamChanges(
    val audience: String? = null,
    val deliveryMethod: SsfDeliveryMethod? = null,
    val eventsAllowed: List<SsfEventType>? = null,
    val receiverClientId: String? = null,
    val description: JsonNullable<String> = JsonNullable.Absent,
    val endpointUrl: JsonNullable<String> = JsonNullable.Absent,
    val eventsRequested: JsonNullable<List<SsfEventType>> = JsonNullable.Absent,
    val expectedUpdatedAt: JsonNullable<String> = JsonNullable.Absent,
    val status: JsonNullable<SsfStreamStatus> = JsonNullable.Absent,
    val statusReason: JsonNullable<String> = JsonNullable.Absent,
    val subjectFormat: JsonNullable<SsfSubjectFormat> = JsonNullable.Absent,
    val authorizationHeader: JsonNullable<Sensitive<String>> = JsonNullable.Absent,
    val clearAuthorizationHeader: JsonNullable<Boolean> = JsonNullable.Absent,
)

/**
 * The `ssf.update_stream` body for **this stream with [changes] applied** — the
 * change-taking read-modify-write form (§32.2, contract 1.62; §27.4 rule 5).
 * Use it instead of [toInput] with no changes whenever you edit a stream you
 * read.
 *
 * What the body carries, and why each point is a rule rather than a convenience:
 *
 *  - **`events_requested`, as read.** An update that omits it **resets** the
 *    stream to every event of `events_allowed`, widening what the receiver
 *    narrowed. The list that was read goes back as it was; an `[]` (the
 *    receiver's "none") goes back as `[]` and is never omitted.
 *  - **Cut to the new ceiling.** When [changes] lowers `eventsAllowed` and does
 *    not name `eventsRequested`, the requested list becomes the entries of the
 *    list read that are in the new ceiling, in their order (a request outside the
 *    ceiling is `400`). An `eventsRequested` named in [changes] is sent as given:
 *    the server judges it.
 *  - **`expected_updated_at`, as read** — the server's own string
 *    ([SsfStream.updatedAtRaw]), byte for byte, not the parsed instant rendered
 *    again. The update then lands only on the version you read, and a write made
 *    since (the receiver's own included) answers `409` (a
 *    [io.axiam.sdk.errors.ConflictError], never retried): read again and decide
 *    again. `JsonNullable.Null` in [changes] is "none": the key is left out of the
 *    body and `null` is never sent.
 *
 * `authorizationHeader` and `clearAuthorizationHeader` are absent unless
 * [changes] names them (absent keeps the stored header, §32.3 rule 5).
 *
 * @param changes what to change over the read; the default changes nothing
 * @return the replacement body
 */
fun SsfStream.toInput(changes: SsfStreamChanges): SsfStreamInput {
    val read = toInput()
    val ceiling = changes.eventsAllowed ?: read.eventsAllowed
    val requested: List<SsfEventType>? = when (val named = changes.eventsRequested) {
        is JsonNullable.Value -> named.value
        JsonNullable.Null -> null
        JsonNullable.Absent ->
            if (changes.eventsAllowed != null) read.eventsRequested?.filter { it in ceiling } else read.eventsRequested
    }
    return SsfStreamInput(
        audience = changes.audience ?: read.audience,
        authorizationHeader = changes.authorizationHeader.orElse(null),
        clearAuthorizationHeader = changes.clearAuthorizationHeader.orElse(null),
        deliveryMethod = changes.deliveryMethod ?: read.deliveryMethod,
        description = changes.description.orElse(read.description),
        endpointUrl = changes.endpointUrl.orElse(read.endpointUrl),
        eventsAllowed = ceiling,
        eventsRequested = requested,
        expectedUpdatedAt = changes.expectedUpdatedAt.orElse(read.expectedUpdatedAt),
        receiverClientId = changes.receiverClientId ?: read.receiverClientId,
        status = changes.status.orElse(read.status),
        statusReason = changes.statusReason.orElse(read.statusReason),
        subjectFormat = changes.subjectFormat.orElse(read.subjectFormat),
    )
}

/** The named value, `null` for [JsonNullable.Null] ("none"), [read] for [JsonNullable.Absent]. */
private fun <T> JsonNullable<T>.orElse(read: T?): T? = when (this) {
    is JsonNullable.Value -> value
    JsonNullable.Null -> null
    JsonNullable.Absent -> read
}

/**
 * The `scim_targets.update` body that re-states this target (§31.2).
 *
 * `credential` is absent: absent keeps the stored one — unless the write
 * changes what it is bound to (`base_url`, `auth.token_url`, `auth.type`),
 * which needs it again (§31.3 rule 2). An unknown `auth` / `scope` arm is
 * carried over and refused locally on encode: replace it before writing back.
 *
 * `expected_updated_at` is this read's `updated_at` (§31.3 rule 4, contract
 * 1.60): the write lands only if no other administrator has written the target
 * since, and is otherwise `409` — reload and retry. Set it to `null` with
 * `copy()` for the earlier last-writer-wins replacement.
 *
 * @return the replacement body
 */
fun ScimTargetResponse.toInput(): ScimTargetInput = ScimTargetInput(
    auth = auth,
    baseUrl = baseUrl,
    credential = null,
    deprovision = deprovision,
    enabled = enabled,
    expectedUpdatedAt = updatedAt,
    name = name,
    pushGroups = pushGroups,
    scope = scope,
    userNameFrom = userNameFrom,
)
