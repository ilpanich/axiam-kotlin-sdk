package io.axiam.sdk.management

import io.axiam.sdk.management.models.DirectoryConfig
import io.axiam.sdk.management.models.SamlServiceProvider
import io.axiam.sdk.management.models.SamlServiceProviderInput
import io.axiam.sdk.management.models.ScimTargetInput
import io.axiam.sdk.management.models.ScimTargetResponse
import io.axiam.sdk.management.models.SetDirectoryConfig
import io.axiam.sdk.management.models.SsfStream
import io.axiam.sdk.management.models.SsfStreamInput

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
 * The `ssf.update_stream` body that re-states this stream (§32.2).
 *
 * `authorizationHeader` and `clearAuthorizationHeader` are absent: absent
 * keeps the stored header — unless the update moves `endpoint_url` to another
 * origin, which needs one or the other (§32.3 rule 5).
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
    receiverClientId = receiverClientId,
    status = status,
    statusReason = statusReason,
    subjectFormat = subjectFormat,
)

/**
 * The `scim_targets.update` body that re-states this target (§31.2).
 *
 * `credential` is absent: absent keeps the stored one — unless the write
 * changes what it is bound to (`base_url`, `auth.token_url`, `auth.type`),
 * which needs it again (§31.3 rule 2). An unknown `auth` / `scope` arm is
 * carried over and refused locally on encode: replace it before writing back.
 *
 * @return the replacement body
 */
fun ScimTargetResponse.toInput(): ScimTargetInput = ScimTargetInput(
    auth = auth,
    baseUrl = baseUrl,
    credential = null,
    deprovision = deprovision,
    enabled = enabled,
    name = name,
    pushGroups = pushGroups,
    scope = scope,
    userNameFrom = userNameFrom,
)
