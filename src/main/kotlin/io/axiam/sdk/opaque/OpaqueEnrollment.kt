package io.axiam.sdk.opaque

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The `opaque` object CONTRACT.md §23 defines: a registration record and the
 * server-issued session handle identifying the exchange it came from.
 *
 * The server cannot build this — it never sees the plaintext — so any request
 * that **sets** a password has to carry it: `POST /api/v1/users`,
 * `/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`.
 *
 * Note what is *not* here. The SRP enrolment this replaces carried a salt, a
 * group and a full set of KDF costs, and required the account's canonical
 * username — passing an email produced a verifier no login could ever satisfy,
 * and renaming a user invalidated their verifier outright. A record binds to a
 * credential identifier the server chooses, and the key-stretching parameters
 * are the server's, so there is nothing here a caller can get wrong.
 *
 * @property opaqueSession the handle `register/start` issued.
 * @property registrationRecord the hex `RegistrationRecord`.
 */
public data class OpaqueEnrollment(
    val opaqueSession: String,
    val registrationRecord: String,
) {
    /** Renders this enrolment as the JSON object the password-setting endpoints accept. */
    public fun toJson(): JsonObject = buildJsonObject {
        put("opaque_session", opaqueSession)
        put("registration_record", registrationRecord)
    }
}
