package io.axiam.sdk.errors

/**
 * One field-level complaint from a server that rejected a request body
 * (CONTRACT.md §27.4 rule 7).
 *
 * Present on a [ValidationError] only when the server actually reported
 * per-field detail; a server that says nothing more than "400" yields an empty
 * list rather than a fabricated entry.
 *
 * @property field   the offending field's name, as the server spelled it
 * @property message what the server said about it
 */
data class FieldError(val field: String, val message: String)

/**
 * A §27 management operation addressed something that does not exist
 * (HTTP 404).
 *
 * A SUB-TYPE of [AuthzError], not a peer of it: CONTRACT.md §27.4 rule 7 is
 * explicit that the three §27 classifications live *inside* the §2 taxonomy.
 * `catch (e: AuthzError)` written before §27 existed still catches this.
 *
 * Why [AuthzError] rather than [NetworkError]: on an access-controlled
 * surface, "no such object" and "no such object *that you may see*" are the
 * same response by design, and a server that distinguished them would be
 * leaking the existence of objects the caller cannot read.
 */
class NotFoundError(message: String) : AuthzError(message)

/**
 * A §27 management operation collided with the state already there
 * (HTTP 409): a name already taken, a certificate already revoked, a role that
 * already holds the grant.
 *
 * A SUB-TYPE of [AuthzError], not of [NetworkError]. §2 already maps 409 to
 * `AuthzError` as "resource-level access denied", and CONTRACT.md §27.4
 * rule 7 keeps that mapping rather than re-deciding it — the sub-type exists
 * to give the caller something to act on, not to move the status.
 *
 * Never retried: a conflict is the server telling the truth, not a transient
 * fault, and repeating the request cannot change it (§27.4 rule 8).
 */
class ConflictError(message: String) : AuthzError(message)

/**
 * A §27 management request body the server refused (HTTP 400 or 422).
 *
 * A SUB-TYPE of [NetworkError] (CONTRACT.md §27.4 rule 7). Never retried: the
 * body is wrong, and sending the same bytes again produces the same refusal.
 *
 * @property fields the server's per-field detail when it sent any, else empty
 */
class ValidationError(
    message: String,
    val fields: List<FieldError> = emptyList(),
) : NetworkError(message)
