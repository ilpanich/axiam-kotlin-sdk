package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * An RFC 7591 §3.2.1 / RFC 7592 §3 client information response — the
 * registration [io.axiam.sdk.AxiamClient.readClientRegistration],
 * [io.axiam.sdk.AxiamClient.updateClientRegistration] and
 * [io.axiam.sdk.AxiamClient.deleteClientRegistration] act on (CONTRACT.md
 * §28.12).
 *
 * [registrationAccessToken] and [clientSecret] are [Sensitive] (§28.12.4):
 * `toString()` renders both as `[SENSITIVE]`, and the type has no
 * kotlinx.serialization serializer, so no JSON encoder can reach them either.
 *
 * Every member the server sent that this type does not name — and every named
 * member that arrived with an unexpected JSON type — is kept verbatim in
 * [extra]. RFC 7591 §3.2.1 lets a server add members, and because an update
 * is a **full replacement**, a member a read returned and an update left out
 * is a member the server deletes. Passing a read's result (or a `copy()` of
 * it) straight to `updateClientRegistration` therefore sends it back intact,
 * including `jwks` / `jwks_uri` and the CIBA `backchannel_*` members.
 *
 * @property clientId the client's `client_id`
 * @property clientIdIssuedAt when the client id was issued (seconds since the
 *   epoch); never sent on an update
 * @property clientName the registered display name
 * @property redirectUris the registered redirect URIs
 * @property grantTypes the registered grant types
 * @property responseTypes the registered response types
 * @property tokenEndpointAuthMethod how the client authenticates at the token
 *   endpoint; the server refuses an update that changes it
 * @property scope the registered scope, space-separated
 * @property registrationClientUri where this registration is read, replaced and
 *   deleted; never sent on an update
 * @property clientSecretExpiresAt when the client secret expires (`0` = never);
 *   never sent on an update
 * @property jwks the client's JWK Set, for a `private_key_jwt` client
 * @property jwksUri where the client's JWK Set is published
 * @property clientSecret the client secret — present only on the registration
 *   response itself, never on a read or an update; never sent back
 * @property registrationAccessToken the registration access token — present on
 *   the registration response and, **rotated**, on every update response;
 *   absent on a read; never sent in a body
 * @property extra every other member of the response, verbatim
 */
data class ClientRegistration(
    val clientId: String,
    val clientIdIssuedAt: Long? = null,
    val clientName: String? = null,
    val redirectUris: List<String> = emptyList(),
    val grantTypes: List<String> = emptyList(),
    val responseTypes: List<String> = emptyList(),
    val tokenEndpointAuthMethod: String? = null,
    val scope: String? = null,
    val registrationClientUri: String? = null,
    val clientSecretExpiresAt: Long? = null,
    val jwks: JsonElement? = null,
    val jwksUri: String? = null,
    val clientSecret: Sensitive<String>? = null,
    val registrationAccessToken: Sensitive<String>? = null,
    val extra: Map<String, JsonElement> = emptyMap(),
) {

    /**
     * The RFC 7592 §2.2 replacement body (§28.12.2 rule 4): every member but
     * the five the server states, with `client_id` set to this registration's
     * own.
     */
    internal fun updateBody(): JsonObject {
        val body = LinkedHashMap<String, JsonElement>(extra)
        for (key in SERVER_STATED_MEMBERS) body.remove(key)
        body["client_id"] = JsonPrimitive(clientId)
        clientName?.let { body["client_name"] = JsonPrimitive(it) }
        body["redirect_uris"] = stringArray(redirectUris)
        body["grant_types"] = stringArray(grantTypes)
        body["response_types"] = stringArray(responseTypes)
        tokenEndpointAuthMethod?.let { body["token_endpoint_auth_method"] = JsonPrimitive(it) }
        scope?.let { body["scope"] = JsonPrimitive(it) }
        jwks?.let { body["jwks"] = it }
        jwksUri?.let { body["jwks_uri"] = JsonPrimitive(it) }
        return JsonObject(body)
    }

    companion object {
        /**
         * The members `updateClientRegistration` never sends (§28.12.2 rule 4).
         * The first four the server refuses with `400 invalid_request` when
         * present; `client_secret` it never accepts back.
         */
        internal val SERVER_STATED_MEMBERS: List<String> = listOf(
            "registration_access_token",
            "registration_client_uri",
            "client_secret_expires_at",
            "client_id_issued_at",
            "client_secret",
        )

        /**
         * Decodes a client information response, tolerating unknown members.
         *
         * A member of an unexpected JSON type is kept in [extra] rather than
         * dropped: a replacement must not lose what the server holds.
         *
         * @throws NetworkError when [json] carries no string `client_id`
         */
        fun fromJson(json: JsonObject): ClientRegistration {
            val map = LinkedHashMap<String, JsonElement>(json)

            fun takeString(key: String): String? {
                val value = map.remove(key) ?: return null
                if (value is JsonPrimitive && value.isString) return value.content
                if (value !is JsonNull) map[key] = value
                return null
            }

            fun takeLong(key: String): Long? {
                val value = map.remove(key) ?: return null
                val number = (value as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
                if (number != null) return number
                if (value !is JsonNull) map[key] = value
                return null
            }

            fun takeList(key: String): List<String> {
                val value = map.remove(key) ?: return emptyList()
                if (value is JsonArray) {
                    return value.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                }
                if (value !is JsonNull) map[key] = value
                return emptyList()
            }

            val clientId = takeString("client_id")
                ?: throw NetworkError("client registration response carries no client_id")
            val jwks = map.remove("jwks")?.takeIf { it !is JsonNull }
            return ClientRegistration(
                clientId = clientId,
                clientIdIssuedAt = takeLong("client_id_issued_at"),
                clientName = takeString("client_name"),
                redirectUris = takeList("redirect_uris"),
                grantTypes = takeList("grant_types"),
                responseTypes = takeList("response_types"),
                tokenEndpointAuthMethod = takeString("token_endpoint_auth_method"),
                scope = takeString("scope"),
                registrationClientUri = takeString("registration_client_uri"),
                clientSecretExpiresAt = takeLong("client_secret_expires_at"),
                jwks = jwks,
                jwksUri = takeString("jwks_uri"),
                clientSecret = takeString("client_secret")?.let { Sensitive.of(it) },
                registrationAccessToken = takeString("registration_access_token")?.let { Sensitive.of(it) },
                extra = map.toMap(),
            )
        }

        private fun stringArray(items: List<String>): JsonArray = JsonArray(items.map { JsonPrimitive(it) })
    }
}
