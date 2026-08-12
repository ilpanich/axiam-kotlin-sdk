package io.axiam.sdk.ktor

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.Sensitive

/**
 * A configured `WWW-Authenticate: UMA` challenge emitter (CONTRACT.md §20.3,
 * emit half).
 *
 * Set one on [AxiamAuthConfig.umaChallenge] and a denial from [requireAccess]
 * stops being a bare 403: the guard mints a fresh permission ticket for the
 * action the caller lacked and returns it in the header, so a UMA-aware client
 * knows where to go for authority instead of only being told "no".
 *
 * **Opt-in, and deliberately so.** Emitting a challenge means minting a
 * credential — a wire call to the Protection API, and a live ticket, produced
 * on a path the caller did not explicitly request. A guard that did that on
 * every denial by default would turn each unauthorized request into a
 * Protection API call, which is a denial-of-service amplifier pointed at your
 * own authorization server. So it happens only where an application configured
 * one.
 *
 * **Failure is not escalation.** If minting fails — the PAT expired, the
 * Protection API is down, the resource declares none of the requested scopes —
 * the denial still surfaces as an ordinary 403 without a challenge. A caller
 * who was going to be refused is refused either way; letting a Protection API
 * outage turn a deny into a 503 would hand the outage a second consequence,
 * and letting it turn into an allow would be a security bug.
 *
 * @property realm the protection realm named in the header
 * @property asUri the authorization server the caller should redeem the ticket
 *   at — normally this deployment's issuer, read from discovery rather than
 *   concatenated by hand (§12.3 rule 6)
 * @property pat a Protection API Token: a *client-credentials* token carrying
 *   the `uma_protection` scope (§20.2 rule 1). A user token cannot stand in —
 *   a minted ticket is bound to the `client_id` that minted it
 * @property client the client whose `umaRequestTicket` mints the ticket
 */
public class UmaChallenger(
    public val realm: String,
    public val asUri: String,
    public val pat: Sensitive<String>,
    public val client: AxiamClient,
) {
    /**
     * Renders without the PAT (§7): a challenger is configuration an
     * application may reasonably log, and the credential inside it is not.
     */
    override fun toString(): String = "UmaChallenger(realm=$realm, asUri=$asUri, pat=$pat)"
}
