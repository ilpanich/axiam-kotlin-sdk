package io.axiam.sdk.mcp

import io.axiam.sdk.ReasonCode
import io.axiam.sdk.errors.FieldError
import io.axiam.sdk.errors.ValidationError

/**
 * MCP resource-server helpers (CONTRACT.md §28, RFC 9728 + RFC 6750) — the
 * resource-server half of the Model Context Protocol authorization handshake:
 * publishing the RFC 9728 protected-resource metadata document that tells an
 * MCP client which authorization server guards this resource, and emitting
 * the `WWW-Authenticate` challenge that starts the client's discovery. AXIAM
 * is the authorization server and implements none of this — an MCP server
 * built with this SDK is the resource server, and [Mcp] is the whole of its
 * side.
 *
 * §28.0: **no operation here performs network I/O**, so §16's retry policy
 * and §9's single-flight refresh do not apply, and nothing in this object
 * touches the SDK client's own session. Both operations are pure local
 * computation, like `oidcBegin` (§12.1) and `umaParseChallenge` (§20.5).
 *
 * **Nothing here is a source of truth about a token.** The document is a
 * claim a resource server publishes about itself; the challenge is a hint it
 * gives a caller that already failed. Whether a request is authorized stays
 * §10.1's and §11's decision, unchanged and unreachable from here.
 *
 * `serveProtectedResourceMetadata` — the third §28.1 operation — is
 * `io.axiam.sdk.ktor.serveProtectedResourceMetadata`, a `Route` extension: it
 * needs a Ktor route to register on, which does not belong in this
 * framework-independent object. Spring Boot users reuse the Java SDK's
 * `io.axiam.sdk.mcp.Mcp` and its `io.axiam.sdk.spring` collaborators — see
 * the README.
 */
object Mcp {

    /** RFC 9728 §3.1's well-known prefix — inserted between a resource's authority and its path (§28.3). */
    const val PROTECTED_RESOURCE_METADATA_PREFIX: String = "/.well-known/oauth-protected-resource"

    /**
     * `protectedResourceMetadata(...)` (CONTRACT.md §28.1) — build and
     * validate the RFC 9728 protected-resource metadata document this server
     * publishes about itself, and derive the path and URL it is served at.
     *
     * **Validation happens here and it refuses; it never repairs.** Every
     * §28.2 rule is checked before any route exists and before any request is
     * served, and a violation throws [ValidationError]. Nothing is
     * normalised, trimmed, lowercased or re-encoded to make it pass: a value
     * that needs adjusting is a configuration mistake an operator fixes in
     * one line, and a helper that quietly fixed it would publish a document
     * describing a resource server that does not exist.
     *
     * **Nothing in the document may come from a request** (§28.2 rule 8).
     * Both [resource] and [authorizationServers] are configuration; this SDK
     * offers no option to build either from the `Host` header, the
     * `Forwarded`/`X-Forwarded-*` family or the request URL, because a
     * document assembled from the request is a document an attacker can
     * point at an authorization server of their choosing — the whole
     * handshake redirected with one header.
     *
     * @param resource the resource identifier: absolute, `https` (or `http`
     *   on a loopback host), no query, no fragment. A trailing slash is
     *   significant
     * @param authorizationServers the issuer identifiers of the authorization
     *   servers guarding it — at least one, no duplicates, no query, no
     *   fragment
     * @param scopesSupported the scope tokens this resource server
     *   understands. Order is preserved, duplicates are refused, and an
     *   empty list omits the member
     * @param bearerMethodsSupported defaults to `["header"]`, which is the
     *   only accepted value in this contract version
     * @param resourceDocumentation optional documentation page for a human.
     *   May carry a query and a fragment; omitted from the document when
     *   `null`
     * @throws ValidationError when any CONTRACT.md §28.2 rule is violated
     */
    fun protectedResourceMetadata(
        resource: String,
        authorizationServers: List<String>,
        scopesSupported: List<String>,
        bearerMethodsSupported: List<String> = DEFAULT_BEARER_METHODS,
        resourceDocumentation: String? = null,
    ): ProtectedResourceMetadata {
        val op = "protectedResourceMetadata"

        // Rule 1 + rule 2.
        val parsed = requireAbsoluteUri(op, "resource", resource, IDENTIFIER)

        // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
        if (authorizationServers.isEmpty()) {
            refuse(
                op,
                "authorization_servers",
                "must name at least one authorization server — a document that names none answers none of the " +
                    "question the client asked",
            )
        }
        val seenServers = LinkedHashSet<String>()
        for (entry in authorizationServers) {
            requireAbsoluteUri(op, "authorization_servers", entry, IDENTIFIER)
            if (!seenServers.add(entry)) {
                refuse(op, "authorization_servers", "duplicate entry \"$entry\"")
            }
        }

        // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
        val seenScopes = LinkedHashSet<String>()
        for (scope in scopesSupported) {
            if (scope.isEmpty() || !isAll(scope, ::isNqchar)) {
                refuse(
                    op,
                    "scopes_supported",
                    "\"$scope\" is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control " +
                        "character, no non-ASCII)",
                )
            }
            if (!seenScopes.add(scope)) {
                refuse(op, "scopes_supported", "duplicate scope \"$scope\"")
            }
        }

        // Rule 6: exactly ["header"].
        if (bearerMethodsSupported.size != 1 || bearerMethodsSupported[0] != "header") {
            refuse(
                op,
                "bearer_methods_supported",
                "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential " +
                    "from the Authorization header alone, so $bearerMethodsSupported would describe behaviour " +
                    "this SDK does not have",
            )
        }

        // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
        if (resourceDocumentation != null) {
            requireAbsoluteUri(op, "resource_documentation", resourceDocumentation, LOCATOR)
        }

        val document = ProtectedResourceMetadataDocument(
            resource = resource,
            authorizationServers = seenServers.toList(),
            scopesSupported = seenScopes.toList().ifEmpty { null },
            bearerMethodsSupported = DEFAULT_BEARER_METHODS,
            resourceDocumentation = resourceDocumentation,
        )
        val metadataPath = deriveMetadataPath(parsed.path)
        return ProtectedResourceMetadata(
            document = document,
            metadataPath = metadataPath,
            metadataUrl = "${parsed.scheme}://${parsed.authority}$metadataPath",
        )
    }

    /**
     * `bearerChallenge(...)` (CONTRACT.md §28.4) — build the **value** of a
     * `WWW-Authenticate` header, never the whole header line and never a map.
     * The caller sets the header.
     *
     * Parameters appear in a fixed order — `error`, `error_description`,
     * `scope`, `resource_metadata` — separated by exactly `, `.
     * `resource_metadata` is always present; the other three are omitted
     * when not given.
     *
     * **Every value is quoted and no value is ever escaped.** RFC 6750 §3
     * restricts each parameter to a character set that cannot contain `"` or
     * `\`, so a value needing an escape is a value that does not belong in a
     * challenge: this function refuses it rather than escaping, truncating
     * or stripping it. A challenge is built from the code's own constants
     * and a route's own configuration, so an invalid one is a programming
     * error, not a runtime condition to degrade around.
     *
     * @param resourceMetadataUrl the document's URL — the one parameter that
     *   is always present. May carry a query and a fragment
     * @param error one of RFC 6750 §3.1's three codes, or `null` when the
     *   request carried no authentication information at all
     * @param errorDescription a human-readable description, for an
     *   application building **its own** challenge for its own 400. This
     *   SDK's own guards never set it: every distinction a 401 draws for an
     *   unauthenticated stranger is an oracle
     * @param scope the scope the route asked for, verbatim — one or more
     *   tokens joined by a single space
     * @throws ValidationError when any parameter is outside RFC 6750's syntax
     */
    fun bearerChallenge(
        resourceMetadataUrl: String,
        error: BearerChallengeError? = null,
        errorDescription: String? = null,
        scope: String? = null,
    ): String {
        val op = "bearerChallenge"
        val params = mutableListOf<String>()

        error?.let { params += "error=\"${it.wireValue}\"" }

        if (errorDescription != null) {
            if (errorDescription.isEmpty() || !isAll(errorDescription, ::isNqschar)) {
                refuse(
                    op,
                    "error_description",
                    "must be one or more NQSCHAR (no '\"', no '\\', no control character, no non-ASCII) — a " +
                        "value needing an escape does not belong in a challenge",
                )
            }
            params += "error_description=\"$errorDescription\""
        }

        if (scope != null) {
            if (scope.isEmpty()) {
                refuse(op, "scope", "must be one or more scope tokens joined by a single space")
            }
            for (token in scope.split(" ")) {
                if (token.isEmpty() || !isAll(token, ::isNqchar)) {
                    refuse(
                        op,
                        "scope",
                        "\"$scope\" is not a space-joined list of scope tokens — no leading, trailing or " +
                            "doubled space, and no empty token",
                    )
                }
            }
            params += "scope=\"$scope\""
        }

        requireAbsoluteUri(op, "resource_metadata", resourceMetadataUrl, LOCATOR)
        if (!isAll(resourceMetadataUrl, ::isNqchar)) {
            refuse(
                op,
                "resource_metadata",
                "must carry no '\"', no '\\', no space and no control character — a correctly encoded URL " +
                    "cannot, so one that does has not been encoded",
            )
        }
        params += "resource_metadata=\"$resourceMetadataUrl\""

        return "Bearer " + params.joinToString(", ")
    }
}

// ---------------------------------------------------------------------------
// §28.5 guard-support (internal): consumed only by io.axiam.sdk.ktor. Spring
// Boot reuses the Java SDK's own io.axiam.sdk.mcp.Mcp, so none of this is
// framework-independent public API — the three canonical operations above
// are the whole of it.
// ---------------------------------------------------------------------------

/**
 * The precomputed CONTRACT.md §28 state a Ktor guard carries once
 * `resourceMetadataUrl` is configured: the two challenges that do not depend
 * on a route's own scope, plus the exempted document path. Built once, at
 * plugin-install time, by [mcpGuardChallenges].
 *
 * There is deliberately no precomputed `insufficient_scope` vector here:
 * `AxiamAuthentication` is one plugin instance shared by every route in the
 * application, each with its own `requireAccess(..., scope = ...)` call, so
 * — following the Java SDK's `AxiamAuthorizationInterceptor`, which is in the
 * identical position for Spring MVC — that vector is built fresh per denial
 * by [challengeFor403] from [resourceMetadataUrl] rather than baked in here
 * for one route.
 */
internal data class McpGuardChallenges(
    val resourceMetadataUrl: String,
    val noCredential: String,
    val invalidToken: String,
    val metadataPath: String,
)

/**
 * Validates a guard's §28 configuration and precomputes the challenges it
 * will emit. Called once, when `AxiamAuthentication` is installed — never
 * per-request.
 *
 * Returns `null` when [resourceMetadataUrl] is `null`: §28 is opt-in, and
 * with the option absent the guard behaves exactly as it did before §28
 * existed — no header on any response, no status changed, no body changed.
 *
 * **[expectedAudience] is mandatory once [resourceMetadataUrl] is set**, and
 * the refusal names both options. A resource server that publishes "tokens
 * for me carry this `aud`" and then does not check `aud` has published a
 * claim it does not honour, and a token minted for a *different* resource
 * server opens it. That is the confusion RFC 8707 exists to prevent, so this
 * is a refusal rather than a warning.
 *
 * @param resourceMetadataUrl `AxiamAuthConfig.resourceMetadataUrl`, or `null` when unset
 * @param expectedAudience the client's own already-configured §10.1 row 6
 *   expected audience ([io.axiam.sdk.AxiamClient.expectedAudience]) — §28
 *   adds no second audience option
 * @param operation the guard's name, so the refusal says which guard refused
 * @throws ValidationError when [resourceMetadataUrl] is set without [expectedAudience], or either is outside §28.4's syntax
 */
internal fun mcpGuardChallenges(
    resourceMetadataUrl: String?,
    expectedAudience: String?,
    operation: String,
): McpGuardChallenges? {
    if (resourceMetadataUrl == null) return null

    if (expectedAudience.isNullOrEmpty()) {
        refuse(
            operation,
            "resourceMetadataUrl",
            "requires expectedAudience to be set on the same client (CONTRACT.md §28.5 rule 2) — announcing a " +
                "resource identifier obliges this server to check that an inbound token's `aud` is that " +
                "identifier, and a resource server that announces itself without checking is opened by a token " +
                "minted for somebody else",
        )
    }

    val parsed = requireAbsoluteUri(operation, "resourceMetadataUrl", resourceMetadataUrl, LOCATOR)
    return McpGuardChallenges(
        resourceMetadataUrl = resourceMetadataUrl,
        noCredential = Mcp.bearerChallenge(resourceMetadataUrl),
        invalidToken = Mcp.bearerChallenge(resourceMetadataUrl, error = BearerChallengeError.INVALID_TOKEN),
        metadataPath = parsed.path.ifEmpty { "/" },
    )
}

/**
 * Picks between §28.4's first two vectors for a 401: [McpGuardChallenges.invalidToken]
 * when the request carried a credential, [McpGuardChallenges.noCredential]
 * when it carried none.
 *
 * §28.4 is explicit that the absent `error` is not an oversight — RFC 6750 §3
 * says a resource server SHOULD NOT name an error code when the request
 * carried no authentication information, because no credential is not a bad
 * credential.
 */
internal fun challengeFor401(challenges: McpGuardChallenges, credentialPresented: Boolean): String =
    if (credentialPresented) challenges.invalidToken else challenges.noCredential

/**
 * §28.5 rule 5: the one class of 403 that carries a challenge, and only it.
 *
 * A `no_grant` denial on a route that named a scope means *ask for more*,
 * which is exactly what a challenge invites a client to do. A
 * `denied_by_rule` denial means *an administrator has already decided*, and
 * challenging on it sends an MCP client all the way around the
 * authorization loop to arrive at the identical 403. An absent or
 * unrecognised `reasonCode` — an older server, a value this SDK predates —
 * is not eligible either: §11 rule 9 requires an unknown code to leave the
 * outcome alone, and the outcome here is a header-free 403.
 *
 * @param challenges the guard's precomputed challenges, or `null` when §28 is off
 * @param reasonCode the decision's `reason_code`, verbatim
 * @param scope the route's own scope argument, verbatim, or `null` for none
 * @return the challenge to emit, or `null` when this 403 gains no header
 */
internal fun challengeFor403(challenges: McpGuardChallenges?, reasonCode: String?, scope: String?): String? {
    if (challenges == null || scope == null || reasonCode != ReasonCode.NO_GRANT) return null
    return Mcp.bearerChallenge(challenges.resourceMetadataUrl, error = BearerChallengeError.INSUFFICIENT_SCOPE, scope = scope)
}

/**
 * Is this request the unauthenticated `GET`/`HEAD` of the metadata document?
 *
 * §28.3 rule 2 requires the document to be reachable with no credential of
 * any kind, and requires the SDK to exempt the path explicitly since the §10
 * guard (`AxiamAuthentication`) runs globally — a document that 401s cannot
 * start the handshake it exists to start: the client would be holding a 401
 * and being told to go read a page that answers 401.
 *
 * The exemption is derived from [challenges], so it exists only where §28 is
 * configured and covers exactly the one path that option names.
 *
 * @param path the request's path, with no query string (as Ktor's `ApplicationRequest.path()` returns it)
 */
internal fun isMetadataDocumentRequest(challenges: McpGuardChallenges?, method: String?, path: String?): Boolean {
    if (challenges == null || path == null) return false
    val verb = method?.uppercase() ?: ""
    if (verb != "GET" && verb != "HEAD") return false
    return path == challenges.metadataPath
}

/**
 * §28.5 rule 3: where `io.axiam.sdk.ktor.serveProtectedResourceMetadata` can
 * see the guard it is paired with, it MUST refuse the configuration at
 * startup unless the two agree — the guard's `resourceMetadataUrl` equals
 * [metadata]'s [ProtectedResourceMetadata.metadataUrl], and the guard's
 * expected audience equals [metadata]'s [ProtectedResourceMetadataDocument.resource].
 *
 * Both comparisons are simple string equality (RFC 3986 §6.2.1): no
 * normalisation, no case folding of the host, no trailing-slash tolerance.
 * Passing both arguments as `null` skips the check entirely — the guard is
 * configured in another process, this side can see only its own value, and
 * nothing can be checked.
 *
 * @throws ValidationError when either given value does not match [metadata]
 */
internal fun requireMetadataMatchesGuard(
    metadata: ProtectedResourceMetadata,
    guardResourceMetadataUrl: String?,
    guardExpectedAudience: String?,
) {
    if (guardResourceMetadataUrl == null && guardExpectedAudience == null) return
    val op = "serveProtectedResourceMetadata"
    if (guardResourceMetadataUrl != metadata.metadataUrl) {
        refuse(
            op,
            "resourceMetadataUrl",
            "is \"$guardResourceMetadataUrl\" but this document is published at \"${metadata.metadataUrl}\" — " +
                "the challenge would point at a document that is not this resource server's",
        )
    }
    if (guardExpectedAudience != metadata.document.resource) {
        refuse(
            op,
            "expectedAudience",
            "is \"$guardExpectedAudience\" but this document announces \"${metadata.document.resource}\" — the " +
                "document would announce one identifier while the guard checked `aud` against another, so every " +
                "token the flow produced would be refused",
        )
    }
}

// ---------------------------------------------------------------------------
// Validation plumbing (private) — §28.2 rules 1-2-3-7, §28.4's character
// classes. Ported from the reference TypeScript implementation and the Java
// SDK's io.axiam.sdk.mcp.Mcp; deliberately not java.net.URI/kotlin.io.URI,
// which normalise (resolve `..`, re-encode) where §28.2 forbids adjusting a
// value to make it pass, and §28.3 derives the document's own path from the
// string exactly as written.
// ---------------------------------------------------------------------------

private val DEFAULT_BEARER_METHODS = listOf("header")

/**
 * The three hosts §28.2 rule 2 lets an `http` URL use, and the only ones.
 * AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim — there is
 * deliberately no flag, environment variable or debug build that widens
 * this.
 */
private val LOOPBACK_HOSTS = setOf("127.0.0.1", "[::1]", "localhost")

/** `scheme://authority[path][?query][#fragment]`, matched against the caller's string exactly as given. */
private val ABSOLUTE_URI = Regex("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)(\\?[^#]*)?(#[\\s\\S]*)?$")

/** The pieces of an absolute URI, sliced out of the caller's string without normalisation. */
private data class ParsedUri(
    val scheme: String,
    val authority: String,
    val path: String,
    val hasQuery: Boolean,
    val hasFragment: Boolean,
)

private fun parseAbsoluteUri(raw: String): ParsedUri? {
    val match = ABSOLUTE_URI.matchEntire(raw) ?: return null
    val authority = match.groupValues[2]
    if (authority.isEmpty()) return null
    return ParsedUri(
        scheme = match.groupValues[1],
        authority = authority,
        path = match.groupValues[3],
        hasQuery = match.groups[4] != null,
        hasFragment = match.groups[5] != null,
    )
}

/**
 * The host inside an authority: `userinfo@` stripped, port stripped, an IPv6
 * literal's brackets kept (so `[::1]` compares as §28.2 rule 2 spells it).
 *
 * Stripping `userinfo` is what makes `http://localhost@evil.example.com/` a
 * refusal rather than a loopback pass — the host there is `evil.example.com`.
 */
private fun hostOf(authority: String): String {
    val at = authority.lastIndexOf('@')
    val hostport = if (at >= 0) authority.substring(at + 1) else authority
    if (hostport.startsWith("[")) {
        val close = hostport.indexOf(']')
        return if (close < 0) hostport else hostport.substring(0, close + 1)
    }
    val colon = hostport.indexOf(':')
    return if (colon < 0) hostport else hostport.substring(0, colon)
}

/** How much of §28.2 rule 1 a particular member is held to — rule 7 and §28.4's `resource_metadata` relax two parts of it. */
private data class UriPolicy(val allowQuery: Boolean, val allowFragment: Boolean)

private val IDENTIFIER = UriPolicy(allowQuery = false, allowFragment = false)
private val LOCATOR = UriPolicy(allowQuery = true, allowFragment = true)

/** §28.2 rules 1 and 2, applied to one member. Returns the parse so a caller that needs the path (§28.3) does not parse twice. */
private fun requireAbsoluteUri(operation: String, field: String, raw: String?, policy: UriPolicy): ParsedUri {
    if (raw.isNullOrEmpty()) refuse(operation, field, "must be a non-empty absolute URI")
    val parsed = parseAbsoluteUri(raw)
        ?: refuse(operation, field, "must be an absolute URI with a scheme and an authority, not \"$raw\"")
    if (parsed.hasQuery && !policy.allowQuery) {
        refuse(operation, field, "must carry no query — §28.3 derives the metadata path from it")
    }
    if (parsed.hasFragment && !policy.allowFragment) {
        refuse(operation, field, "must carry no fragment")
    }
    val scheme = parsed.scheme.lowercase()
    if (scheme == "https") return parsed
    if (scheme == "http" && LOOPBACK_HOSTS.contains(hostOf(parsed.authority).lowercase())) return parsed
    refuse(
        operation,
        field,
        "must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and \"$raw\" is neither",
    )
}

/** §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment between the authority and the path. */
private fun deriveMetadataPath(resourcePath: String): String =
    if (resourcePath.isEmpty() || resourcePath == "/") {
        Mcp.PROTECTED_RESOURCE_METADATA_PREFIX
    } else {
        Mcp.PROTECTED_RESOURCE_METADATA_PREFIX + resourcePath
    }

/** `NQCHAR`: `%x21` / `%x23`-`%x5B` / `%x5D`-`%x7E`. No space, no `"`, no `\`, no control, no non-ASCII. */
private fun isNqchar(c: Char): Boolean {
    val code = c.code
    return code == 0x21 || code in 0x23..0x5b || code in 0x5d..0x7e
}

/** `NQSCHAR`: `NQCHAR` plus the space (`%x20`). */
private fun isNqschar(c: Char): Boolean = c.code == 0x20 || isNqchar(c)

private fun isAll(value: String, predicate: (Char) -> Boolean): Boolean = value.all(predicate)

/**
 * Raises §28's refusal.
 *
 * §28.6 pins the error taxonomy: "§28's refusals are `ValidationError`; no
 * new type". A refusal is raised from the §28 operation itself — a document
 * or a challenge is built from the code's own constants and a route's own
 * configuration, so an invalid one is a programming error and not a runtime
 * condition to degrade around.
 */
private fun refuse(operation: String, field: String, message: String): Nothing =
    throw ValidationError("$operation: $field $message (CONTRACT.md §28)", listOf(FieldError(field, message)))
