package io.axiam.sdk.mcp

import io.axiam.sdk.errors.ValidationError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §28.9 required tests 1 and 2 — the two that need no framework:
 * the document's shape and its validation negatives, and the challenge's
 * quoting and its refusals. Tests 3, 4 and 5, and the off-by-default
 * regression, live in `io.axiam.sdk.ktor.KtorMcpTest` — they need a route
 * behind the guard.
 *
 * §28.9's fixture, used throughout:
 *
 * ```
 * resource                 = "https://mcp.example.com/mcp"
 * authorization_servers    = ["https://axiam.example.com"]
 * scopes_supported         = ["mcp:read", "mcp:tools"]
 * bearer_methods_supported = ["header"]
 * resource_documentation   = "https://mcp.example.com/docs"
 * metadata_path            = "/.well-known/oauth-protected-resource/mcp"
 * metadata_url             = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
 * expected_audience        = "https://mcp.example.com/mcp"
 * ```
 */
class McpTest {

    private val resource = "https://mcp.example.com/mcp"
    private val authorizationServers = listOf("https://axiam.example.com")
    private val scopesSupported = listOf("mcp:read", "mcp:tools")
    private val resourceDocumentation = "https://mcp.example.com/docs"
    private val metadataPath = "/.well-known/oauth-protected-resource/mcp"
    private val metadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    private fun fixture() = Mcp.protectedResourceMetadata(
        resource = resource,
        authorizationServers = authorizationServers,
        scopesSupported = scopesSupported,
        resourceDocumentation = resourceDocumentation,
    )

    // -----------------------------------------------------------------
    // §28.9 test 1 — the document and its validation
    // -----------------------------------------------------------------

    @Test
    fun `produces the exact JSON of §28-2 from the fixture`() {
        val metadata = fixture()

        val parsed = Json.parseToJsonElement(metadata.document.toJson()).jsonObject()
        assertEquals(resource, parsed["resource"]?.jsonPrimitive?.content)
        assertEquals(authorizationServers, parsed["authorization_servers"]?.jsonArray?.map { it.jsonPrimitive.content })
        assertEquals(scopesSupported, parsed["scopes_supported"]?.jsonArray?.map { it.jsonPrimitive.content })
        assertEquals(listOf("header"), parsed["bearer_methods_supported"]?.jsonArray?.map { it.jsonPrimitive.content })
        assertEquals(resourceDocumentation, parsed["resource_documentation"]?.jsonPrimitive?.content)
        assertEquals(
            setOf("resource", "authorization_servers", "scopes_supported", "bearer_methods_supported", "resource_documentation"),
            parsed.keys,
        )
        assertEquals(metadataPath, metadata.metadataPath)
        assertEquals(metadataUrl, metadata.metadataUrl)
    }

    @Test
    fun `derives every metadata_path in §28-3's table`() {
        val cases = listOf(
            "https://mcp.example.com" to "/.well-known/oauth-protected-resource",
            "https://mcp.example.com/" to "/.well-known/oauth-protected-resource",
            "https://mcp.example.com/mcp" to "/.well-known/oauth-protected-resource/mcp",
            "https://mcp.example.com/mcp/" to "/.well-known/oauth-protected-resource/mcp/",
            "https://mcp.example.com/a/b" to "/.well-known/oauth-protected-resource/a/b",
        )
        for ((res, path) in cases) {
            val metadata = Mcp.protectedResourceMetadata(res, authorizationServers, scopesSupported)
            assertEquals(path, metadata.metadataPath, res)
            assertEquals("https://mcp.example.com$path", metadata.metadataUrl, res)
            // Nothing is normalised: the trailing slash of the fourth case survives.
            assertEquals(res, metadata.document.resource, res)
        }
    }

    @Test
    fun `refuses a resource that is relative, or carries a fragment or a query`() {
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("/mcp", authorizationServers, scopesSupported)
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("mcp.example.com/mcp", authorizationServers, scopesSupported)
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("https://mcp.example.com/mcp#tools", authorizationServers, scopesSupported)
        }
        // §28.3 derives the document's own URL from this value and a query
        // makes that derivation ambiguous — §28 forbids what RFC 8707 permits.
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("https://mcp.example.com/mcp?tenant_id=acme", authorizationServers, scopesSupported)
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("", authorizationServers, scopesSupported)
        }
    }

    @Test
    fun `refuses http on a routable host and accepts it on loopback`() {
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("http://mcp.example.com/mcp", authorizationServers, scopesSupported)
        }

        val loopback = Mcp.protectedResourceMetadata(
            "http://127.0.0.1:8080/mcp",
            listOf("http://localhost:9000"),
            scopesSupported,
        )
        assertEquals("http://127.0.0.1:8080/mcp", loopback.document.resource)
        assertEquals("http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp", loopback.metadataUrl)

        // The carve-out is the HOST, not a substring of it: userinfo merely
        // reading "localhost" resolves to the routable host after the `@`.
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("http://localhost@evil.example.com/mcp", authorizationServers, scopesSupported)
        }

        // §28.2 rule 2's third host: `[::1]`, brackets included.
        val v6 = Mcp.protectedResourceMetadata("http://[::1]:8080/mcp", listOf("http://[::1]:9000"), scopesSupported)
        assertEquals("http://[::1]:8080/.well-known/oauth-protected-resource/mcp", v6.metadataUrl)
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata("http://[2001:db8::1]:8080/mcp", authorizationServers, scopesSupported)
        }
    }

    @Test
    fun `refuses an empty authorization_servers, and an entry with a query, a fragment or a duplicate`() {
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, emptyList(), scopesSupported)
        }
        // §28.2 rule 4: the tenant travels as `?tenant_id=` on individual
        // endpoint URLs, never on the issuer. An entry carrying one is not an
        // issuer.
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, listOf("https://axiam.example.com?tenant_id=a"), scopesSupported)
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, listOf("https://axiam.example.com#frag"), scopesSupported)
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(
                resource,
                listOf("https://axiam.example.com", "https://axiam.example.com"),
                scopesSupported,
            )
        }
    }

    @Test
    fun `refuses a duplicate scope and a scope outside NQCHAR, and preserves the caller's order`() {
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, listOf("mcp:read", "mcp:read"))
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, listOf("mcp read"))
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, listOf("mcp:\"read\""))
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, listOf(""))
        }

        val reordered = Mcp.protectedResourceMetadata(resource, authorizationServers, listOf("mcp:tools", "mcp:read"))
        assertEquals(listOf("mcp:tools", "mcp:read"), reordered.document.scopesSupported)
    }

    @Test
    fun `refuses any bearer_methods_supported that is not exactly header`() {
        // §10's guard reads a bearer credential from the Authorization header
        // alone, so "body"/"query" would describe behaviour this SDK does not have.
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, scopesSupported, listOf("query"))
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, scopesSupported, listOf("header", "body"))
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, scopesSupported, emptyList())
        }
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(resource, authorizationServers, scopesSupported, listOf("header", "header"))
        }

        val defaulted = Mcp.protectedResourceMetadata(resource, authorizationServers, scopesSupported)
        assertEquals(listOf("header"), defaulted.document.bearerMethodsSupported)
    }

    @Test
    fun `omits scopes_supported when empty, and resource_documentation when absent — never null`() {
        val bare = Mcp.protectedResourceMetadata(resource, authorizationServers, emptyList())

        val json = bare.document.toJson()
        val parsed = Json.parseToJsonElement(json).jsonObject()
        assertEquals(
            setOf("resource", "authorization_servers", "bearer_methods_supported"),
            parsed.keys,
        )
        // An empty scopes_supported would assert "this server understands no
        // scopes" — a different, almost always false, claim. And an explicit
        // `null` is not an omission.
        assertFalse(json.contains("null"), "no member is ever emitted as null")
        assertFalse(parsed.containsKey("scopes_supported"))
        assertFalse(parsed.containsKey("resource_documentation"))
    }

    @Test
    fun `accepts a resource_documentation with a query and a fragment — it is a page, not an identifier`() {
        val metadata = Mcp.protectedResourceMetadata(
            resource,
            authorizationServers,
            scopesSupported,
            resourceDocumentation = "https://mcp.example.com/docs?v=2#tools",
        )
        assertEquals("https://mcp.example.com/docs?v=2#tools", metadata.document.resourceDocumentation)
        assertThrows(ValidationError::class.java) {
            Mcp.protectedResourceMetadata(
                resource,
                authorizationServers,
                scopesSupported,
                resourceDocumentation = "http://docs.example.com/mcp",
            )
        }
    }

    // -----------------------------------------------------------------
    // §28.9 test 2 — challenge quoting
    // -----------------------------------------------------------------

    @Test
    fun `builds the four §28-4 test vectors as exact strings`() {
        assertEquals(
            "Bearer resource_metadata=\"$metadataUrl\"",
            Mcp.bearerChallenge(metadataUrl),
        )
        assertEquals(
            "Bearer error=\"invalid_token\", resource_metadata=\"$metadataUrl\"",
            Mcp.bearerChallenge(metadataUrl, error = BearerChallengeError.INVALID_TOKEN),
        )
        assertEquals(
            "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"$metadataUrl\"",
            Mcp.bearerChallenge(metadataUrl, error = BearerChallengeError.INSUFFICIENT_SCOPE, scope = "mcp:tools"),
        )
        assertEquals(
            "Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", " +
                "scope=\"mcp:read mcp:tools\", resource_metadata=\"$metadataUrl\"",
            Mcp.bearerChallenge(
                metadataUrl,
                error = BearerChallengeError.INVALID_REQUEST,
                errorDescription = "The access token is malformed",
                scope = "mcp:read mcp:tools",
            ),
        )
    }

    @Test
    fun `refuses every challenge value outside RFC 6750's syntax, never escaping`() {
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, errorDescription = "has \" quote") }
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, errorDescription = "has \\ backslash") }
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, errorDescription = "has \n newline") }
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, errorDescription = "has é non-ascii") }

        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, scope = " mcp:read") }
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, scope = "mcp:read  mcp:tools") }
        assertNoEscapeRefusal { Mcp.bearerChallenge(metadataUrl, scope = "") }

        assertNoEscapeRefusal { Mcp.bearerChallenge("https://mcp.example.com/a b") }
    }

    /** Asserts the call refuses rather than produces a challenge with `\"` inside it. */
    private fun assertNoEscapeRefusal(block: () -> String) {
        var produced: String? = null
        try {
            produced = block()
        } catch (_: ValidationError) {
            return
        }
        throw AssertionError("expected a refusal, got a challenge: $produced")
    }

    @Test
    fun `error is restricted to RFC 6750's three codes at compile time`() {
        // TypeScript and Java accept `error` as a string and refuse
        // `invalid_grant` (a well-formed-looking OAuth code outside RFC
        // 6750 §3.1) at runtime. Kotlin's BearerChallengeError enum makes
        // that string unrepresentable instead: there is no fourth constant
        // to pass, so §28.9 test 2's "refuses an error of invalid_grant"
        // negative holds structurally rather than by a runtime assertion.
        assertEquals(3, BearerChallengeError.entries.size)
        assertEquals(
            setOf("invalid_request", "invalid_token", "insufficient_scope"),
            BearerChallengeError.entries.map { it.wireValue }.toSet(),
        )
    }
}

private fun kotlinx.serialization.json.JsonElement.jsonObject(): JsonObject = this as JsonObject
