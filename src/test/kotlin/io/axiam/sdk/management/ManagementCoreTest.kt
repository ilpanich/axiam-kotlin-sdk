package io.axiam.sdk.management

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.internal.ManagementTransport
import io.axiam.sdk.management.models.CreateRoleRequest
import io.axiam.sdk.management.models.CreateScimTokenResponse
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * The CONTRACT.md §27 core types, tested directly rather than through a route.
 *
 * [PageRequest] and [Page] carry the arithmetic §27.4 rule 4 depends on, the
 * two `Sensitive` serializers decide whether a secret reaches a socket, and
 * [ManifestValidation] refuses a manifest before the first request. Each is
 * cheaper and clearer to pin here than to reach through a mounted server.
 */
class ManagementCoreTest : ManagementTestBase() {

    // ---- §27.4 rule 4: paging arithmetic --------------------------------

    /** A negative offset or a zero limit is a caller bug, caught at construction. */
    @Test
    fun `a page request refuses nonsense`() {
        assertThrows(IllegalArgumentException::class.java) { PageRequest(offset = -1) }
        assertThrows(IllegalArgumentException::class.java) { PageRequest(limit = 0) }
        assertThrows(IllegalArgumentException::class.java) { PageRequest(limit = -5) }
    }

    /**
     * An unset limit is omitted, not sent as zero.
     *
     * The server reads `limit=0` as "none" and answers with an empty page, so
     * the difference between omitting the parameter and sending a zero is the
     * difference between the server's default and no results at all.
     */
    @Test
    fun `an unset limit is omitted rather than sent as zero`() {
        assertNull(PageRequest.first().limit)
        assertEquals(null, ManagementSupport.pageQuery(emptyMap(), null)["limit"])
        assertEquals("0", ManagementSupport.pageQuery(emptyMap(), null)["offset"])
        assertEquals("25", ManagementSupport.pageQuery(emptyMap(), PageRequest.of(25))["limit"])
    }

    /** A manual walk advances by what it consumed. */
    @Test
    fun `next advances the window`() {
        assertEquals(PageRequest(2, 2), PageRequest.of(2).next(2))
        assertEquals(PageRequest(5, null), PageRequest.first().next(5))
    }

    /** A page knows whether it is the last one, and where the next one starts. */
    @Test
    fun `a page reports where the next one starts`() {
        val middle = Page(listOf("a", "b"), total = 5, offset = 0, limit = 2)
        assertFalse(middle.isLast)
        assertEquals(PageRequest(2, 2), middle.nextPage())

        val last = Page(listOf("e"), total = 5, offset = 4, limit = 2)
        assertTrue(last.isLast)
        assertNull(last.nextPage())

        // An empty page ends the walk even when total disagrees, so a
        // miscounting server costs one wasted request rather than a loop.
        val lying = Page(emptyList<String>(), total = 900, offset = 0, limit = 2)
        assertTrue(lying.isLast)
        assertNull(lying.nextPage())

        // A server that reported no limit must not produce a zero-limit next
        // window, which PageRequest would reject.
        val noLimit = Page(listOf("a"), total = 5, offset = 0, limit = 0)
        assertEquals(PageRequest(1, null), noLimit.nextPage())

        assertTrue(Page.empty<String>().isLast)
    }

    // ---- §27.5: which writer exposes a secret ---------------------------

    /**
     * The redacting serializer round-trips a secret in and renders it out
     * redacted; the exposing one writes it in the clear.
     *
     * Both directions matter. A response carries a secret IN — so the reader
     * has to accept it — and re-serializing that response anywhere other than
     * the request path must not put it back on the wire.
     */
    @Test
    fun `the two sensitive serializers disagree on purpose`() {
        val secret = Sensitive.of("tok-abcdef")

        val redacted = ManagementTransport.READER.encodeToString(
            SensitiveRedactingSerializer, secret,
        )
        assertEquals("\"[SENSITIVE]\"", redacted)

        val exposed = ManagementTransport.WIRE.encodeToString(
            SensitiveExposingSerializer, secret,
        )
        assertEquals("\"tok-abcdef\"", exposed)

        assertEquals(
            "tok-abcdef",
            ManagementTransport.READER
                .decodeFromString(SensitiveRedactingSerializer, "\"tok-abcdef\"").expose(),
        )
        assertEquals(
            "tok-abcdef",
            ManagementTransport.WIRE
                .decodeFromString(SensitiveExposingSerializer, "\"tok-abcdef\"").expose(),
        )
    }

    /**
     * A model carrying a secret cannot be serialized by a caller's own `Json`.
     *
     * Fail-closed, and loudly. `Sensitive` is `@Contextual`, so a `Json` with
     * neither serializer registered throws rather than quietly emitting either
     * the secret or a placeholder the server would reject. That is deliberately
     * stricter than the UUID and timestamp serializers, which are attached
     * per-property and work anywhere.
     */
    @Test
    fun `a model carrying a secret refuses a foreign serializer`() {
        val model = CreateScimTokenResponse(
            createdAt = java.time.Instant.parse("2026-08-26T00:00:00Z"),
            createdBy = EXAMPLE_ID,
            expiresAt = java.time.Instant.parse("2027-08-26T00:00:00Z"),
            id = EXAMPLE_ID,
            name = "provisioning",
            provisioningToken = Sensitive.of("tok-abcdef"),
            status = io.axiam.sdk.management.models.ScimTokenStatus.ACTIVE,
            tenantId = TENANT_ID,
            userId = EXAMPLE_ID,
        )
        assertThrows(kotlinx.serialization.SerializationException::class.java) {
            Json.encodeToString(CreateScimTokenResponse.serializer(), model)
        }
        // The SDK's own reader renders it, redacted.
        val rendered = ManagementTransport.READER
            .encodeToString(CreateScimTokenResponse.serializer(), model)
        assertFalse(rendered.contains("tok-abcdef"))
        assertTrue(rendered.contains("[SENSITIVE]"))
    }

    // ---- §27.6 rule 1: what validation refuses --------------------------

    /** A duplicate key is refused: two entries claiming one name cannot both win. */
    @Test
    fun `duplicate keys are refused`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        roles = listOf(
                            ManagementManifest.RoleSpec("editor", "Editor", "One"),
                            ManagementManifest.RoleSpec("editor", "Editor", "Two"),
                        ),
                        permissions = listOf(
                            ManagementManifest.PermissionSpec("read", "document:read", "A"),
                            ManagementManifest.PermissionSpec("read", "document:read", "B"),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("role key 'editor' is declared more than once"))
        assertTrue(thrown.message!!.contains("permission key 'read' is declared more than once"))
    }

    /** A grant narrowed to a scope no resource declares is refused before calling. */
    @Test
    fun `a grant naming an unknown scope is refused`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        permissions = listOf(
                            ManagementManifest.PermissionSpec("read", "document:read", "Read"),
                        ),
                        roles = listOf(
                            ManagementManifest.RoleSpec(
                                "editor", "Editor", "Edits", false,
                                listOf(ManagementManifest.GrantSpec("read", null, listOf("ghost"))),
                            ),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("scope 'ghost'"))
        assertEquals(0, totalCalls())
    }

    /** A user joining a group nothing declares, and a group holding an unknown role. */
    @Test
    fun `dangling group and user references are refused`() = runTest {
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().manifest().plan(
                    ManagementManifest(
                        users = listOf(
                            ManagementManifest.UserSpec(
                                "alice", "alice", "a@example.test", null,
                                roles = listOf("ghost-role"), groups = listOf("ghost-group"),
                            ),
                        ),
                    ),
                )
            }
        }
        assertTrue(thrown.message!!.contains("holds role 'ghost-role'"))
        assertTrue(thrown.message!!.contains("joins group 'ghost-group'"))
    }

    // ---- §27.4 rule 7: what an odd error body does ----------------------

    /** An error body that is not JSON still yields a usable message. */
    @Test
    fun `a non json error body is quoted rather than dropped`() = runTest {
        mount("POST", "/api/v1/roles", 409, "<html>gateway said no</html>")
        val thrown = assertThrows(io.axiam.sdk.errors.ConflictError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().roles().create(CreateRoleRequest("Edits", false, "Editor"))
            }
        }
        assertTrue(
            thrown.message!!.contains("gateway said no"),
            "a body the SDK cannot parse is still the best explanation there is",
        )
    }

    /** An error body carrying `error` rather than `message` is understood too. */
    @Test
    fun `an error keyed body is understood`() = runTest {
        mount("GET", "/api/v1/users/$EXAMPLE_ID", 404, """{"error":"gone for good"}""")
        val thrown = assertThrows(io.axiam.sdk.errors.NotFoundError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().get(EXAMPLE_ID) }
        }
        assertTrue(thrown.message!!.contains("gone for good"))
    }

    /** An empty error body leaves the operation name standing alone. */
    @Test
    fun `an empty error body still names the operation`() = runTest {
        mount("GET", "/api/v1/users/$EXAMPLE_ID", 404, "")
        val thrown = assertThrows(io.axiam.sdk.errors.NotFoundError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().users().get(EXAMPLE_ID) }
        }
        assertTrue(thrown.message!!.contains("users.get"))
    }

    /** A 400 whose body has no `errors` key is still a ValidationError, with no fields. */
    @Test
    fun `a validation error without field detail carries none`() = runTest {
        mount("PUT", "/api/v1/users/$EXAMPLE_ID", 400, """{"message":"nope"}""")
        val thrown = assertThrows(ValidationError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().users().update(
                    EXAMPLE_ID,
                    io.axiam.sdk.management.models.UpdateUserRequest(email = "x@example.test"),
                )
            }
        }
        assertTrue(thrown.fields.isEmpty(), "no detail is not the same as invented detail")
    }

    /** An `errors` array whose entries lack a `field` contributes nothing. */
    @Test
    fun `a field error without a field name is skipped`() = runTest {
        mount(
            "PUT", "/api/v1/users/$EXAMPLE_ID", 422,
            """{"message":"nope","errors":[{"detail":"unhelpful"},{"field":"email"}]}""",
        )
        val thrown = assertThrows(ValidationError::class.java) {
            kotlinx.coroutines.runBlocking {
                client.management().users().update(
                    EXAMPLE_ID,
                    io.axiam.sdk.management.models.UpdateUserRequest(email = "x@example.test"),
                )
            }
        }
        assertEquals(1, thrown.fields.size)
        assertEquals("email", thrown.fields[0].field)
        assertEquals("is invalid", thrown.fields[0].message, "a missing message gets a default")
    }

    // ---- §27.8: the request body goes out as JSON -----------------------

    /** A DELETE carries no body, and a bodiless POST carries an empty one. */
    @Test
    fun `a delete sends no body`() = runTest {
        val route = mount("DELETE", "/api/v1/users/$EXAMPLE_ID", 204, "")
        client.management().users().delete(EXAMPLE_ID)
        assertEquals("", route.last().body)
    }

    /** A bodiless POST still declares JSON, so a server that requires it is satisfied. */
    @Test
    fun `a bodiless post is still a json request`() = runTest {
        val route = mount("POST", "/api/v1/certificates/$EXAMPLE_ID/revoke", 204, "")
        client.management().certificates().revoke(EXAMPLE_ID)
        assertTrue(
            route.last().headers["Content-Type"]!!.startsWith("application/json"),
            "got ${route.last().headers["Content-Type"]}",
        )
    }

    /** Query parameters are sorted, so a request is reproducible from its telemetry. */
    @Test
    fun `query parameters are sent in a stable order`() = runTest {
        val route = mount("GET", "/api/v1/users", 200, pageOf(null))
        client.management().users().list(PageRequest(offset = 40, limit = 20))
        assertEquals(mapOf("limit" to "20", "offset" to "40"), route.last().query)
    }

    /** A null query filter is omitted rather than sent empty. */
    @Test
    fun `a null query filter is omitted`() = runTest {
        val route = mount("DELETE", "/api/v1/roles/$EXAMPLE_ID/users/$EXAMPLE_ID", 204, "")
        client.management().roles().unassignFromUser(EXAMPLE_ID, EXAMPLE_ID, null)
        assertFalse(route.last().query.containsKey("resource_id"))
    }

    private val exampleId: UUID get() = EXAMPLE_ID

    /** The wire writer omits an unset property and keeps a set one. */
    @Test
    fun `the wire writer omits what was never named`() {
        val text = ManagementSupport.encodeBody(
            "users.update",
            io.axiam.sdk.management.models.UpdateUserRequest.serializer(),
            io.axiam.sdk.management.models.UpdateUserRequest(email = "x@example.test"),
        )
        val keys = (Json.parseToJsonElement(text) as JsonObject).keys
        assertEquals(setOf("email"), keys)
        assertEquals(
            "x@example.test",
            (Json.parseToJsonElement(text) as JsonObject)["email"]!!.jsonPrimitive.content,
        )
        assertEquals(exampleId, EXAMPLE_ID)
    }

    /**
     * An object-shaped read that answers 204 is an error, not a null model.
     *
     * The other two shapes have an honest empty value — a page with no items, a
     * list with none — but there is no empty `Role`. Manufacturing one with
     * default fields would hand the caller a record of something that does not
     * exist, so this says so instead.
     */
    @Test
    fun `an object read with no body is an error not an empty model`() = runTest {
        mount("GET", "/api/v1/roles/$EXAMPLE_ID", 204, "")
        val thrown = assertThrows(NetworkError::class.java) {
            kotlinx.coroutines.runBlocking { client.management().roles().get(EXAMPLE_ID) }
        }
        assertTrue(thrown.message!!.contains("roles.get"))
        assertTrue(thrown.message!!.contains("no body"))
    }
}
