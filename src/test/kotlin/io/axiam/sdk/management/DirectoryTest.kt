package io.axiam.sdk.management

import io.axiam.sdk.Redaction
import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.models.DirectoryConfig
import io.axiam.sdk.management.models.DirectoryKind
import io.axiam.sdk.management.models.LinkDirectoryAccount
import io.axiam.sdk.management.models.SetDirectoryConfig
import io.axiam.sdk.management.models.UpdateDirectoryConfig
import io.axiam.sdk.internal.ManagementTransport
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/**
 * The `directory` management namespace — CONTRACT.md §30.8's six required
 * tests. The bind secret is generated at run time.
 */
class DirectoryTest : ManagementTestBase() {

    private val directory = "/api/v1/tenants/$TENANT_ID/directory"

    private fun configBody(extra: String = ""): String =
        """{"id":"${UUID.randomUUID()}","tenant_id":"$TENANT_ID","enabled":true,"kind":"active_directory",
            "url":"ldaps://dc.corp.example","start_tls":false,"bind_dn":"cn=svc,dc=corp",
            "base_dn":"dc=corp","user_filter":"(sAMAccountName={username})",
            "user_attribute_map":{"username":"sAMAccountName","email":"mail",
                                  "display_name":"displayName","external_id":"objectGUID"},
            "group_base_dn":null,"group_filter":null,"group_member_attribute":"member",
            "group_nesting_depth":5,"group_mappings":[],"sync_interval_secs":3600,
            "jit_provisioning":false,"trust_anchors_pem":[],
            "created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"$extra}"""

    private fun setBody(bindSecret: String?) = SetDirectoryConfig(
        baseDn = "dc=corp",
        bindDn = "cn=svc,dc=corp",
        bindSecret = bindSecret?.let { Sensitive.of(it) },
        enabled = true,
        kind = DirectoryKind.ACTIVE_DIRECTORY,
        startTls = false,
        url = "ldaps://dc.corp.example",
        userFilter = "(sAMAccountName={username})",
    )

    // -- 1. Redaction ------------------------------------------------------------

    @Test
    fun `the bind secret reaches the wire and no rendering`() = runTest {
        val secret = Redaction.secret("bind-")
        val set = setBody(secret)
        val update = UpdateDirectoryConfig(bindSecret = Sensitive.of(secret))
        for ((label, rendering) in listOf("set" to set.toString(), "update" to update.toString())) {
            Redaction.assertNoFragment(rendering, secret, label)
        }
        // The reader's re-encoding (what a log serializer would use) redacts too.
        val logged = ManagementTransport.READER.encodeToString(SetDirectoryConfig.serializer(), set)
        Redaction.assertNoFragment(logged, secret, "serialized for logs")

        val route = mount(
            "PUT", directory, 400,
            """{"error":"validation_error","message":"url: plaintext LDAP is refused"}""",
        )
        val e = assertThrows<ValidationError> { runBlocking { client.directory.set(set) } }
        Redaction.assertNoFragment(e.toString(), secret, "error")
        assertEquals(JsonPrimitive(secret), route.last().json()["bind_secret"], "but it is on the wire")
    }

    // -- 2. No secret on the response ----------------------------------------------

    @Test
    fun `a bind secret in a response is dropped`() = runTest {
        val leaked = Redaction.secret("bind-")
        mount("GET", directory, 200, configBody(""","bind_secret":"$leaked""""))
        val config = client.directory.get()
        Redaction.assertNoFragment(config.toString(), leaked, "toString")
        Redaction.assertNoFragment(
            ManagementTransport.READER.encodeToString(DirectoryConfig.serializer(), config),
            leaked,
            "serialized",
        )
        // ...and there is no accessor: DirectoryConfig declares no such property.
        assertFalse(
            DirectoryConfig::class.members.any { it.name.contains("secret", ignoreCase = true) },
            "DirectoryConfig has no secret member",
        )
        assertEquals("ldaps://dc.corp.example", config.url)
    }

    // -- 3. Sparse update ------------------------------------------------------------

    @Test
    fun `update sends exactly the members it was given`() = runTest {
        val route = mount("PATCH", directory, 200, configBody())
        val secret = Redaction.secret("bind-")

        client.directory.update(UpdateDirectoryConfig(enabled = false))
        client.directory.update(
            UpdateDirectoryConfig(url = "ldaps://dc2.corp.example", bindSecret = Sensitive.of(secret)),
        )
        client.directory.update(UpdateDirectoryConfig(groupFilter = JsonNullable.Null))
        client.directory.update(UpdateDirectoryConfig(groupBaseDn = JsonNullable.Value("ou=groups,dc=corp")))

        val sent = route.requests
        assertEquals(4, sent.size)
        assertEquals("PATCH", sent[0].method)
        assertEquals(JsonObject(mapOf("enabled" to JsonPrimitive(false))), sent[0].json())
        assertEquals(listOf("bind_secret", "url"), sent[1].keys())
        assertEquals(JsonPrimitive(secret), sent[1].json()["bind_secret"])
        assertEquals(JsonObject(mapOf("group_filter" to JsonNull)), sent[2].json(), "null clears")
        assertEquals(
            JsonObject(mapOf("group_base_dn" to JsonPrimitive("ou=groups,dc=corp"))),
            sent[3].json(),
        )
    }

    // -- 4. Replacement ----------------------------------------------------------------

    @Test
    fun `set sends every required member and decodes 201 and 200`() = runTest {
        // SetDirectoryConfig cannot be built without its seven required members:
        // they are constructor parameters with no default, so a call that omits
        // one does not compile. What is left to check is the wire.
        for (status in listOf(201, 200)) {
            val route = mount("PUT", directory, status, configBody())
            val config = client.directory.set(setBody(null))
            assertTrue(config.enabled)
            val sent = route.last().json()
            for (required in listOf("enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter")) {
                assertTrue(required in sent, "$required missing")
            }
            assertFalse("bind_secret" in sent, "absent keeps the stored secret")
        }
    }

    // -- 5. No retry ----------------------------------------------------------------------

    @Test
    fun `no write is retried on 503`() = runTest {
        val put = mount("PUT", directory, 503, "")
        val patch = mount("PATCH", directory, 503, "")
        val delete = mount("DELETE", directory, 503, "")
        val link = mount("POST", "$directory/links", 503, "")
        val d = client.directory // the default client: retry ENABLED
        assertThrows<NetworkError> { runBlocking { d.set(setBody(Redaction.secret("bind-"))) } }
        assertThrows<NetworkError> { runBlocking { d.update(UpdateDirectoryConfig()) } }
        assertThrows<NetworkError> { runBlocking { d.delete() } }
        assertThrows<NetworkError> { runBlocking { d.linkAccount(LinkDirectoryAccount(UUID.randomUUID())) } }
        for ((name, route) in listOf("set" to put, "update" to patch, "delete" to delete, "link" to link)) {
            assertEquals(1, route.calls(), "$name: exactly one request")
        }
    }

    @Test
    fun `no write is re-sent after a dropped connection`() = runTest {
        val d = client.directory // the default client: retry ENABLED
        assertSentOnceOverDroppedConnection("set", mountDropped("PUT", directory)) {
            d.set(setBody(Redaction.secret("bind-")))
        }
        assertSentOnceOverDroppedConnection("update", mountDropped("PATCH", directory)) {
            d.update(UpdateDirectoryConfig())
        }
        assertSentOnceOverDroppedConnection("delete", mountDropped("DELETE", directory)) { d.delete() }
        assertSentOnceOverDroppedConnection("link", mountDropped("POST", "$directory/links")) {
            d.linkAccount(LinkDirectoryAccount(UUID.randomUUID()))
        }
    }

    // -- 6. Errors and link_account -----------------------------------------------------------

    @Test
    fun `errors map per section 2 and link_account sends only the user id`() = runTest {
        mount(
            "PUT", directory, 400,
            """{"error":"validation_error","message":"url: changing the connection requires entering the bind secret again"}""",
        )
        mount("PATCH", directory, 409, """{"error":"conflict","message":"opaque_mode"}""")
        mount("GET", directory, 404, """{"error":"not_found","message":"none"}""")
        mount("DELETE", directory, 401, """{"error":"unauthorized","message":"human only"}""")

        val e = assertThrows<ValidationError> { runBlocking { client.directory.set(setBody(null)) } }
        assertTrue(e.message.orEmpty().contains("bind secret again"))
        assertThrows<ConflictError> { runBlocking { client.directory.update(UpdateDirectoryConfig(enabled = true)) } }
        assertThrows<NotFoundError> { runBlocking { client.directory.get() } }
        assertThrows<AuthError> { runBlocking { client.directory.delete() } }

        val user = UUID.randomUUID()
        val links = mount(
            "POST", "$directory/links", 200,
            """{"user_id":"$user","directory_external_id":"3f2a-objectguid",
                "webauthn_credentials_deleted":2,"certificates_revoked":1,"was_already_linked":false}""",
        )
        val result = client.directory.linkAccount(LinkDirectoryAccount(userId = user))
        assertEquals(JsonObject(mapOf("user_id" to JsonPrimitive(user.toString()))), links.last().json())
        assertEquals(user, result.userId)
        assertEquals("3f2a-objectguid", result.directoryExternalId)
        assertEquals(2L, result.webauthnCredentialsDeleted)
        assertEquals(1L, result.certificatesRevoked)
        assertFalse(result.wasAlreadyLinked)
    }

    @Test
    fun `sync status decodes an unknown result and the first-run nulls`() = runTest {
        mount(
            "GET", "$directory/sync-status", 200,
            """{"last_result":"something_new","last_attempt_at":null,"last_full_run_at":null,
                "full_required":true,"has_watermark":false}""",
        )
        val status = client.directory.getSyncStatus()
        assertEquals("something_new", status.lastResult)
        assertTrue(status.fullRequired && !status.hasWatermark)
        assertNull(status.lastAttemptAt)
    }

    @Test
    fun `a read converts into the replacement body without a secret`() {
        val config = ManagementTransport.READER.decodeFromString(DirectoryConfig.serializer(), configBody())
        val body = config.toInput()
        assertNull(body.bindSecret, "absent keeps the stored secret")
        assertEquals(config.url, body.url)
        assertEquals(5, body.groupNestingDepth)
        assertEquals(3600L, body.syncIntervalSecs)
    }

    @Test
    fun `the directory routes default the tenant and a handle can name another`() = runTest {
        val other = UUID.randomUUID()
        val mine = mount("GET", directory, 200, configBody())
        val theirs = mount("GET", "/api/v1/tenants/$other/directory", 200, configBody())
        client.directory.forTenant(other).get()
        client.directory.get()
        assertEquals(1, theirs.calls())
        assertEquals(1, mine.calls())
    }

    @Test
    fun `JsonNullable spells the three states`() {
        assertEquals(JsonNullable.Null, JsonNullable.of<String>(null))
        assertEquals(JsonNullable.Value("x"), JsonNullable.of("x"))
        assertEquals("x", JsonNullable.of("x").valueOrNull)
        assertNull(JsonNullable.Null.valueOrNull)
        assertNull(JsonNullable.Absent.valueOrNull)
    }
}
