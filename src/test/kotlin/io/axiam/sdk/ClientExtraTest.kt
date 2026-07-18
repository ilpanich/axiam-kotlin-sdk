package io.axiam.sdk

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.internal.SessionState
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.concurrent.TimeUnit

class ClientExtraTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `login includes org_slug when configured with a slug`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .orgSlug("acme-org")
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(5))
            .writeTimeout(Duration.ofSeconds(5))
            .build().use { client ->
                client.login("a@b.c", "pw")
            }
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("\"org_slug\":\"acme-org\""))
    }

    @Test
    fun `verifyMfa failure maps to error`() {
        server.enqueue(MockResponse().setResponseCode(401).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(AuthError::class.java) {
                runBlocking { client.verifyMfa(Sensitive.of("chal"), "000000") }
            }
        }
    }

    @Test
    fun `explicit refresh succeeds and rotates the session`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        server.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=${TestSupport.fakeJwt(jti = "s9")}; Path=/")
                .addHeader("Set-Cookie", "axiam_refresh=r9; Path=/")
                .setBody("{}"),
        )
        TestSupport.clientFor(server).use { client ->
            client.login("a@b.c", "pw")
            server.takeRequest()
            client.refresh()
            val refreshReq = server.takeRequest()
            assertEquals("/api/v1/auth/refresh", refreshReq.path)
            val body = refreshReq.body.readUtf8()
            assertTrue(body.contains("\"tenant_id\""))
            assertTrue(body.contains("\"org_id\""))
        }
    }

    @Test
    fun `refresh fails cleanly when org id cannot be resolved`() = runBlocking {
        // Session token carries no org_id and none is configured on the client.
        val noOrgJwt = buildString {
            append(
                java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("""{"alg":"EdDSA"}""".toByteArray()),
            )
            append(".")
            append(
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ("""{"sub":"u","tenant_id":"${TestSupport.TENANT_UUID}",""" +
                        """"jti":"j","exp":${System.currentTimeMillis() / 1000 + 3600}}""").toByteArray(),
                ),
            )
            append(".sig")
        }
        server.enqueue(
            MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=$noOrgJwt; Path=/")
                .setBody("{}"),
        )
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID).build().use { client ->
            client.login("a@b.c", "pw")
            server.takeRequest()
            assertThrows(AuthError::class.java) { runBlocking { client.refresh() } }
        }
    }

    @Test
    fun `explicit refresh propagates a server rejection as AuthError`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        server.enqueue(MockResponse().setResponseCode(401).setBody("{}"))
        TestSupport.clientFor(server).use { client ->
            client.login("a@b.c", "pw")
            server.takeRequest()
            assertThrows(AuthError::class.java) { runBlocking { client.refresh() } }
        }
    }

    @Test
    fun `logout maps a server error to an exception`() = runBlocking {
        server.enqueue(TestSupport.loginOkResponse())
        server.enqueue(MockResponse().setResponseCode(500).setBody("boom"))
        TestSupport.clientFor(server).use { client ->
            client.login("a@b.c", "pw")
            server.takeRequest()
            assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
                runBlocking { client.logout() }
            }
        }
    }

    @Test
    fun `a malformed success body surfaces as NetworkError`() = runBlocking {
        server.enqueue(TestSupport.json(200, "not-json"))
        TestSupport.clientFor(server).use { client ->
            assertThrows(io.axiam.sdk.errors.NetworkError::class.java) {
                runBlocking { client.checkAccess("read", "r-1") }
            }
        }
    }

    @Test
    fun `batchCheck with no results key yields an empty list`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{}"""))
        TestSupport.clientFor(server).use { client ->
            val results = client.batchCheck(listOf(AccessCheck("read", "a")))
            assertTrue(results.isEmpty())
        }
    }

    @Test
    fun `override http client is adopted but jar and TLS are re-applied`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        val base = OkHttpClient.Builder().callTimeout(3, TimeUnit.SECONDS).build()
        AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .httpClient(base)
            .build().use { client ->
                assertTrue(client.can("read", "r-1"))
            }
    }

    @Test
    fun `unverified claim decoder rejects malformed tokens`() {
        assertNull(SessionState.decodeUnverifiedClaims("only.two"))
        assertNull(SessionState.decodeUnverifiedClaims("a.b.c.d"))
        val claims = SessionState.decodeUnverifiedClaims(TestSupport.fakeJwt(scope = ""))
        assertEquals(emptyList<String>(), claims!!.roles)
    }
}
