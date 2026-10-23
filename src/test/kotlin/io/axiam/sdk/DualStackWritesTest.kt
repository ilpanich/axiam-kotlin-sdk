package io.axiam.sdk

import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.util.Collections
import java.util.UUID

/**
 * C164-50 (contract 1.64 review, §16.1, §34.2 P11): a request that must be sent at most once is
 * still DELIVERED when the first resolved address refuses. A client built with
 * `retryOnConnectionFailure(false)` also loses OkHttp 4's fallback to the next address, so a
 * management write or a sessionless call on such a host reached the server 0 times once the
 * connection pool was empty. The bodies are one-shot instead: the fallback stays, a sent request
 * is never replayed.
 *
 * The resolver puts a refusing address first: `localhost` -> [127.0.0.2, 127.0.0.1], with the mock
 * on 127.0.0.1 only.
 */
class DualStackWritesTest {

    private lateinit var server: MockWebServer
    private val seen = Collections.synchronizedList(mutableListOf<RecordedRequest>())
    private val tenant = "22222222-2222-2222-2222-222222222222"
    private val groupId = UUID.randomUUID()
    private var drop = false

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.requestUrl?.encodedPath ?: ""
                return when {
                    path == "/api/v1/auth/login" -> TestSupport.loginOkResponse()
                    path.startsWith("/api/v1/") || path.startsWith("/oauth2/register/") || path.startsWith("/ssf/v1/poll/") -> {
                        seen += request
                        if (drop) {
                            MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST)
                        } else {
                            MockResponse().setResponseCode(204)
                        }
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun dualStack() = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> =
            if (hostname == "localhost") {
                listOf(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("127.0.0.1"))
            } else {
                Dns.SYSTEM.lookup(hostname)
            }
    }

    private fun client(): AxiamClient =
        AxiamClient.builder("http://localhost:${server.port}", tenant)
            .httpClient(OkHttpClient.Builder().dns(dualStack()).build())
            .build()

    private val registrationUri get() = "http://localhost:${server.port}/oauth2/register/dcr-client-1?tenant_id=$tenant"

    private fun registrations() = seen.filter { it.path?.startsWith("/oauth2/register/") == true }

    private fun ssfPolls() = seen.filter { it.path?.startsWith("/ssf/v1/poll/") == true }

    /** A logged-in client with a kept-alive connection to 127.0.0.1 in the pool, then the server drops what it reads. */
    private suspend fun pooledClientThatDrops(retry: Boolean = true): AxiamClient {
        val client = AxiamClient.builder("http://localhost:${server.port}", tenant)
            .httpClient(OkHttpClient.Builder().dns(dualStack()).build())
            .apply { if (!retry) retryDisabled() }
            .build()
        client.login("admin@example.test", "hunter2hunter2")
        drop = true
        return client
    }

    private fun writes() = seen.filter { it.path?.startsWith("/api/v1/groups") == true }

    @Test
    fun `a management DELETE reaches the server when the first address refuses, with the pool empty`(): Unit = runBlocking {
        val client = client()
        client.login("admin@example.test", "hunter2hunter2")
        client.okHttpClient().connectionPool.evictAll() // a pooled connection would hide the failure

        client.groups.delete(groupId)

        assertEquals(1, writes().size, "one DELETE at the server")
        assertEquals("DELETE", writes().single().method)
    }

    @Test
    fun `a management write with a body reaches the server when the first address refuses, with the pool empty`(): Unit = runBlocking {
        val client = client()
        client.login("admin@example.test", "hunter2hunter2")
        client.okHttpClient().connectionPool.evictAll()

        runCatching {
            client.groups.create(io.axiam.sdk.management.models.CreateGroupRequest(description = "d", name = "g"))
        }

        assertEquals(1, writes().size, "one POST at the server (the 204 may fail to decode, the request was delivered)")
    }

    @Test
    fun `a management write is not replayed after a drop on a pooled connection (P11)`(): Unit = runBlocking {
        val client = client()
        client.login("admin@example.test", "hunter2hunter2") // leaves a pooled connection to 127.0.0.1
        drop = true

        assertThrows<NetworkError> { runBlocking { client.groups.delete(groupId) } }

        assertEquals(1, writes().size, "exactly one DELETE; neither §16 nor OkHttp re-sends a write")
    }

    @Test
    fun `a sessionless registration call reaches the server when the first address refuses, with the pool empty`(): Unit = runBlocking {
        val client = client()
        client.login("admin@example.test", "hunter2hunter2")
        client.okHttpClient().connectionPool.evictAll()
        val uri = registrationUri

        client.deleteClientRegistration(uri, Sensitive.of(Redaction.secret("tok-")))

        val deletes = seen.filter { it.path?.startsWith("/oauth2/register/") == true }
        assertEquals(1, deletes.size, "one DELETE at the server")
    }

    // -- C164-56: the P11 read-and-drop case on each sessionless write ------------------------------

    @Test
    fun `a registration DELETE is sent once over a pooled connection that drops (P11, C164-56)`(): Unit = runBlocking {
        val client = pooledClientThatDrops()

        assertThrows<NetworkError> {
            runBlocking { client.deleteClientRegistration(registrationUri, Sensitive.of(Redaction.secret("tok-"))) }
        }

        assertEquals(1, registrations().size, "exactly one DELETE")
    }

    @Test
    fun `a registration PUT is sent once over a pooled connection that drops (P11, C164-56)`(): Unit = runBlocking {
        val client = pooledClientThatDrops()

        assertThrows<NetworkError> {
            runBlocking {
                client.updateClientRegistration(
                    registrationUri, Sensitive.of(Redaction.secret("tok-")),
                    io.axiam.sdk.oidc.ClientRegistration("dcr-client-1"),
                )
            }
        }

        assertEquals(1, registrations().size, "exactly one PUT")
    }

    @Test
    fun `ssf poll is sent exactly three times, its section 16 cap, over a pooled connection that drops (P11, C164-56)`(): Unit = runBlocking {
        val client = pooledClientThatDrops()
        val receiver = io.axiam.sdk.ssf.SsfReceiver(
            client,
            io.axiam.sdk.ssf.SsfReceiverConfig(
                "https://iam.example.test/t/$tenant",
                "https://rp.example.test",
                io.axiam.sdk.ssf.SsfKeySource.JwksUri("http://localhost:${server.port}/oauth2/jwks"),
                accessTokenProvider = { Sensitive.of(Redaction.secret("cc-")) },
            ),
        )

        assertThrows<NetworkError> { runBlocking { receiver.poll("stream-1") } }

        assertEquals(3, ssfPolls().size, "three attempts under §16, no OkHttp replay on top")
    }

    // -- C164-55: the one sessionless READ is an idempotent GET OkHttp may recover once -----------------

    @Test
    fun `a registration read over a pooled connection that drops reaches at most four sends with retry, two without (C164-55)`(): Unit = runBlocking {
        val client = pooledClientThatDrops()
        assertThrows<NetworkError> {
            runBlocking { client.readClientRegistration(registrationUri, Sensitive.of(Redaction.secret("tok-"))) }
        }
        val withRetry = registrations().size
        assertTrue(withRetry in 3..4, "§16's three attempts, plus at most one OkHttp recovery of the idempotent GET: $withRetry")

        seen.clear()
        val without = pooledClientThatDrops(retry = false)
        assertThrows<NetworkError> {
            runBlocking { without.readClientRegistration(registrationUri, Sensitive.of(Redaction.secret("tok-"))) }
        }
        val withoutRetry = registrations().size
        assertTrue(withoutRetry in 1..2, "one attempt, plus at most one OkHttp recovery: $withoutRetry")
    }
}
