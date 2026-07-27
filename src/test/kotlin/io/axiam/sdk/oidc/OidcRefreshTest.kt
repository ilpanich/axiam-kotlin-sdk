package io.axiam.sdk.oidc

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class OidcRefreshTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    @BeforeEach
    fun setUp() {
        signingKey = OidcTestKit.generateSigningKey()
        server = MockWebServer()
        dispatcher = OidcTestKit.routingDispatcher(server, signingKey)
        server.dispatcher = dispatcher
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `oidcRefresh posts grant_type=refresh_token and skips nonce validation even with an id_token`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        val configuration = client.oidcDiscover()
        val idToken = OidcTestKit.signIdToken(signingKey, issuer = configuration.issuer, nonce = null)
        dispatcher.onJson(
            "/oauth2/token",
            200,
            OidcTestKit.tokenResponseJson(accessToken = "new-access", idToken = idToken),
        )

        val result = client.oidcRefresh(
            OidcRefreshParams.of("old-refresh", tenantId = "22222222-2222-2222-2222-222222222222"),
        )
        assertEquals("new-access", result.accessToken.expose())
        assertEquals("user-1", result.idClaims?.sub)
        assertNull(result.idClaims?.nonce)
    }

    @Test
    fun `N concurrent oidcRefresh callers collapse into exactly one token request`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val tokenCalls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            tokenCalls.incrementAndGet()
            Thread.sleep(150) // hold the flight open so waiters queue behind the leader
            okhttp3.mockwebserver.MockResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.tokenResponseJson(accessToken = "shared-access"))
        }

        val results = (1..6).map {
            async(Dispatchers.IO) {
                client.oidcRefresh(OidcRefreshParams.of("old-refresh", tenantId = "22222222-2222-2222-2222-222222222222"))
            }
        }.awaitAll()

        assertEquals(1, tokenCalls.get())
        results.forEach { assertEquals("shared-access", it.accessToken.expose()) }
    }

    @Test
    fun `a failed oidcRefresh delivers the same failure to every waiter with no retry`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        val tokenCalls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            tokenCalls.incrementAndGet()
            Thread.sleep(150) // hold the flight open so waiters queue behind the leader
            okhttp3.mockwebserver.MockResponse().setResponseCode(400)
                .addHeader("Content-Type", "application/json")
                .setBody(OidcTestKit.oauth2ErrorJson("invalid_grant", "expired"))
        }

        val results = (1..4).map {
            async(Dispatchers.IO) {
                runCatching {
                    client.oidcRefresh(OidcRefreshParams.of("old-refresh", tenantId = "22222222-2222-2222-2222-222222222222"))
                }
            }
        }.awaitAll()

        assertEquals(1, tokenCalls.get())
        assertEquals(4, results.count { it.isFailure })
    }

    @Test
    fun `oidcRefresh omits an unsupplied scope field`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson())

        client.oidcRefresh(OidcRefreshParams(Sensitive.of("rt"), tenantId = "22222222-2222-2222-2222-222222222222"))

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assertEquals(false, request.body.readUtf8().contains("scope="))
    }
}
