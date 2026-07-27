package io.axiam.sdk.oidc

import io.axiam.sdk.errors.AuthError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OidcLoginClientCredentialsTest {

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
    fun `loginClientCredentials happy path posts grant_type=client_credentials and returns no id_token`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson(accessToken = "m2m-access"))

        val result = client.loginClientCredentials(
            LoginClientCredentialsParams(tenantId = "22222222-2222-2222-2222-222222222222"),
        )

        assertEquals("m2m-access", result.accessToken.expose())
        assertNull(result.idToken)
        assertNull(result.idClaims)

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        val body = request.body.readUtf8()
        assert(body.contains("grant_type=client_credentials"))
        assert(body.contains("client_secret=${OidcTestKit.CLIENT_SECRET}"))
    }

    @Test
    fun `loginClientCredentials requires a configured client secret`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = null)
        client.oidcDiscover()
        assertThrows(AuthError::class.java) {
            runBlocking {
                client.loginClientCredentials(LoginClientCredentialsParams(tenantId = "22222222-2222-2222-2222-222222222222"))
            }
        }
    }

    @Test
    fun `loginClientCredentials forwards an optional scope`(): Unit = runBlocking {
        val client = OidcTestKit.clientFor(server, clientSecret = OidcTestKit.CLIENT_SECRET)
        client.oidcDiscover()
        dispatcher.onJson("/oauth2/token", 200, OidcTestKit.tokenResponseJson())

        client.loginClientCredentials(
            LoginClientCredentialsParams(scope = "reports:read", tenantId = "22222222-2222-2222-2222-222222222222"),
        )

        var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        while (!request.path!!.startsWith("/oauth2/token")) {
            request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
        }
        assert(request.body.readUtf8().contains("scope=reports%3Aread"))
    }
}
