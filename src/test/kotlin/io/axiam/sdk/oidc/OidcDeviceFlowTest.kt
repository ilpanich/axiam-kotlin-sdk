package io.axiam.sdk.oidc

import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.errors.OAuthProtocolError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Device Authorization Grant — CONTRACT.md §14.
 *
 * Fixtures use a 1-second interval so the wire assertions — which answers
 * loop, which terminate, how many requests actually go out, and the §14.3
 * rule 2 ordering guarantee — run in about as long as they take to describe.
 */
class OidcDeviceFlowTest {

    private lateinit var server: MockWebServer
    private lateinit var signingKey: com.nimbusds.jose.jwk.OctetKeyPair
    private lateinit var dispatcher: OidcTestKit.RoutingDispatcher

    private val tenantId = "22222222-2222-2222-2222-222222222222"

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

    private fun base() = server.url("/").toString()

    /** A device client: no client secret, per §14.1. */
    private fun deviceClient() = OidcTestKit.clientFor(server)

    private fun mountAuthorization(expiresIn: Int = 30, interval: Int? = 1) {
        dispatcher.onJson(
            "/oauth2/device_authorization",
            200,
            OidcTestKit.deviceAuthorizationJson(base(), expiresIn, interval),
        )
    }

    /** Replies with each response in order, repeating the last once exhausted. */
    private fun scriptToken(vararg steps: () -> MockResponse) {
        val index = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            val i = index.getAndIncrement()
            steps[minOf(i, steps.size - 1)]()
        }
    }

    private fun oauthError(code: String) = MockResponse()
        .setResponseCode(400)
        .addHeader("Content-Type", "application/json")
        .setBody(OidcTestKit.oauth2ErrorJson(code, "$code description"))

    private fun tokenSuccess() = MockResponse()
        .setResponseCode(200)
        .addHeader("Content-Type", "application/json")
        .setBody(OidcTestKit.tokenResponseJson(accessToken = "device-access-token"))

    // -----------------------------------------------------------------------
    // deviceAuthorize
    // -----------------------------------------------------------------------

    @Test
    fun `deviceAuthorize is unauthenticated, form-encoded, and sends tenant_id as a query param`(): Unit = runBlocking {
        mountAuthorization()
        val client = deviceClient()

        val authorization = client.deviceAuthorize(
            DeviceAuthorizeParams(scope = "openid profile", tenantId = tenantId),
        )

        // discovery, then the authorization request
        server.takeRequest()
        val request = server.takeRequest()
        // Decoded rather than matched raw: OkHttp percent-encodes the space in
        // a multi-scope value, and asserting on the encoding would test OkHttp
        // rather than the request this SDK builds.
        val body = java.net.URLDecoder.decode(request.body.readUtf8(), "UTF-8")

        assertTrue(request.getHeader("Content-Type")!!.startsWith("application/x-www-form-urlencoded"))
        assertFalse(body.contains("client_secret"), "§14.1: deviceAuthorize MUST NOT send client_secret")
        assertTrue(body.contains("scope=openid profile"))
        assertFalse(body.contains("tenant_id"), "§12.1 note 2: tenant_id is a query parameter")
        assertEquals(tenantId, request.requestUrl!!.queryParameter("tenant_id"))

        assertEquals(OidcTestKit.USER_CODE, authorization.userCode)
        assertEquals(1, authorization.interval)
        assertNotNull(authorization.verificationUriComplete)
    }

    @Test
    fun `an absent interval defaults to five seconds, never faster`(): Unit = runBlocking {
        mountAuthorization(expiresIn = 600, interval = null)

        val authorization = deviceClient().deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))

        assertEquals(
            OidcSupport.DEFAULT_POLL_INTERVAL_SECONDS,
            authorization.interval,
            "§14.2 rule 2: an SDK MUST NOT hard-code a faster floor",
        )
    }

    @Test
    fun `a server-sent interval of zero is treated as absent`(): Unit = runBlocking {
        // Polling with no delay is never what the server meant.
        mountAuthorization(expiresIn = 600, interval = 0)

        val authorization = deviceClient().deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))

        assertEquals(OidcSupport.DEFAULT_POLL_INTERVAL_SECONDS, authorization.interval)
    }

    @Test
    fun `deviceAuthorize errors rather than guessing a URL when the endpoint is absent`(): Unit = runBlocking {
        val bareDispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = { OidcTestKit.discoveryJsonWithoutOptionalEndpoints(base()) },
            jwksBody = { OidcTestKit.jwksJson(signingKey.toPublicJWK()) },
        )
        server.dispatcher = bareDispatcher

        val error = assertThrows(AuthError::class.java) {
            runBlocking { deviceClient().deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId)) }
        }
        assertTrue(
            error.message!!.contains("device_authorization_endpoint"),
            "the error should name the missing endpoint",
        )
    }

    @Test
    fun `the device code is redacted but the user code is not`(): Unit = runBlocking {
        mountAuthorization()

        val authorization = deviceClient().deviceAuthorize(DeviceAuthorizeParams(tenantId = tenantId))

        assertFalse(
            authorization.toString().contains(OidcTestKit.DEVICE_CODE),
            "§14.5: device_code is a bearer credential and must never render",
        )
        assertEquals(OidcTestKit.DEVICE_CODE, authorization.deviceCode.expose())
        // §14.5: userCode is NOT wrapped — it exists to be read aloud, and
        // wrapping it would defeat the one thing it is for.
        assertEquals(OidcTestKit.USER_CODE, authorization.userCode)
        assertTrue(authorization.toString().contains(OidcTestKit.USER_CODE))
    }

    // -----------------------------------------------------------------------
    // §14.2 polling
    // -----------------------------------------------------------------------

    @Test
    fun `authorization_pending loops rather than raising`(): Unit = runBlocking {
        mountAuthorization()
        scriptToken(
            { oauthError("authorization_pending") },
            { oauthError("authorization_pending") },
            { tokenSuccess() },
        )

        val tokens = deviceClient().deviceLogin(
            DeviceLoginParams(tenantId = tenantId, onUserCode = { }),
        )

        assertEquals("device-access-token", tokens.accessToken.expose())
    }

    @Test
    fun `slow_down is not terminal`(): Unit = runBlocking {
        // The interval increase itself is not wall-clock-asserted; what matters
        // is that slow_down is not mistaken for a terminal answer. An SDK that
        // let it fall through would abort a grant the user is still approving.
        mountAuthorization(expiresIn = 60)
        scriptToken({ oauthError("slow_down") }, { tokenSuccess() })

        val tokens = deviceClient().deviceLogin(
            DeviceLoginParams(tenantId = tenantId, onUserCode = { }),
        )

        assertEquals("device-access-token", tokens.accessToken.expose())
    }

    @Test
    fun `access_denied, expired_token and invalid_grant are terminal and distinct`(): Unit = runBlocking {
        // §14.2 rule 3: "a human said no" and "nobody answered" are the only
        // two pieces of information the device can act on.
        for (code in listOf("access_denied", "expired_token", "invalid_grant")) {
            mountAuthorization()
            val polls = AtomicInteger(0)
            dispatcher.on("/oauth2/token") {
                polls.incrementAndGet()
                oauthError(code)
            }

            val error = assertThrows(OAuthProtocolError::class.java) {
                runBlocking {
                    deviceClient().deviceLogin(DeviceLoginParams(tenantId = tenantId, onUserCode = { }))
                }
            }
            assertEquals(code, error.error)
            assertEquals(1, polls.get(), "a terminal answer must stop the loop at once")
        }
    }

    @Test
    fun `polling stops at expires_in even while the server still says pending`(): Unit = runBlocking {
        // 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick
        // is the deadline and must not be sent.
        mountAuthorization(expiresIn = 2, interval = 1)
        val polls = AtomicInteger(0)
        dispatcher.on("/oauth2/token") {
            polls.incrementAndGet()
            oauthError("authorization_pending")
        }

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                deviceClient().deviceLogin(DeviceLoginParams(tenantId = tenantId, onUserCode = { }))
            }
        }

        assertEquals(
            "expired_token",
            error.error,
            "§14.2 rule 4: reported under the same code the server would have used, so a " +
                "caller's branch does not care which side noticed first",
        )
        assertEquals(1, polls.get(), "no poll may be sent past the deadline")
    }

    @Test
    fun `a 5xx mid-poll is retried, not treated as terminal`(): Unit = runBlocking {
        mountAuthorization(expiresIn = 60)
        scriptToken(
            { oauthError("authorization_pending") },
            { MockResponse().setResponseCode(500) },
            { MockResponse().setResponseCode(503) },
            { tokenSuccess() },
        )

        val tokens = deviceClient().deviceLogin(
            DeviceLoginParams(tenantId = tenantId, onUserCode = { }),
        )

        assertEquals(
            "device-access-token",
            tokens.accessToken.expose(),
            "§14.2 rule 6: a server restart must not lose an approved grant",
        )
    }

    // -----------------------------------------------------------------------
    // §14.3 deviceLogin
    // -----------------------------------------------------------------------

    @Test
    fun `deviceLogin surfaces the user code before the first poll and awaits the callback`(): Unit = runBlocking {
        mountAuthorization()
        val order = mutableListOf<String>()
        dispatcher.on("/oauth2/token") {
            order.add("poll")
            tokenSuccess()
        }

        var seen: String? = null
        deviceClient().deviceLogin(
            DeviceLoginParams(
                tenantId = tenantId,
                onUserCode = { authorization ->
                    // A suspend callback: a device rendering a QR code may need
                    // to await a paint, and polling before that resolves would
                    // defeat rule 2 as surely as not calling back at all.
                    kotlinx.coroutines.delay(20)
                    order.add("userCode")
                    seen = authorization.userCode
                },
            ),
        )

        assertEquals(listOf("userCode", "poll"), order, "§14.3 rule 2")
        assertEquals(OidcTestKit.USER_CODE, seen)
    }

    @Test
    fun `a successful deviceLogin returns a token set carrying the access token`(): Unit = runBlocking {
        mountAuthorization()
        dispatcher.on("/oauth2/token") { tokenSuccess() }

        val tokens = deviceClient().deviceLogin(
            DeviceLoginParams(tenantId = tenantId, onUserCode = { }),
        )

        // §14.6 as amended by the contract 1.7 errata: assert the RETURNED
        // token set. This SDK does not adopt — §14.3 rule 4 defers to the
        // §12.1 loginClientCredentials MAY, and Kotlin's settled posture there
        // is to leave the tokens with the caller.
        assertEquals("device-access-token", tokens.accessToken.expose())
        assertEquals("Bearer", tokens.tokenType)
    }

    // -----------------------------------------------------------------------
    // devicePoll standalone
    // -----------------------------------------------------------------------

    @Test
    fun `devicePoll surfaces pending so a hand-rolled loop sees what deviceLogin sees`(): Unit = runBlocking {
        dispatcher.on("/oauth2/token") { oauthError("authorization_pending") }

        val error = assertThrows(OAuthProtocolError::class.java) {
            runBlocking {
                deviceClient().devicePoll(
                    DevicePollParams(
                        deviceCode = io.axiam.sdk.Sensitive.of(OidcTestKit.DEVICE_CODE),
                        tenantId = tenantId,
                    ),
                )
            }
        }
        assertEquals("authorization_pending", error.error)
    }

    @Test
    fun `devicePoll sends the device-code grant type`(): Unit = runBlocking {
        dispatcher.on("/oauth2/token") { tokenSuccess() }

        deviceClient().devicePoll(
            DevicePollParams(
                deviceCode = io.axiam.sdk.Sensitive.of(OidcTestKit.DEVICE_CODE),
                tenantId = tenantId,
            ),
        )

        server.takeRequest() // discovery
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"))
        assertTrue(body.contains("device_code=${OidcTestKit.DEVICE_CODE}"))
    }
}
