package io.axiam.sdk.oidc

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.ValidationError
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * CONTRACT.md §12.1 `idp_hint` (contract 1.65) and §26.2 rule 8: the optional hint of
 * `oidcBegin`, emitted as `axiam_idp_hint`, and pushed in the body by `oidcPar`.
 */
class IdpHintTest {

    private lateinit var server: MockWebServer
    private lateinit var configuration: OidcConfiguration
    private lateinit var client: AxiamClient

    private val tenantId = "22222222-2222-2222-2222-222222222222"
    private val redirect = "https://app.example.com/callback"
    private val eight = setOf(
        "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
        "code_challenge", "code_challenge_method",
    )

    @BeforeEach
    fun setUp(): Unit = runBlocking {
        server = MockWebServer()
        server.dispatcher = OidcTestKit.routingDispatcher(server, OidcTestKit.generateSigningKey()).also {
            it.on("/oauth2/par") {
                MockResponse().setResponseCode(201).addHeader("Content-Type", "application/json")
                    .setBody("""{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}""")
            }
        }
        server.start()
        client = OidcTestKit.clientFor(server, clientId = "app", tenantId = tenantId)
        configuration = client.oidcDiscover()
        server.takeRequest() // the discovery fetch, so the PAR test reads its own request
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun begin(hint: String? = null, extra: Map<String, String> = emptyMap()) =
        client.oidcBegin(OidcBeginParams(configuration, redirect, extraParams = extra, idpHint = hint))

    private fun names(url: String) = url.toHttpUrl().queryParameterNames

    @Test
    fun idpHintEmittedOnce() {
        for (hint in listOf("corp-okta", "3f2b8c1e-7d44-4b0a-9a55-0e1c2d3e4f50", "Google", "a b&c=d/é+%41")) {
            val request = begin(hint)
            val url = request.url.toHttpUrl()
            assertEquals(listOf(hint), url.queryParameterValues("axiam_idp_hint"), "parsed, not a substring match")
            assertEquals(eight + "axiam_idp_hint", url.queryParameterNames)
            assertEquals(request.state, url.queryParameter("state"))
            assertEquals(request.nonce, url.queryParameter("nonce"))
            assertEquals("S256", url.queryParameter("code_challenge_method"))
            assertEquals(
                1,
                url.query!!.split("&").count { URLDecoder.decode(it.substringBefore('='), StandardCharsets.UTF_8) == "axiam_idp_hint" },
            )
        }
    }

    @Test
    fun idpHintOmittedWhenUnset() {
        val url = begin().url
        assertEquals(eight, names(url))
        assertFalse(url.contains("idp_hint"))
        assertFalse(names(url).contains("kc_idp_hint"))
        // A hint never produces the Keycloak spelling either.
        assertFalse(names(begin("corp-okta").url).contains("kc_idp_hint"))
    }

    @Test
    fun idpHintNotDuplicated() {
        val set = begin("corp-okta", mapOf("axiam_idp_hint" to "other")).url.toHttpUrl()
        assertEquals(listOf("corp-okta"), set.queryParameterValues("axiam_idp_hint"), "the option is the single source")
        // Unset: the caller's own extra still passes through, once.
        val passthrough = begin(null, mapOf("axiam_idp_hint" to "other")).url.toHttpUrl()
        assertEquals(listOf("other"), passthrough.queryParameterValues("axiam_idp_hint"))
    }

    @Test
    fun idpHintBounds() {
        assertThrows(ValidationError::class.java) { begin("") }
        assertThrows(ValidationError::class.java) { begin("a".repeat(257)) }
        assertThrows(ValidationError::class.java) { begin("é".repeat(129)) } // 258 UTF-8 bytes
        val max = "a".repeat(256)
        assertEquals(listOf(max), begin(max).url.toHttpUrl().queryParameterValues("axiam_idp_hint"))
        val maxMultiByte = "é".repeat(128) // exactly 256 bytes
        assertEquals(listOf(maxMultiByte), begin(maxMultiByte).url.toHttpUrl().queryParameterValues("axiam_idp_hint"))
        // Nothing else about the value is judged: whitespace, case and unknown names pass untouched.
        assertEquals(listOf(" Not A Provider "), begin(" Not A Provider ").url.toHttpUrl().queryParameterValues("axiam_idp_hint"))
    }

    @Test
    fun parIdpHintInPushedBody(): Unit = runBlocking {
        for (hint in listOf("corp-okta", null)) {
            val before = server.requestCount
            val begun = begin(hint)
            val pushed = client.oidcPar(OidcParParams(begun, redirect, configuration = configuration, tenantId = tenantId, idpHint = hint))
            assertEquals(before + 1, server.requestCount)
            val request = server.takeRequest()
            assertEquals("/oauth2/par", request.requestUrl!!.encodedPath)
            val fields = request.body.readUtf8().split("&").map {
                URLDecoder.decode(it.substringBefore('='), StandardCharsets.UTF_8) to
                    URLDecoder.decode(it.substringAfter('='), StandardCharsets.UTF_8)
            }
            val hints = fields.filter { it.first == "axiam_idp_hint" }.map { it.second }
            assertEquals(if (hint == null) emptyList() else listOf(hint), hints)
            assertFalse(fields.any { it.first == "kc_idp_hint" })

            // The redirect stays exactly client_id + request_uri (+ the tenant routing parameter
            // §26.2 rule 2 carves out, which the PAR suite pins): the hint never rides it.
            val url = pushed.url.toHttpUrl()
            assertEquals(setOf("tenant_id", "client_id", "request_uri"), url.queryParameterNames)
            assertTrue(url.queryParameter("axiam_idp_hint") == null)
        }
        // Same bounds as oidcBegin, refused with no push.
        val before = server.requestCount
        assertThrows(ValidationError::class.java) {
            runBlocking { client.oidcPar(OidcParParams(begin(), redirect, configuration = configuration, idpHint = "")) }
        }
        assertEquals(before, server.requestCount)
    }
}
