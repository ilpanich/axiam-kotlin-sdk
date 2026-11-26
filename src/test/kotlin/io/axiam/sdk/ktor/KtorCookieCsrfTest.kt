package io.axiam.sdk.ktor

import com.nimbusds.jose.jwk.OctetKeyPair
import io.axiam.sdk.AccessTokenFixtures
import io.axiam.sdk.AccessTokenFixtures.strings
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.options
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * CONTRACT.md §3a (restated in contract 1.68; N12) — the resource-server guard
 * must apply the cookie double-submit check when the credential it accepted was
 * the `axiam_access` COOKIE and the method is state-changing.
 *
 * Each case also asserts how many times the guarded handler ran: a handler that
 * runs, even if a 403 is written afterwards, has already done the work the
 * request forged.
 */
class KtorCookieCsrfTest {

    private lateinit var key: OctetKeyPair
    private lateinit var jwks: AccessTokenFixtures.Jwks
    private val handlerRuns = AtomicInteger()

    @BeforeEach
    fun setUp() {
        key = AccessTokenFixtures.newKey("k1")
        jwks = AccessTokenFixtures.Jwks(key)
        handlerRuns.set(0)
    }

    @AfterEach
    fun tearDown() = jwks.shutdown()

    private fun token(roles: Boolean = false) =
        AccessTokenFixtures.mint(key, claims = if (roles) mapOf("roles" to strings("admin")) else emptyMap())

    /** One app with a guarded route per method and per §11 helper, all bumping [handlerRuns]. */
    private fun ApplicationTestBuilder.guardedApp(axiam: io.axiam.sdk.AxiamClient) {
        application {
            install(AxiamAuthentication) { this.client = axiam }
            routing {
                post("/auth") { call.requireAuth() ?: return@post; handlerRuns.incrementAndGet(); call.respondText("ran") }
                put("/auth") { call.requireAuth() ?: return@put; handlerRuns.incrementAndGet(); call.respondText("ran") }
                patch("/auth") { call.requireAuth() ?: return@patch; handlerRuns.incrementAndGet(); call.respondText("ran") }
                delete("/auth") { call.requireAuth() ?: return@delete; handlerRuns.incrementAndGet(); call.respondText("ran") }
                post("/role") { call.requireRole("admin") ?: return@post; handlerRuns.incrementAndGet(); call.respondText("ran") }
                // No helper at all: the plugin alone must refuse before the handler.
                post("/bare") { handlerRuns.incrementAndGet(); call.respondText("ran") }
                get("/auth") { call.requireAuth() ?: return@get; handlerRuns.incrementAndGet(); call.respondText("ran") }
                head("/auth") { handlerRuns.incrementAndGet(); call.respondText("ran") }
                options("/auth") { handlerRuns.incrementAndGet(); call.respondText("ran") }
            }
        }
    }

    private suspend fun HttpClient.send(
        method: HttpMethod,
        path: String,
        cookie: String? = null,
        bearer: String? = null,
        csrfHeader: String? = null,
    ): HttpResponse = request(path) {
        this.method = method
        cookie?.let { header(HttpHeaders.Cookie, it) }
        bearer?.let { header(HttpHeaders.Authorization, "Bearer $it") }
        csrfHeader?.let { header("X-CSRF-Token", it) }
    }

    @Test
    fun `a cookie-sourced POST with no X-CSRF-Token header is refused 403 and the handler does not run`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, handlerRuns.get(), "the guarded handler must not run on a CSRF failure")
        axiam.close()
    }

    @Test
    fun `the same POST with a matching X-CSRF-Token is admitted`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x", csrfHeader = "x")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `a mismatched X-CSRF-Token is refused 403`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x", csrfHeader = "y")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `a header with no axiam_csrf cookie to compare against is refused 403`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=${token()}", csrfHeader = "x")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `an empty header and an empty cookie do not match each other`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=", csrfHeader = "")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `PUT PATCH and DELETE are state-changing too`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        for (method in listOf(HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete)) {
            val response = client.send(method, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x")
            assertEquals(HttpStatusCode.Forbidden, response.status, "$method without the header")
            val ok = client.send(method, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x", csrfHeader = "x")
            assertEquals(HttpStatusCode.OK, ok.status, "$method with the header")
        }
        assertEquals(3, handlerRuns.get(), "only the three requests carrying the header reach the handler")
        axiam.close()
    }

    @Test
    fun `the check runs before a role helper can admit the request`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val refused = client.send(HttpMethod.Post, "/role", cookie = "axiam_access=${token(roles = true)}; axiam_csrf=x")
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertTrue(refused.bodyAsText().contains("csrf"), "the 403 must say it is the CSRF check")
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `a route with no helper is still protected by the plugin`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/bare", cookie = "axiam_access=${token()}; axiam_csrf=x")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `a Bearer-authenticated POST with no CSRF material is admitted`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", bearer = token())
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `a Bearer header wins over a cookie and keeps the exemption`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(
            HttpMethod.Post, "/auth",
            bearer = token(), cookie = "axiam_access=${token()}; axiam_csrf=x",
        )
        assertEquals(HttpStatusCode.OK, response.status)
        axiam.close()
    }

    @Test
    fun `safe methods with the cookie and no header are admitted`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        for (method in listOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)) {
            val response = client.send(method, "/auth", cookie = "axiam_access=${token()}; axiam_csrf=x")
            assertEquals(HttpStatusCode.OK, response.status, "$method")
        }
        assertEquals(3, handlerRuns.get())
        axiam.close()
    }

    @Test
    fun `an invalid cookie token is still 401 not 403`() = testApplication {
        val axiam = jwks.client()
        guardedApp(axiam)
        val response = client.send(HttpMethod.Post, "/auth", cookie = "axiam_access=not-a-jwt; axiam_csrf=x")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(0, handlerRuns.get())
        axiam.close()
    }
}
