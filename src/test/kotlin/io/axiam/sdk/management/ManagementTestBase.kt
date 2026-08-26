package io.axiam.sdk.management

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.TestSupport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Shared scaffolding for the CONTRACT.md §27 management tests.
 *
 * The generated conformance suite and the hand-written semantics suites both
 * build a client the same way: a real `login()` against a mocked endpoint, so
 * the org and tenant UUIDs the management routes interpolate come from the
 * access token's claims exactly as they would in production, rather than being
 * poked into private fields by the test.
 *
 * MockWebServer's default queue is the wrong shape here — a management test
 * mounts a route and asserts the SDK reached *that* path, which a queue cannot
 * express. So this installs a [Dispatcher] that routes on method and path and
 * fails loudly on anything unmounted.
 */
abstract class ManagementTestBase {

    /** The mocked server every test in this hierarchy talks to. */
    protected lateinit var server: MockWebServer

    /** A logged-in client pointed at [server]. */
    protected lateinit var client: AxiamClient

    private val routes = ConcurrentHashMap<String, Route>()
    private val unmatched = mutableListOf<String>()

    /** What one mounted route answered, and what actually reached it. */
    class Route(private val status: Int, private val body: String) {
        internal val requests = mutableListOf<Recorded>()

        /** How many requests reached this route. */
        fun calls(): Int = requests.size

        /** The most recent request this route saw. */
        fun last(): Recorded = requests.lastOrNull() ?: throw AssertionError("route was never called")

        internal fun respond(): MockResponse {
            val response = MockResponse().setResponseCode(status)
            if (body.isNotEmpty()) {
                response.setHeader("Content-Type", "application/json").setBody(body)
            }
            return response
        }
    }

    /**
     * What a mounted route saw.
     *
     * @property method the HTTP method
     * @property path the path, without the query string
     * @property query the decoded query parameters
     * @property body the raw request body
     * @property headers the request headers, matched case-insensitively
     */
    data class Recorded(
        val method: String,
        val path: String,
        val query: Map<String, String>,
        val body: String,
        val headers: Map<String, String>,
    ) {
        /** The request body's key set, sorted. */
        fun keys(): List<String> = json().keys.sorted()

        /** The request body as a JSON object. */
        fun json(): JsonObject = Json.parseToJsonElement(body) as JsonObject
    }

    /** Starts the server and logs a client in against it. */
    @BeforeEach
    fun startServer() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val full = request.path ?: ""
                val bare = full.substringBefore('?')

                if (bare == "/api/v1/auth/login") {
                    return TestSupport.loginOkResponse(
                        TestSupport.fakeJwt(tenantId = TENANT_ID.toString(), orgId = orgClaim),
                    )
                }

                val route = routes["${request.method} $bare"]
                if (route == null) {
                    unmatched += "${request.method} $bare"
                    return MockResponse().setResponseCode(501)
                        .setBody("no route mounted for ${request.method} $bare")
                }
                val query = buildMap {
                    if ('?' in full) {
                        for (pair in full.substringAfter('?').split('&')) {
                            val eq = pair.indexOf('=')
                            if (eq > 0) {
                                put(
                                    URLDecoder.decode(pair.take(eq), StandardCharsets.UTF_8),
                                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8),
                                )
                            }
                        }
                    }
                }
                // Header names are case-insensitive on the wire, so the recorded
                // map is too: the SDK sends X-Tenant-Id and an assertion
                // spelling it X-Tenant-ID is still asserting the same header.
                val headers = sortedMapOf<String, String>(String.CASE_INSENSITIVE_ORDER)
                request.headers.forEach { (name, value) -> headers[name] = value }
                route.requests += Recorded(
                    request.method ?: "", bare, query, request.body.readUtf8(), headers,
                )
                return route.respond()
            }
        }
        server.start()
        client = AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build()
        kotlinx.coroutines.runBlocking { client.login("admin@example.test", "hunter2hunter2") }
    }

    /** Shuts the client and server down. */
    @AfterEach
    fun stopServer() {
        client.close()
        server.close()
    }

    /**
     * Mounts one route, answering [body] at [status].
     *
     * The match is exact on method and path, so an operation that sends its
     * request somewhere other than the registry's path fails here rather than
     * falling through to another mock.
     *
     * @param method the HTTP method to match
     * @param path the exact path to match
     * @param status the status to answer with
     * @param body the body to answer with, or empty for none
     * @return the mounted route, for assertions
     */
    protected fun mount(method: String, path: String, status: Int, body: String): Route {
        val route = Route(status, body)
        routes["$method $path"] = route
        return route
    }

    /**
     * The route mounted at `method path`, for assertions.
     *
     * @param method the mounted method
     * @param path the mounted path
     * @return the route
     */
    protected fun route(method: String, path: String): Route =
        routes["$method $path"] ?: throw AssertionError("no route mounted at $method $path")

    /** Requests that reached no mounted route. */
    protected fun unmatched(): List<String> = unmatched.toList()

    /** How many requests reached any mounted route, plus any that missed. */
    protected fun totalCalls(): Int = routes.values.sumOf { it.calls() } + unmatched.size

    /** The org_id claim the mocked login endpoint mints; overridable per test. */
    private var orgClaim: String = ORG_ID.toString()

    /**
     * Makes every subsequent login mint a token whose `org_id` is [value].
     *
     * @param value the raw claim to embed, valid UUID or not
     */
    protected fun mintOrgClaim(value: String) {
        orgClaim = value
    }

    /**
     * Logs [other] in against this suite's mocked login endpoint.
     *
     * @param other a client built against [server] but not yet logged in
     */
    protected suspend fun login(other: AxiamClient) {
        other.login("admin@example.test", "hunter2hunter2")
    }

    /**
     * Asserts every field the server sent survived the decode onto [value].
     *
     * Re-encodes the decoded model and compares its key set against the body the
     * route answered with. The mounted bodies carry exactly the fields
     * `openapi.json` marks required, so anything missing here is a field the
     * generated model dropped — which is not a hypothetical: the Go port of this
     * surface silently lost `provisioning_token`, a ONE-TIME secret, to a
     * generator that mishandled an inline `allOf`. Nothing in a surface test
     * that only checks the method and path would have noticed.
     *
     * @param value the decoded model
     * @param serializer that model's generated serializer
     * @param sent the raw body the route answered with
     */
    protected fun <T> assertDecodedEveryField(
        value: T,
        serializer: kotlinx.serialization.KSerializer<T>,
        sent: String,
    ) {
        val expected = (Json.parseToJsonElement(sent) as JsonObject).keys.sorted()
        val actual = (
            io.axiam.sdk.internal.ManagementTransport.READER
                .encodeToJsonElement(serializer, value) as JsonObject
            ).keys.sorted()
        val dropped = expected - actual.toSet()
        if (dropped.isNotEmpty()) {
            throw AssertionError(
                "${value!!::class.simpleName} dropped $dropped: the server sent " +
                    "${expected.size} fields and the model carries ${actual.size}. A field the " +
                    "generator did not emit is one no caller can ever read.",
            )
        }
    }

    /** The §27.9 expected surface: every operation the vendored registry declares. */
    protected fun expectedSurface(): List<String> {
        val registry = Json.parseToJsonElement(
            java.io.File("management-registry.json").readText(),
        ) as JsonObject
        val namespaces = registry["namespaces"] as JsonObject
        return namespaces.flatMap { (ns, body) ->
            ((body as JsonObject)["operations"] as JsonObject).keys.map { "$ns.$it" }
        }.sorted()
    }

    companion object {
        /** The organization UUID the test client's access token carries. */
        val ORG_ID: UUID = UUID.fromString("22222222-2222-4222-8222-222222222222")

        /** The tenant UUID the test client's access token carries. */
        val TENANT_ID: UUID = UUID.fromString("33333333-3333-4333-8333-333333333333")

        /** The identifier the generated cases pass for every `{..._id}` parameter. */
        val EXAMPLE_ID: UUID = UUID.fromString("11111111-1111-4111-8111-111111111111")

        /** The slug the client is built with, and sends as `X-Tenant-Id` (§5 rule 2). */
        const val TENANT_SLUG = "acme"

        /** A single-item page envelope around [item]. */
        fun pageOf(item: String?): String =
            if (item == null) {
                """{"items":[],"total":0,"offset":0,"limit":200}"""
            } else {
                """{"items":[$item],"total":1,"offset":0,"limit":200}"""
            }

        /** A minimal role response body. */
        fun roleBody(id: UUID, name: String, description: String): String =
            """{"id":"$id","name":"$name","description":"$description","is_global":false,""" +
                """"tenant_id":"$TENANT_ID","created_at":"2026-08-26T00:00:00Z",""" +
                """"updated_at":"2026-08-26T00:00:00Z"}"""
    }
}
