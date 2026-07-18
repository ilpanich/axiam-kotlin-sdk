package io.axiam.sdk

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.util.Base64
import java.util.UUID

/** Shared test helpers: a client pointed at a MockWebServer and fake-JWT minting. */
object TestSupport {

    const val TENANT_ID = "acme"
    val ORG_ID: UUID = UUID.fromString("11111111-1111-1111-1111-111111111111")
    val TENANT_UUID: UUID = UUID.fromString("22222222-2222-2222-2222-222222222222")

    fun clientFor(server: MockWebServer, orgId: UUID? = ORG_ID): AxiamClient =
        AxiamClient.builder(server.url("/").toString(), TENANT_ID)
            .apply { if (orgId != null) orgId(orgId) }
            .build()

    /**
     * Mints a NON-cryptographic JWT (`header.payload.sig`) whose payload decodes
     * via the SDK's unverified claim decoder. Used to seed the cookie jar with a
     * session the SDK can read tenant/org/jti/exp from — never for signature
     * verification (that path uses a real Ed25519 token elsewhere).
     */
    fun fakeJwt(
        sub: String = "user-1",
        tenantId: String = TENANT_UUID.toString(),
        orgId: String = ORG_ID.toString(),
        jti: String = "session-1",
        scope: String = "documents:read documents:write",
        expEpochSec: Long = System.currentTimeMillis() / 1000 + 3600,
    ): String {
        val header = """{"alg":"EdDSA","typ":"JWT"}"""
        val payload = """{"sub":"$sub","tenant_id":"$tenantId","org_id":"$orgId",""" +
            """"jti":"$jti","scope":"$scope","exp":$expEpochSec}"""
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString(header.toByteArray()) + "." +
            enc.encodeToString(payload.toByteArray()) + ".c2ln"
    }

    /** A 200 response that sets the access (and refresh) session cookies. */
    fun loginOkResponse(accessJwt: String = fakeJwt(), refresh: String = "refresh-token"): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .addHeader("Set-Cookie", "axiam_access=$accessJwt; Path=/")
            .addHeader("Set-Cookie", "axiam_refresh=$refresh; Path=/")
            .addHeader("X-CSRF-Token", "csrf-abc")
            .setBody("{}")

    fun json(code: Int, body: String): MockResponse =
        MockResponse().setResponseCode(code).setBody(body).addHeader("Content-Type", "application/json")
}
