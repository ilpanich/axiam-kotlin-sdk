package io.axiam.sdk

import com.nimbusds.jose.jwk.JWKSet
import io.axiam.sdk.errors.AuthError
import io.axiam.sdk.oidc.OidcTestKit
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * CONTRACT.md §6: `customCa` is the private-CA mechanism, so it must reach the JWKS fetch as well as the
 * HTTP client (#107). The JWKS endpoint here is HTTPS with a server certificate issued by an in-memory
 * test CA that only `customCa` trusts; a client WITHOUT the CA must still fail (TLS stays strict).
 */
class JwksCustomCaTest {

    private lateinit var server: MockWebServer
    private lateinit var rootCaPem: String
    private val key = AccessTokenFixtures.newKey("k1")

    @BeforeEach
    fun setUp() {
        val rootCa = HeldCertificate.Builder().certificateAuthority(0).commonName("AXIAM Test Root CA").build()
        val serverCert = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .signedBy(rootCa)
            .build()
        rootCaPem = rootCa.certificatePem()
        val handshake = HandshakeCertificates.Builder().heldCertificate(serverCert).build()
        server = MockWebServer()
        server.useHttps(handshake.sslSocketFactory(), false)
        server.dispatcher = OidcTestKit.RoutingDispatcher(
            discoveryBody = { OidcTestKit.discoveryJson(server.url("/").toString()) },
            jwksBody = { JWKSet(key.toPublicJWK()).toString() },
        )
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun builder() = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
        .oidcClientId(OidcTestKit.CLIENT_ID)

    @Test
    fun `verifySession fetches the JWKS through customCa`() {
        builder().customCa(rootCaPem.toByteArray()).build().use { c ->
            val user = c.verifySession(AccessTokenFixtures.mint(key))
            c.jwksVerifier().awaitIdleForTesting()
            assertEquals("user-1", user.userId)
        }
    }

    @Test
    fun `without the CA the JWKS fetch still fails closed`() {
        builder().build().use { c ->
            try {
                assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
            } finally {
                c.jwksVerifier().awaitIdleForTesting()
            }
        }
    }

    @Test
    fun `the OIDC logout-token path fetches the JWKS through customCa`(): Unit = runBlocking {
        val issuer = server.url("/").toString().trimEnd('/')
        builder().customCa(rootCaPem.toByteArray()).build().use { c ->
            val verified = c.verifyLogoutToken(OidcTestKit.signLogoutToken(key, issuer))
            assertEquals(OidcTestKit.LOGOUT_SID, verified.sid)
        }
    }

    @Test
    fun `a certificate for another host name is refused even though its CA is trusted`() {
        val ca = HeldCertificate.Builder().certificateAuthority(0).commonName("Other Root CA").build()
        val wrongHost = HeldCertificate.Builder()
            .commonName("elsewhere.invalid")
            .addSubjectAlternativeName("elsewhere.invalid")
            .signedBy(ca)
            .build()
        val other = MockWebServer()
        other.useHttps(HandshakeCertificates.Builder().heldCertificate(wrongHost).build().sslSocketFactory(), false)
        other.dispatcher = server.dispatcher
        other.start()
        try {
            AxiamClient.builder(other.url("/").toString(), TestSupport.TENANT_ID)
                .customCa(ca.certificatePem().toByteArray())
                .build().use { c ->
                    try {
                        assertThrows(AuthError::class.java) { c.verifySession(AccessTokenFixtures.mint(key)) }
                    } finally {
                        c.jwksVerifier().awaitIdleForTesting()
                    }
                }
        } finally {
            other.shutdown()
        }
    }
}
