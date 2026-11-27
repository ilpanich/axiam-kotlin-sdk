package io.axiam.sdk

import com.nimbusds.jose.jwk.JWKSet
import io.axiam.sdk.internal.JwksTls
import io.axiam.sdk.internal.JwksVerifier
import io.axiam.sdk.internal.TlsFactory
import io.axiam.sdk.oidc.OidcTestKit
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

/**
 * CONTRACT.md §6.1 / §12.3 rule 6: the client identity goes to the JWKS endpoint only when the `jwks_uri` has the
 * same origin as the base URL; another origin gets `customCa` trust alone.
 */
class JwksClientIdentityOriginTest {

    private lateinit var server: MockWebServer
    private lateinit var tls: JwksTls
    private val key = AccessTokenFixtures.newKey("k1")

    @BeforeEach
    fun setUp() {
        val ca = HeldCertificate.Builder().certificateAuthority(0).commonName("Test Root CA").build()
        val serverCert = HeldCertificate.Builder()
            .commonName("localhost").addSubjectAlternativeName("localhost").addSubjectAlternativeName("127.0.0.1")
            .signedBy(ca).build()
        val clientCert = HeldCertificate.Builder().commonName("device-1").signedBy(ca).build()
        val handshake = HandshakeCertificates.Builder()
            .heldCertificate(serverCert).addTrustedCertificate(ca.certificate).build()
        server = MockWebServer()
        server.useHttps(handshake.sslSocketFactory(), false)
        server.requestClientAuth() // optional: the request records whether an identity was presented
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = MockResponse().setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(JWKSet(key.toPublicJWK()).toString())
        }
        server.start()
        val full = TlsFactory.build(
            ca.certificatePem().toByteArray(),
            clientCert.certificatePem().toByteArray(),
            Sensitive.of(clientCert.privateKeyPkcs8Pem().toByteArray()),
        )
        val trustOnly = TlsFactory.build(ca.certificatePem().toByteArray(), null, null)
        tls = JwksTls(full.sslContext.socketFactory, trustOnly.sslContext.socketFactory)
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private fun presentedCertificates(baseUrl: String): Int {
        val jwksUri = server.url("/oauth2/jwks").toString()
        val verifier = JwksVerifier.forJwksUri(jwksUri, baseUrl, tls)
        val token = OidcTestKit.signIdToken(key, "https://issuer.example.com", nonce = null)
        verifier.verifyForIdToken(token)
        verifier.awaitIdleForTesting()
        val request = server.takeRequest(2, TimeUnit.SECONDS)
        assertNotNull(request)
        return request!!.handshake?.peerCertificates?.size ?: 0
    }

    @Test
    fun `the identity is presented to a jwks_uri on the base URL's origin`() {
        assertEquals(1, presentedCertificates(server.url("/").toString()))
    }

    @Test
    fun `no identity is presented to a jwks_uri on another origin`() {
        assertEquals(0, presentedCertificates("https://other.example"))
    }

    @Test
    fun `customCa adds to the default trust store for the JWKS fetch instead of replacing it`() {
        val ca = HeldCertificate.Builder().certificateAuthority(0).commonName("Added CA").build()
        val trustOnly = TlsFactory.build(ca.certificatePem().toByteArray(), null, null).trustManager
        // The added CA is trusted ...
        trustOnly.checkServerTrusted(arrayOf(ca.certificate), "RSA")
        // ... and so is a root of the JVM default store (a one-certificate chain that is itself an anchor).
        val defaults = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as java.security.KeyStore?) }
            .trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().first()
        val root = defaults.acceptedIssuers.first()
        trustOnly.checkServerTrusted(arrayOf(root), "RSA")
        // An unrelated self-signed certificate is still refused.
        val stranger = HeldCertificate.Builder().certificateAuthority(0).commonName("Stranger").build()
        org.junit.jupiter.api.Assertions.assertThrows(Exception::class.java) {
            trustOnly.checkServerTrusted(arrayOf(stranger.certificate), "RSA")
        }
    }
}
