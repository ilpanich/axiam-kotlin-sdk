package io.axiam.sdk

import io.axiam.sdk.errors.NetworkError
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * §6.1 mTLS: a MockWebServer configured with requireClientAuth over HTTPS. All
 * PKI (root CA, server cert, client cert) is generated in-memory at test time
 * via okhttp-tls — no key material is ever written to disk or committed.
 */
class MtlsTest {

    private lateinit var server: MockWebServer
    private lateinit var rootCaPem: String
    private lateinit var clientCertPem: String
    private lateinit var clientKeyPem: String

    @BeforeEach
    fun setUp() {
        val rootCa = HeldCertificate.Builder()
            .certificateAuthority(0)
            .commonName("AXIAM Test Root CA")
            .build()

        val serverCert = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .signedBy(rootCa)
            .build()

        val clientCert = HeldCertificate.Builder()
            .commonName("device-1")
            .signedBy(rootCa)
            .build()

        rootCaPem = rootCa.certificatePem()
        clientCertPem = clientCert.certificatePem()
        clientKeyPem = clientCert.privateKeyPkcs8Pem()

        val serverHandshake = HandshakeCertificates.Builder()
            .heldCertificate(serverCert)
            .addTrustedCertificate(rootCa.certificate) // trust client certs signed by the root
            .build()

        server = MockWebServer()
        server.useHttps(serverHandshake.sslSocketFactory(), false)
        server.requireClientAuth()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    @Test
    fun `client presenting a certificate completes the mTLS handshake`() = runBlocking {
        server.enqueue(TestSupport.json(200, """{"allowed":true}"""))
        val client = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .customCa(rootCaPem.toByteArray())
            .clientCertificate(clientCertPem.toByteArray(), clientKeyPem.toByteArray())
            .build()
        client.use {
            val result = it.checkAccess("read", "r-1")
            assertTrue(result.allowed)
        }
    }

    @Test
    fun `client without a certificate fails the required client auth`() {
        // Trusts the server (customCa) but presents NO client identity — the
        // server's requireClientAuth rejects the handshake → NetworkError.
        val client = AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
            .customCa(rootCaPem.toByteArray())
            .build()
        client.use {
            assertThrows(NetworkError::class.java) {
                runBlocking { it.checkAccess("read", "r-1") }
            }
        }
    }

    @Test
    fun `mTLS configured with only one of cert or key is rejected at construction`() {
        assertThrows(NetworkError::class.java) {
            // Reflectively force the invalid one-sided state is not possible via the
            // public builder (clientCertificate takes both), so assert the builder
            // path with a garbage PEM key surfaces a clear construction error.
            AxiamClient.builder(server.url("/").toString(), TestSupport.TENANT_ID)
                .customCa(rootCaPem.toByteArray())
                .clientCertificate(clientCertPem.toByteArray(), "not-a-pem-key".toByteArray())
                .build()
        }
    }
}
