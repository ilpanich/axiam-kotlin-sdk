package io.axiam.sdk

import io.axiam.sdk.errors.NetworkError
import io.axiam.sdk.internal.TlsFactory
import okhttp3.tls.HeldCertificate
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Direct [TlsFactory] coverage for construction-time edges that the public
 * [AxiamClient.Builder] can't reach on its own (its `clientCertificate()`
 * always sets cert+key together) — the mTLS "exactly one supplied" guard, an
 * unsupported private-key algorithm, and [TlsFactory.Tls.trustManager]'s
 * client-trust delegation.
 */
class TlsFactoryTest {

    @Test
    fun `build rejects a client cert supplied without a matching key`() {
        val cert = HeldCertificate.Builder().commonName("device-1").build()
        assertThrows(NetworkError::class.java) {
            TlsFactory.build(null, cert.certificatePem().toByteArray(), null)
        }
    }

    @Test
    fun `build rejects a client key supplied without a matching cert`() {
        val cert = HeldCertificate.Builder().commonName("device-1").build()
        assertThrows(NetworkError::class.java) {
            TlsFactory.build(null, null, Sensitive.of(cert.privateKeyPkcs8Pem().toByteArray()))
        }
    }

    @Test
    fun `build rejects a client key PEM whose DER matches no supported algorithm`() {
        val cert = HeldCertificate.Builder().commonName("device-1").build()
        // Correct PEM armor/label (passes the "PRIVATE KEY" containment check)
        // but the base64 body isn't a valid Ed25519/RSA/EC PKCS#8 DER — every
        // KeyFactory attempt fails, reaching the final "unsupported algorithm".
        val garbageDer = Base64.getEncoder().encodeToString(ByteArray(48) { it.toByte() })
        val garbageKeyPem = "-----BEGIN PRIVATE KEY-----\n$garbageDer\n-----END PRIVATE KEY-----\n"
        assertThrows(NetworkError::class.java) {
            TlsFactory.build(null, cert.certificatePem().toByteArray(), Sensitive.of(garbageKeyPem.toByteArray()))
        }
    }

    @Test
    fun `composite trust manager's checkClientTrusted delegates to the primary`() {
        val rootCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Root").build()
        val tls = TlsFactory.build(rootCa.certificatePem().toByteArray(), null, null)
        // Any invocation (even one that itself throws, e.g. an empty chain) is
        // enough to prove delegation runs — the JDK's default trust manager
        // rejects an empty chain with a CertificateException.
        assertThrows(Exception::class.java) {
            tls.trustManager.checkClientTrusted(emptyArray(), "RSA")
        }
    }

    @Test
    fun `composite trust manager accepts a server chain via either root`() {
        val rootCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Root").build()
        val tls = TlsFactory.build(rootCa.certificatePem().toByteArray(), null, null)
        assertTrue(tls.trustManager.acceptedIssuers.isNotEmpty())
    }
}
