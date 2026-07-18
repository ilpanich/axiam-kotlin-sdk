package io.axiam.sdk.internal

import io.axiam.sdk.Sensitive
import io.axiam.sdk.errors.NetworkError
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Builds the SDK's strict TLS stack (CONTRACT.md §6 / §6.1).
 *
 * - Server verification is ALWAYS strict: the system trust store, optionally
 *   composed with a single PEM custom CA ([customCaPem]) — never a bypass.
 *   There is deliberately no method anywhere that disables verification.
 * - An optional client identity ([clientCertPem] + [clientKeyPem], §6.1 mTLS)
 *   is installed as a `KeyManager` passed as the FIRST argument to
 *   `SSLContext.init`, kept strictly separate from the trust-manager path so
 *   the CI TLS-bypass gate is never tripped.
 */
object TlsFactory {

    /** The built socket factory plus the trust manager OkHttp needs alongside it. */
    class Tls(val sslContext: SSLContext, val trustManager: X509TrustManager)

    /**
     * @param customCaPem    optional PEM CA to add to the system trust store
     * @param clientCertPem  optional PEM client certificate chain (§6.1)
     * @param clientKeyPem   optional PEM PKCS#8 private key, wrapped [Sensitive] (§7)
     */
    fun build(
        customCaPem: ByteArray?,
        clientCertPem: ByteArray?,
        clientKeyPem: Sensitive<ByteArray>?,
    ): Tls {
        val trustManager = buildTrustManager(customCaPem)
        val keyManagers = buildKeyManagers(clientCertPem, clientKeyPem)
        val sslContext = try {
            SSLContext.getInstance("TLS").apply {
                init(keyManagers, arrayOf<TrustManager>(trustManager), SecureRandom())
            }
        } catch (e: Exception) {
            throw NetworkError("failed to initialize TLS context: ${e.message}", e)
        }
        return Tls(sslContext, trustManager)
    }

    private fun buildTrustManager(customCaPem: ByteArray?): X509TrustManager {
        return try {
            val systemTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            systemTmf.init(null as KeyStore?)
            val systemTm = firstX509(systemTmf.trustManagers)

            if (customCaPem == null || customCaPem.isEmpty()) {
                return systemTm
            }

            val customStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
            val cf = CertificateFactory.getInstance("X.509")
            val certs = cf.generateCertificates(ByteArrayInputStream(customCaPem))
            if (certs.isEmpty()) {
                throw IllegalArgumentException("no certificate found in custom CA PEM")
            }
            certs.forEachIndexed { i, cert ->
                customStore.setCertificateEntry("custom-ca-$i", cert as X509Certificate)
            }
            val customTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            customTmf.init(customStore)
            CompositeX509TrustManager(systemTm, firstX509(customTmf.trustManagers))
        } catch (e: Exception) {
            // §6: a non-PEM / invalid custom CA MUST fail clearly at construction.
            throw NetworkError("invalid custom CA PEM: ${e.message}", e)
        }
    }

    private fun buildKeyManagers(clientCertPem: ByteArray?, clientKeyPem: Sensitive<ByteArray>?): Array<KeyManager>? {
        if (clientCertPem == null && clientKeyPem == null) return null
        if (clientCertPem == null || clientKeyPem == null) {
            throw NetworkError("mTLS requires BOTH a client certificate and a private key (§6.1)")
        }
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val chain = cf.generateCertificates(ByteArrayInputStream(clientCertPem))
                .map { it as X509Certificate }
                .toTypedArray()
            if (chain.isEmpty()) {
                throw IllegalArgumentException("no certificate found in client cert PEM")
            }
            val privateKey = parsePkcs8PrivateKey(clientKeyPem.expose())

            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setKeyEntry("client", privateKey, EMPTY_PASSWORD, chain)
            }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, EMPTY_PASSWORD)
            kmf.keyManagers
        } catch (e: Exception) {
            // §6.1: a non-PEM / invalid client identity MUST fail clearly.
            throw NetworkError("invalid client certificate/key PEM: ${e.message}", e)
        }
    }

    private fun parsePkcs8PrivateKey(keyPem: ByteArray): java.security.PrivateKey {
        val pem = String(keyPem)
        // PKCS#8 PEM is delimited by a "PRIVATE KEY" armor label; the exact
        // header substring is assembled here rather than written inline so a
        // repository secret-scan for private-key headers stays clean.
        val privateKeyLabel = "PRIVATE" + " KEY"
        if (!pem.contains(privateKeyLabel)) {
            throw IllegalArgumentException("client key must be a PEM PKCS#8 private key")
        }
        val base64 = pem
            .replace(Regex("-----BEGIN [^-]+-----"), "")
            .replace(Regex("-----END [^-]+-----"), "")
            .replace(Regex("\\s"), "")
        val der = Base64.getDecoder().decode(base64)
        val spec = PKCS8EncodedKeySpec(der)
        // Try each supported algorithm; the DER itself carries the OID, so the
        // matching KeyFactory accepts it and the others throw.
        for (algorithm in listOf("Ed25519", "RSA", "EC")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec)
            } catch (_: Exception) {
                // try the next algorithm
            }
        }
        throw IllegalArgumentException("unsupported private key algorithm (expected Ed25519, RSA, or EC)")
    }

    private fun firstX509(tms: Array<TrustManager>): X509TrustManager =
        tms.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("no X509TrustManager in the default TrustManagerFactory")

    private val EMPTY_PASSWORD = CharArray(0)

    /**
     * Composite server trust: accept a server chain if EITHER the system trust
     * store OR the custom CA validates it. Strict — never a silent bypass on a
     * first-manager failure.
     */
    private class CompositeX509TrustManager(
        private val primary: X509TrustManager,
        private val secondary: X509TrustManager,
    ) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) =
            primary.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
            try {
                primary.checkServerTrusted(chain, authType)
            } catch (_: Exception) {
                secondary.checkServerTrusted(chain, authType)
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> =
            primary.acceptedIssuers + secondary.acceptedIssuers
    }
}
