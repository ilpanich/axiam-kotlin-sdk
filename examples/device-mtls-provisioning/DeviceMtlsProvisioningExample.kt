package io.axiam.sdk.examples.devicemtlsprovisioning

import io.axiam.sdk.AxiamClient
import io.axiam.sdk.errors.ConflictError
import io.axiam.sdk.errors.NotFoundError
import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.PageRequest
import io.axiam.sdk.management.models.BindCertificate
import io.axiam.sdk.management.models.CertificateStatus
import io.axiam.sdk.management.models.CertificateType
import io.axiam.sdk.management.models.CreateCertificateRequest
import io.axiam.sdk.management.models.CreateServiceAccountRequest
import io.axiam.sdk.management.models.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.system.exitProcess

/**
 * Provisions an IoT device with an mTLS identity, then lets the device
 * authenticate with it.
 *
 * Two halves, and the split between them is the point.
 *
 * **The operator half** (`provision`) runs once, on a machine an administrator
 * controls, against an authenticated CONTRACT.md §27 management client. It
 * creates the device's service account, mints a Device certificate from the
 * tenant's signing CA, binds the two, and writes the private key to disk. That
 * key is returned by exactly one call and never again (§27.5) — no later `get`
 * has a field where it was — so losing the response means revoking the
 * certificate and minting another.
 *
 * **The device half** (`run`) runs on the device, forever after, with no
 * password and no management access at all. It presents the certificate and key
 * as a §6.1 mutual-TLS identity and does nothing else privileged.
 *
 * Run:
 * ```
 * AXIAM_BASE_URL=https://axiam.example.com AXIAM_TENANT=acme \
 * AXIAM_ADMIN=admin@example.com AXIAM_ADMIN_PASSWORD=... \
 *   ./gradlew runDeviceMtlsProvisioningExample --args="provision sensor-42"
 *   ./gradlew runDeviceMtlsProvisioningExample --args="run     sensor-42"
 *   ./gradlew runDeviceMtlsProvisioningExample --args="revoke  sensor-42"
 * ```
 */
object DeviceMtlsProvisioningExample {

    private val baseUrl = env("AXIAM_BASE_URL", "https://localhost:8443")
    private val tenant = env("AXIAM_TENANT", "acme")
    private val admin = env("AXIAM_ADMIN", "admin@example.com")
    private val adminPassword = env("AXIAM_ADMIN_PASSWORD", "")

    /** Where the device's certificate and private key are written, and read back. */
    private val identityDir: Path = Path.of(env("AXIAM_DEVICE_DIR", "./device-identity"))

    @JvmStatic
    fun main(args: Array<String>): Unit = runBlocking {
        if (args.size != 2) {
            System.err.println("usage: provision|run|revoke <device-name>")
            exitProcess(2)
        }
        val device = args[1]
        try {
            when (args[0]) {
                "provision" -> provision(device)
                "run" -> run(device)
                "revoke" -> revoke(device)
                else -> {
                    System.err.println("usage: provision|run|revoke <device-name>")
                    exitProcess(2)
                }
            }
        } catch (e: ValidationError) {
            // §27.4 rule 7: the server rejected the input, and said which parts.
            System.err.println("rejected: ${e.message} ${e.fields}")
            exitProcess(1)
        }
    }

    /**
     * Creates the device's identity and writes it to disk, once.
     *
     * Every step is a §27 management write, and §27.4 rule 8 does not retry
     * writes — generating a certificate twice mints two, and only one of them
     * ends up on the device.
     */
    private suspend fun provision(device: String) {
        client().use { client ->
            client.login(admin, adminPassword)

            // 1. The signing CA this tenant's device certificates chain to.
            //    {org_id} defaults from the client (§27.4 rule 3). {tenant_id}
            //    does NOT on this route: under caCertificates it names the
            //    tenant being administered rather than the calling context, so
            //    it is an ordinary argument — which is what resolvedTenantId()
            //    is public for.
            val tenantId = client.resolvedTenantId()
                ?: error("login did not resolve a tenant UUID; cannot address signing CAs")
            val issuer = client.management().caCertificates()
                .listSigningCasAll(tenantId, PageRequest.of(100))
                .firstOrNull { it.status == CertificateStatus.ACTIVE }
                ?: error(
                    "tenant '$tenant' has no active signing CA; generate one with " +
                        "caCertificates().generateSigningCa(...) before provisioning devices",
                )

            // 2. The service account the device authenticates as.
            val account = try {
                client.management().serviceAccounts().create(
                    CreateServiceAccountRequest(
                        description = "IoT device $device, mTLS identity",
                        name = device,
                    ),
                )
            } catch (e: ConflictError) {
                // Already provisioned. Re-minting a certificate for an existing
                // account is a decision an operator should make deliberately, so
                // this stops rather than quietly issuing a second identity.
                error(
                    "a service account named '$device' already exists; revoke its certificate " +
                        "and delete it first, or pick another name (${e.message})",
                )
            }

            // 3. The certificate. privateKeyPem comes back from THIS call and no
            //    other — certificates().get() has no field where it was.
            val certificate = client.management().certificates().generate(
                CreateCertificateRequest(
                    certType = CertificateType.DEVICE,
                    issuerCaId = issuer.id,
                    keyAlgorithm = KeyAlgorithm.ED25519,
                    subject = "CN=$device,OU=devices,O=$tenant",
                    validityDays = 825,
                ),
            )

            // 4. Write it down before doing anything else that could fail. The
            //    key is a Sensitive, so expose() is the one explicit unwrap
            //    (§27.5) — printing `certificate` anywhere shows [SENSITIVE].
            writeSecret(identityDir.resolve("$device-key.pem"), certificate.privateKeyPem.expose())
            Files.createDirectories(identityDir)
            Files.writeString(
                identityDir.resolve("$device-cert.pem"),
                certificate.publicCertPem + (certificate.chainPem ?: ""),
            )

            // 5. Bind the certificate to the account, so presenting it
            //    authenticates as that principal.
            client.management().serviceAccounts()
                .bindCertificate(account.id, BindCertificate(certificateId = certificate.id))

            println("provisioned $device")
            println("  service account : ${account.id}")
            println("  certificate     : ${certificate.id} (${certificate.fingerprint})")
            println("  valid until     : ${certificate.notAfter}")
            println("  identity written: $identityDir/")
        }
    }

    /**
     * Authenticates as the device, with the identity provisioning wrote.
     *
     * No password, no management surface, no secret in the environment — the
     * private key on disk *is* the credential. Presenting it never relaxes
     * server verification (§6.1 rule 2): strict TLS stays fully on.
     */
    private suspend fun run(device: String) {
        val cert = identityDir.resolve("$device-cert.pem")
        val key = identityDir.resolve("$device-key.pem")
        if (!Files.exists(cert) || !Files.exists(key)) {
            error("no identity for '$device' in $identityDir/; provision it first")
        }
        AxiamClient.builder(baseUrl, tenant)
            .clientCertificate(Files.readAllBytes(cert), Files.readAllBytes(key))
            .build()
            .use { println("$device may publish telemetry: ${it.can("telemetry:publish", "device/$device")}") }
    }

    /**
     * Revokes the device's certificate — the decommissioning path.
     *
     * Deleting the service account alone leaves a valid certificate in the
     * field; revoking the certificate is what actually stops the device
     * authenticating.
     */
    private suspend fun revoke(device: String) {
        client().use { client ->
            client.login(admin, adminPassword)

            val account = client.management().serviceAccounts()
                .listAll(PageRequest.of(200)).firstOrNull { it.name == device }
                ?: error("no service account named '$device'")

            for (certificate in client.management().certificates().listAll(PageRequest.of(200))) {
                if (!certificate.subject.startsWith("CN=$device,")) continue
                try {
                    client.management().certificates().revoke(certificate.id)
                } catch (e: NotFoundError) {
                    continue
                }
                println("revoked ${certificate.id}")
            }

            client.management().serviceAccounts().delete(account.id)
            println("deleted service account ${account.id}")
        }
    }

    private fun client(): AxiamClient =
        AxiamClient.builder(baseUrl, tenant).orgSlug(tenant).build()

    /**
     * Writes [content] readable only by this user.
     *
     * The mode is set at creation rather than afterwards: a chmod after the fact
     * leaves a window in which the key is world-readable, which on a shared
     * provisioning host is the whole exposure.
     */
    private fun writeSecret(path: Path, content: String) {
        Files.createDirectories(path.parent)
        Files.deleteIfExists(path)
        try {
            Files.createFile(
                path,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
            )
        } catch (e: UnsupportedOperationException) {
            // Not a POSIX filesystem. Fall back to the closest thing available
            // rather than writing a key with default permissions silently.
            Files.createFile(path)
            path.toFile().setReadable(false, false)
            path.toFile().setReadable(true, true)
            path.toFile().setWritable(false, false)
            path.toFile().setWritable(true, true)
        }
        Files.writeString(path, content)
    }

    private fun env(name: String, fallback: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
}
