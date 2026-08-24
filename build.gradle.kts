import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka") version "1.9.20"
    id("org.jetbrains.kotlinx.kover") version "0.9.9"
    `maven-publish`
    signing
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()

repositories {
    mavenCentral()
}

val ktorVersion = "2.3.12"
val rabbitMqVersion = "5.25.0"
val jnaVersion = "5.19.1"

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // JavaNetCookieJar (CookieManager-backed CookieJar adapter) — §4 cookie jar.
    implementation("com.squareup.okhttp3:okhttp-urlconnection:4.12.0")
    // JWKS fetch/cache + EdDSA (Ed25519) verification — §9 local-verify companion.
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")
    // nimbus delegates Ed25519 sign/verify to Tink — required at runtime for the
    // EdDSA JWKS verification path (mirrors the Java SDK's tink dependency).
    implementation("com.google.crypto.tink:tink:1.15.0")

    // NOTE: org.bouncycastle:bcprov-jdk18on used to sit here, for the §23 SRP
    // client's Argon2id. It is gone with SRP: CONTRACT §23.1 forbids an SDK
    // from implementing OPAQUE, so this SDK derives nothing locally and the key
    // stretching happens inside libaxiam_opaque_ffi. Nothing else in src/main
    // imported org.bouncycastle, so keeping a ~8 MB provider on every
    // consumer's classpath for a code path that no longer exists would be a
    // dependency nobody could explain a year from now.

    // JNA binds libaxiam_opaque_ffi, the OPAQUE (RFC 9807) client half.
    // CONTRACT §23.1 forbids an SDK from implementing OPAQUE itself, so the
    // protocol comes from the same shared library the AXIAM server links.
    //
    // compileOnly, like Ktor and the RabbitMQ client above: a REST/gRPC/AMQP
    // consumer whose tenant does not use OPAQUE should not be made to carry a
    // native-access library. OPAQUE users add net.java.dev.jna:jna themselves.
    // Its absence is a NoClassDefFoundError the loader catches, after which
    // AxiamClient.opaqueAvailable() answers false rather than throwing at
    // login time.
    //
    // Not the Java 22 FFM API: this SDK targets JVM 17, where java.lang.foreign
    // does not exist at all. Raising the target to 22 to avoid one optional
    // dependency would be the larger break by a wide margin.
    compileOnly("net.java.dev.jna:jna:$jnaVersion")

    // Ktor is an OPTIONAL integration (§10/§11): the core compiles and runs
    // without it. compileOnly keeps it off a non-Ktor consumer's classpath;
    // Ktor users add ktor-server-core themselves.
    compileOnly("io.ktor:ktor-server-core:$ktorVersion")

    // The RabbitMQ Java client backs the §22 reactor runtime's bundled
    // transport. Like Ktor above it is an OPTIONAL integration: the core
    // compiles and runs without it, and a consumer who writes no reactor never
    // carries it. Reactor authors add `com.rabbitmq:amqp-client` themselves.
    // §22.10 is explicit that a reactor runtime IS an AMQP consumer, so this is
    // the dependency that lets Kotlin ship one at all — and compileOnly is how
    // it arrives without widening every other consumer's classpath.
    compileOnly("com.rabbitmq:amqp-client:$rabbitMqVersion")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    // In-memory test PKI (HeldCertificate / HandshakeCertificates) for the mTLS
    // test — no private key material is ever committed.
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("com.rabbitmq:amqp-client:$rabbitMqVersion")
    // The OPAQUE tests implement the C ABI in plain Kotlin, which needs JNA's
    // Pointer/Memory types even though no shared library is loaded.
    testImplementation("net.java.dev.jna:jna:$jnaVersion")
    testImplementation("io.ktor:ktor-server-core:$ktorVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
}

kotlin {
    // Target JVM 17 bytecode. A strict toolchain(17) is intentionally NOT pinned
    // so the build runs on either JDK 17 (CI's setup-java) or a newer JDK
    // (e.g. 21) while always emitting 17-compatible bytecode.
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        allWarningsAsErrors.set(false)
    }
}

// The JVM that EXECUTES the tests, chosen independently of the JVM running
// Gradle. These are not the same question, and conflating them is what broke
// the first attempt at a JDK 25 CI leg: Gradle 8.10.2 cannot itself run on
// Java 25 (it fails with a bare, unrecognised "25.0.4"), so pointing
// setup-java at 25 killed the build before a single test ran.
//
// What the SDK actually claims is that its JVM 17 bytecode RUNS on a modern
// JVM — which is a statement about the test launcher, not about Gradle's own
// runtime. A toolchain launcher says exactly that and nothing more: Gradle
// stays on a JDK it supports, compiles to JVM 17 as always, and forks the test
// JVM on the requested version.
//
// Absent the property, tests run on Gradle's own JVM, as before.
val testJavaVersion: Provider<String> = providers.gradleProperty("testJavaVersion")
val javaToolchainService = extensions.getByType<JavaToolchainService>()

tasks.test {
    useJUnitPlatform()

    if (testJavaVersion.isPresent) {
        javaLauncher.set(
            javaToolchainService.launcherFor {
                languageVersion.set(JavaLanguageVersion.of(testJavaVersion.get().toInt()))
            },
        )
        // Hand the requested version to the suite so VersionPolicyTest can
        // confirm the fork actually happened. A toolchain that silently fell
        // back to Gradle's own JVM would otherwise leave the leg reporting
        // green while testing nothing it was added to test.
        systemProperty("axiam.expectedTestJvm", testJavaVersion.get())
    }

    // VersionPolicyTest reads these three files to assert that the declared
    // support range, the published Kotlin version and the CI matrix still
    // agree. Gradle knows nothing about that: the test task's declared inputs
    // are sources and classpath, so with `org.gradle.caching=true` (and the
    // cache that gradle/actions/setup-gradle restores in CI) a change to the
    // workflow YAML alone leaves :test UP-TO-DATE and Gradle serves the
    // previous PASS — the exact drift the test exists to catch would sail
    // through green. Declaring them as inputs is what makes the gate real.
    inputs.file("gradle.properties").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file("build.gradle.kts").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(".github/workflows/sdk-ci-kotlin.yml")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    testLogging {
        events("passed", "skipped", "failed")
    }
}

// ---- Examples (compile-checked, NOT published) ---------------------------
// A dedicated 'examples' source set compiles the runnable samples under
// examples/ against the main SDK output, so they can never drift from the
// public API. `./gradlew compileExamplesKotlin` (also wired into `check`)
// keeps them honest; `runLoginMfaExample` / `runRestAuthzExample` run them.
// These sources are excluded from the published jar and Dokka.
val examples: SourceSet by sourceSets.creating

configurations["examplesImplementation"].extendsFrom(configurations["implementation"])
configurations["examplesRuntimeOnly"].extendsFrom(configurations["runtimeOnly"])

dependencies {
    "examplesImplementation"(sourceSets["main"].output)
    // The UMA resource-server example runs a real Ktor server, which the SDK
    // itself only depends on at compile time (Ktor users bring their own
    // engine). The examples source set therefore needs both the server core the
    // plugin is written against and an engine to actually listen on.
    "examplesImplementation"("io.ktor:ktor-server-core:$ktorVersion")
    "examplesImplementation"("io.ktor:ktor-server-netty:$ktorVersion")
    // examples/reactor drives the bundled RabbitMQ transport.
    "examplesImplementation"("com.rabbitmq:amqp-client:$rabbitMqVersion")
}

// Point the examples compilation at the flat examples/ tree (mirrors the other
// AXIAM SDKs' examples/<topic>/<File> layout) instead of src/examples/kotlin.
sourceSets["examples"].resources.setSrcDirs(emptyList<String>())
kotlin.sourceSets["examples"].kotlin.setSrcDirs(listOf("examples"))

tasks.named("check") {
    dependsOn("compileExamplesKotlin")
}

val runLoginMfaExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/login-mfa/LoginMfaExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.loginmfa.LoginMfaExample")
}

val runOpaqueLoginExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/opaque-login/OpaqueLoginExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.opaquelogin.OpaqueLoginExample")
}

val runRestAuthzExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/rest-authz/RestAuthzExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.restauthz.RestAuthzExample")
}

val runVersionCompatibilityExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/version-compatibility/VersionCompatibilityExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set(
        "io.axiam.sdk.examples.versioncompatibility.VersionCompatibilityExample",
    )
}

val runOidcLoginExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/oidc-login/OidcLoginExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.oidclogin.OidcLoginExample")
    standardInput = System.`in`
}

val runUmaResourceServerExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/uma-resource-server/UmaResourceServerExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.umaresourceserver.UmaResourceServerExample")
}

val runReactorExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/reactor/ReactorExample.kt (needs a reachable amqps:// broker)"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.reactor.ReactorExample")
}

val runWebauthnPasskeysExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/webauthn-passkeys/WebauthnPasskeysExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.webauthnpasskeys.WebauthnPasskeysExample")
}

val runAccountLifecycleExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/account-lifecycle/AccountLifecycleExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.accountlifecycle.AccountLifecycleExample")
}

val runParLoginExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/par-login/ParLoginExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.parlogin.ParLoginExample")
}

val runUmaClientExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/uma-client/UmaClientExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.umaclient.UmaClientExample")
}

// Dokka -> javadoc jar (javadoc.io serves this verbatim).
val dokkaJavadocJar by tasks.registering(Jar::class) {
    dependsOn(tasks.dokkaJavadoc)
    from(tasks.dokkaJavadoc.flatMap { it.outputDirectory })
    archiveClassifier.set("javadoc")
}

val sourcesJar by tasks.registering(Jar::class) {
    from(kotlin.sourceSets["main"].kotlin)
    archiveClassifier.set("sources")
}

kover {
    reports {
        // The runnable samples under examples/ are demonstration code, not part
        // of the SDK's tested surface — exclude them so they don't drag down the
        // coverage ratio (they have no unit tests by design).
        filters {
            excludes {
                classes("io.axiam.sdk.examples.*")
            }
        }
        verify {
            // Regression floor set ~1 point below the achieved ~99.1% line
            // coverage (measured 2026-07-23) so it never false-fails while
            // still catching a real regression; ratchet upward as coverage rises.
            rule {
                minBound(98)
            }
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = project.group.toString()
            artifactId = "axiam-sdk-kotlin"
            version = project.version.toString()

            from(components["java"])
            artifact(sourcesJar)
            artifact(dokkaJavadocJar)

            pom {
                name.set("axiam-sdk-kotlin")
                description.set("Official Kotlin client SDK for AXIAM IAM")
                url.set("https://github.com/ilpanich/axiam-kotlin-sdk")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        name.set("AXIAM Maintainers")
                        url.set("https://github.com/ilpanich/axiam-kotlin-sdk")
                    }
                }
                scm {
                    url.set("https://github.com/ilpanich/axiam-kotlin-sdk")
                    connection.set("scm:git:https://github.com/ilpanich/axiam-kotlin-sdk.git")
                    developerConnection.set("scm:git:https://github.com/ilpanich/axiam-kotlin-sdk.git")
                }
            }
        }
    }
    repositories {
        maven {
            // Sonatype Central (the new Central Portal, central.sonatype.com).
            //
            // maven-publish deploys by doing an HTTP PUT for each artifact to a
            // per-file path — the classic OSSRH / Nexus staging protocol. The
            // Portal's own upload endpoint (/api/v1/publisher/upload) is NOT that:
            // it only accepts a single POST of a zipped bundle and has no
            // per-artifact PUT paths, so every PUT 404s there.
            //
            // Sonatype provides an OSSRH Staging API compatibility service that
            // speaks the exact PUT protocol maven-publish uses and forwards the
            // result into the Central Portal as a validated deployment. Point the
            // deploy there. Credentials are the Portal-generated user token
            // (Account -> Generate User Token) — the same CENTRAL_TOKEN_* values.
            //
            // IMPORTANT: `./gradlew publish` only performs the PUTs. That leaves
            // the artifacts in an *open* staging repository — the maven-publish
            // plugin does NOT close/forward it, so nothing reaches the Portal on
            // its own. A separate POST to
            //   /manual/upload/defaultRepository/<namespace>?publishing_type=...
            // is required to close the staging repo and forward it to the Portal
            // (see the "Close & forward" step in .github/workflows/sdk-ci-kotlin.yml).
            // Only after that does the deployment appear in the Deployments view
            // and — with publishing_type=automatic — auto-release to Central.
            name = "central"
            url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("CENTRAL_TOKEN_USERNAME")
                password = System.getenv("CENTRAL_TOKEN_PASSWORD")
            }
        }
    }
}

signing {
    // Signing OFF by default; flipped on in CI via an in-memory key (ephemeral in
    // the PR gate, the real CI-secret key in the tag-triggered publish job).
    isRequired = false
    val signingKey = System.getenv("GPG_PRIVATE_KEY")
    val signingPassphrase = System.getenv("GPG_PASSPHRASE")
    if (!signingKey.isNullOrBlank()) {
        useInMemoryPgpKeys(signingKey, signingPassphrase ?: "")
        sign(publishing.publications["maven"])
    }
}
