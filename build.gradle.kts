import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    id("org.jetbrains.dokka") version "1.9.20"
    id("org.jetbrains.kotlinx.kover") version "0.8.3"
    `maven-publish`
    signing
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()

repositories {
    mavenCentral()
}

val ktorVersion = "2.3.12"

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

    // Ktor is an OPTIONAL integration (§10/§11): the core compiles and runs
    // without it. compileOnly keeps it off a non-Ktor consumer's classpath;
    // Ktor users add ktor-server-core themselves.
    compileOnly("io.ktor:ktor-server-core:$ktorVersion")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    // In-memory test PKI (HeldCertificate / HandshakeCertificates) for the mTLS
    // test — no private key material is ever committed.
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
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

tasks.test {
    useJUnitPlatform()
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

val runRestAuthzExample by tasks.registering(JavaExec::class) {
    group = "examples"
    description = "Run examples/rest-authz/RestAuthzExample.kt"
    classpath = examples.runtimeClasspath
    mainClass.set("io.axiam.sdk.examples.restauthz.RestAuthzExample")
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
            // Regression floor set below the current ~91% line coverage so it
            // never false-fails; ratchet upward as coverage rises.
            rule {
                minBound(88)
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
            // The uploaded deployment then either auto-releases (if the namespace's
            // publishing default is set to "Automatic" in the Portal) or waits for a
            // manual "Publish" in the Deployments view.
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
