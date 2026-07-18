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
            // Sonatype Central Portal (mirrors the Java SDK's Maven Central deploy).
            name = "central"
            url = uri("https://central.sonatype.com/api/v1/publisher/upload")
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
