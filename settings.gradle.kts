pluginManagement {
    val kotlinVersion: String = providers.gradleProperty("kotlinVersion").get()
    plugins {
        kotlin("jvm") version kotlinVersion
        kotlin("plugin.serialization") version kotlinVersion
    }
}

rootProject.name = "axiam-sdk-kotlin"

// ---- Transitive security floors ------------------------------------------
// Dependabot cannot raise these itself: none is a direct dependency, so its
// security updates fail with `dependency_not_found`. None reaches the
// published POM: all come in through Gradle plugins (Kotlin, Dokka, Kover) or
// the compile-checked `examples` source set. They still sit in the dependency
// graph GitHub scans, and the examples really run a Netty server.
//
//  - jackson-core / jackson-databind 2.22.0–2.22.2: GHSA-7hhh-6rmp-j9qf,
//    GHSA-p6pp-m3f8-5c89, GHSA-cxp5-3px4-pw24, GHSA-wv8q-qhhj-9h54 (fixed in 2.22.3).
//  - io.netty 4.2.x before 4.2.21.Final: ktor-server-netty 3.3.3 asks for 4.2.7,
//    whose netty-codec-http/-http2 carry the request-smuggling and HTTP/2 DoS
//    advisories fixed up to 4.2.17. Every io.netty 4.2 module is aligned, not just
//    the codecs: amqp-client already brings netty-common 4.2.21, and mixing 4.2.7
//    native transports with a 4.2.21 core is its own runtime hazard.
//  - org.bouncycastle *-jdk18on 1.80 (bcprov/bcpkix/bcpg/bcutil): the Kotlin Gradle
//    plugin's own kotlinBouncyCastleConfiguration. Name-constraints bypass, ASN.1
//    nesting guard, risky algorithm in bcpkix, resource consumption in bcpg; 1.85
//    covers all four.
//  - org.freemarker:freemarker 2.3.32: Kover's coverage reporter (buildscript).
//  - io.opentelemetry api/context 1.41.0: the Kotlin plugin's swift-export
//    classpath.
//
// Floors, not pins: a newer request passes through untouched. Drop an entry when
// the upstream that pulls it (Dokka, Ktor, Kover, the Kotlin plugin) ships the patched version itself.
fun ResolutionStrategy.applySecurityFloors() = eachDependency {
    // The number right after `prefix`, from a plain version or from the lower
    // bound of a range: with prefix "1.", both "1.80.2" and "[1.80,1.81)" give 80.
    val version = requested.version?.trimStart('[', '(') ?: return@eachDependency
    fun after(prefix: String): Int? =
        version.takeIf { it.startsWith(prefix) }?.removePrefix(prefix)
            ?.takeWhile(Char::isDigit)?.toIntOrNull()
    fun floor(to: String, reason: String) {
        useVersion(to)
        because(reason)
    }
    when {
        requested.group == "com.fasterxml.jackson.core" &&
            requested.name in setOf("jackson-core", "jackson-databind") ->
            after("2.22.")?.takeIf { it < 3 }
                ?.let { floor("2.22.3", "GHSA-7hhh-6rmp-j9qf et al.: fixed in jackson 2.22.3") }
        requested.group == "io.netty" ->
            after("4.2.")?.takeIf { it < 21 }
                ?.let { floor("4.2.21.Final", "netty-codec-http/-http2 advisories: align Netty 4.2 at 4.2.21.Final") }
        // Every *-jdk18on module moves together: bcpkix/bcpg/bcutil pin bcprov
        // to their own minor ([1.80,1.81)), so raising one alone breaks the range.
        requested.group == "org.bouncycastle" && requested.name.endsWith("-jdk18on") ->
            after("1.")?.takeIf { it < 85 }
                ?.let { floor("1.85", "GHSA-9pwp-9qqc-pr26, GHSA-qp49-qgx5-5m26 (bcprov), GHSA-wg6q-6289-32hp (bcpkix), GHSA-cj8j-37rh-8475 (bcpg)") }
        requested.group == "org.freemarker" && requested.name == "freemarker" ->
            after("2.3.")?.takeIf { it < 35 }
                ?.let { floor("2.3.35", "GHSA-27j2-h3m2-8237: template-loading path traversal, fixed in 2.3.35") }
        // api and context share one version line and must stay aligned.
        requested.group == "io.opentelemetry" &&
            requested.name in setOf("opentelemetry-api", "opentelemetry-context") ->
            after("1.")?.takeIf { it < 67 }
                ?.let { floor("1.67.0", "GHSA-rcgg-9c38-7xpx, GHSA-ccrj-gw8r-854m: W3C baggage/tracestate parsing") }
    }
}

gradle.beforeProject {
    buildscript.configurations.configureEach { resolutionStrategy.applySecurityFloors() }
    configurations.configureEach { resolutionStrategy.applySecurityFloors() }
}
