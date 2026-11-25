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
// security updates fail with `dependency_not_found`. Neither reaches the
// published POM — jackson-core/-databind come in through the Dokka plugin and
// its generator classpaths, the Netty HTTP codecs through ktor-server-netty in
// the compile-checked `examples` source set — but both sit in the dependency
// graph GitHub scans, and the examples really run a Netty server.
//
//  - jackson-core / jackson-databind 2.22.0–2.22.2: GHSA-7hhh-6rmp-j9qf,
//    GHSA-p6pp-m3f8-5c89, GHSA-cxp5-3px4-pw24, GHSA-wv8q-qhhj-9h54 (fixed in 2.22.3).
//  - io.netty 4.2.x before 4.2.21.Final: ktor-server-netty 3.3.3 asks for 4.2.7,
//    whose netty-codec-http/-http2 carry the request-smuggling and HTTP/2 DoS
//    advisories fixed up to 4.2.17. Every io.netty 4.2 module is aligned, not just
//    the codecs: amqp-client already brings netty-common 4.2.21, and mixing 4.2.7
//    native transports with a 4.2.21 core is its own runtime hazard.
//
// Floors, not pins: a newer request passes through untouched. Drop an entry when
// the upstream that pulls it (Dokka, Ktor) ships the patched version itself.
fun ResolutionStrategy.applySecurityFloors() = eachDependency {
    val version = requested.version ?: return@eachDependency
    fun patchOf(prefix: String): Int? =
        version.removePrefix(prefix).takeIf { version.startsWith(prefix) }
            ?.substringBefore('.')?.toIntOrNull()
    when {
        requested.group == "com.fasterxml.jackson.core" &&
            requested.name in setOf("jackson-core", "jackson-databind") ->
            patchOf("2.22.")?.takeIf { it < 3 }?.let {
                useVersion("2.22.3")
                because("GHSA-7hhh-6rmp-j9qf et al.: fixed in jackson 2.22.3")
            }
        requested.group == "io.netty" ->
            patchOf("4.2.")?.takeIf { it < 21 }?.let {
                useVersion("4.2.21.Final")
                because("netty-codec-http/-http2 advisories: align Netty 4.2 at 4.2.21.Final")
            }
    }
}

gradle.beforeProject {
    buildscript.configurations.configureEach { resolutionStrategy.applySecurityFloors() }
    configurations.configureEach { resolutionStrategy.applySecurityFloors() }
}
