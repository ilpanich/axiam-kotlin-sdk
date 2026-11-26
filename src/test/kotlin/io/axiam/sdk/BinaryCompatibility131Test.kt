package io.axiam.sdk

import io.axiam.sdk.ktor.axiamOidcLogin
import io.axiam.sdk.oidc.MemoryOidcStateStore
import io.axiam.sdk.oidc.OidcStateEntry
import io.axiam.sdk.oidc.OidcStateStore
import io.ktor.server.routing.Route
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

/**
 * KOT-R1-3: the public constructors and the login-glue function keep their
 * 1.3.1 JVM signatures, so a jar compiled against 1.3.x still links (the
 * failure otherwise is a `NoSuchMethodError` at the first call).
 */
class BinaryCompatibility131Test {

    @Test
    fun `AxiamUser keeps the three-argument constructor`() {
        val ctor = AxiamUser::class.java.getConstructor(String::class.java, String::class.java, List::class.java)
        val user = ctor.newInstance("u", "t", listOf("r")) as AxiamUser
        assertEquals(emptyList<String>(), user.scopes)
        assertEquals(true, user.rolesClaimPresent)
    }

    @Test
    fun `OidcStateEntry keeps the five-argument constructor`() {
        val ctor = OidcStateEntry::class.java.getConstructor(
            String::class.java, String::class.java, Sensitive::class.java, String::class.java, String::class.java,
        )
        val entry = ctor.newInstance("s", "n", Sensitive.of("v"), "https://a/cb", null) as OidcStateEntry
        assertEquals(null, entry.bindingDigest)
    }

    @Test
    fun `MemoryOidcStateStore keeps the one-argument long constructor`() {
        val store = MemoryOidcStateStore::class.java.getConstructor(Long::class.javaPrimitiveType).newInstance(1_000L)
        assertNotNull(store)
    }

    @Test
    fun `axiamOidcLogin keeps its 1-3-1 JVM signature`() {
        val method = Class.forName("io.axiam.sdk.ktor.AxiamOidcLoginKt").getMethod(
            "axiamOidcLogin",
            Route::class.java, AxiamClient::class.java, String::class.java, OidcStateStore::class.java,
            String::class.java, String::class.java, String::class.java, String::class.java,
            kotlin.jvm.functions.Function3::class.java,
        )
        assertNotNull(method)
    }
}
