package io.axiam.sdk

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
 *
 * The rule exists because the two refusals mean **opposite things to the
 * person on the other end**: `no_grant` says *ask an admin for access*,
 * `denied_by_rule` says *an admin has already decided*. An application that
 * cannot tell them apart sends users to raise tickets that will be refused.
 */
class ReasonCodeTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() = server.shutdown()

    private suspend fun check(body: String): AccessResult {
        server.enqueue(TestSupport.json(200, body))
        return TestSupport.clientFor(server).use { it.checkAccess("read", "r-1") }
    }

    @Test
    fun `an allow surfaces the allowed reason code`() = runBlocking {
        val result = check("""{"allowed":true,"reason_code":"allowed"}""")
        assertTrue(result.allowed)
        assertEquals(ReasonCode.ALLOWED, result.reasonCode)
    }

    @Test
    fun `no_grant and denied_by_rule are not collapsed`() = runBlocking {
        val noGrant = check("""{"allowed":false,"reason_code":"no_grant"}""")
        val byRule = check("""{"allowed":false,"reason_code":"denied_by_rule"}""")

        // Both are refusals…
        assertFalse(noGrant.allowed)
        assertFalse(byRule.allowed)
        // …and the SDK must not reduce them to that shared false.
        assertEquals(ReasonCode.NO_GRANT, noGrant.reasonCode)
        assertEquals(ReasonCode.DENIED_BY_RULE, byRule.reasonCode)
        assertNotEquals(noGrant.reasonCode, byRule.reasonCode)
    }

    @Test
    fun `an unknown reason code is surfaced verbatim and changes nothing`() = runBlocking {
        // §11 rule 9: an SDK that does not recognise a code MUST surface it
        // unchanged and MUST NOT let it affect the outcome, which `allowed`
        // carries alone. This is what lets the server add a fourth code without
        // breaking every deployed SDK.
        val denied = check("""{"allowed":false,"reason_code":"denied_by_some_future_thing"}""")
        assertFalse(denied.allowed)
        assertEquals("denied_by_some_future_thing", denied.reasonCode)

        val allowed = check("""{"allowed":true,"reason_code":"something-unrecognised"}""")
        assertTrue(allowed.allowed, "an unknown code must not flip an allow")
    }

    @Test
    fun `an older server omitting the field is not an error`() = runBlocking {
        // A newer SDK against an older server: the field is simply absent, and
        // that MUST degrade to today's behaviour rather than failing to parse.
        val denied = check("""{"allowed":false}""")
        assertFalse(denied.allowed)
        assertNull(denied.reasonCode)

        val allowed = check("""{"allowed":true,"reason":"role grants it"}""")
        assertTrue(allowed.allowed)
        assertNull(allowed.reasonCode)
        assertEquals("role grants it", allowed.reason)
    }

    @Test
    fun `batchCheck surfaces a reason code per decision`() = runBlocking {
        server.enqueue(
            TestSupport.json(
                200,
                """{"results":[
                    {"allowed":true,"reason_code":"allowed"},
                    {"allowed":false,"reason_code":"no_grant"},
                    {"allowed":false,"reason_code":"denied_by_rule"}
                ]}""",
            ),
        )

        val results = TestSupport.clientFor(server).use { client ->
            client.batchCheck(
                listOf(
                    AccessCheck("read", "r-1"),
                    AccessCheck("write", "r-1"),
                    AccessCheck("delete", "r-1"),
                ),
            )
        }

        assertEquals(
            listOf(ReasonCode.ALLOWED, ReasonCode.NO_GRANT, ReasonCode.DENIED_BY_RULE),
            results.map { it.reasonCode },
        )
    }
}
