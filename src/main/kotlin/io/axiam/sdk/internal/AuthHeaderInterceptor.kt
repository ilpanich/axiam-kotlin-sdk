package io.axiam.sdk.internal

import okhttp3.Interceptor
import okhttp3.Response

/**
 * Synchronous per-request header injection + CSRF capture (CONTRACT.md
 * §3/§5), registered as an OkHttp application interceptor.
 *
 * On every same-origin request it adds `X-Tenant-ID` (§5); a bearer token when
 * one is cached in the cookie jar; and echoes the stored CSRF token as
 * `X-CSRF-Token` on state-changing methods (§3). It captures a fresh
 * `X-CSRF-Token` response header for the next request. Host-isolation: a
 * request to any other host is left undecorated so these values never leak
 * off-origin.
 *
 * A request carrying [NO_SESSION_CREDENTIALS_HEADER] gets neither the bearer
 * token nor the shared jar's cookies — CONTRACT.md §24.1's
 * `setup/register/{start,finish}` pair (contract 1.45), whose only credential
 * is a setup token in the body, and which "MUST NOT attach its session
 * credential to". This interceptor only skips the `Authorization` half: it
 * runs as an **application** interceptor, which is too early to touch
 * `Cookie` — OkHttp's `BridgeInterceptor` sets `Cookie` from the shared
 * `CookieJar` *unconditionally* whenever the jar holds any for the URL,
 * overwriting anything set here, including an explicit empty value. Stripping
 * `Cookie` therefore has to happen downstream, in
 * [NoSessionCredentialsNetworkInterceptor], which runs as a **network**
 * interceptor — after `BridgeInterceptor`, immediately before the request is
 * written to the wire — and which is also where the marker header itself is
 * finally removed, so it never reaches the wire either. The **response** side
 * is untouched here — a successful `setup/register/finish` still has its
 * `Set-Cookie` triple and its `X-CSRF-Token` captured exactly as any other
 * call's would, which is what lets it adopt credentials afterward.
 *
 * The reactive 401 → single-flight refresh path lives in the coroutine layer
 * ([io.axiam.sdk.AxiamClient]), not here — an OkHttp interceptor cannot call a
 * `suspend` refresh — so this interceptor performs no refresh itself.
 */
class AuthHeaderInterceptor(private val session: SessionState) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val sameHost = session.isBaseHost(original.url.host)
        val credentialFree = original.header(NO_SESSION_CREDENTIALS_HEADER) != null

        val builder = original.newBuilder()

        if (sameHost) {
            builder.header("X-Tenant-ID", session.tenantId())
            if (!credentialFree) {
                // CONTRACT.md §6.1 rule 6: an adopted device token is a BEARER
                // credential, never a cookie, and rides ALONE — no CSRF
                // forwarding (there is no fresh one to forward; the response
                // that minted this token set no cookie to protect), and
                // STRIP_COOKIE_HEADER marks the request so
                // [NoSessionCredentialsNetworkInterceptor] removes whatever
                // the shared jar would otherwise attach downstream, after
                // OkHttp's own BridgeInterceptor has run.
                val device = session.deviceToken()
                if (device != null) {
                    builder.header("Authorization", "Bearer $device")
                    builder.header(STRIP_COOKIE_HEADER, "1")
                } else {
                    session.cachedAccessToken()?.let { builder.header("Authorization", "Bearer $it") }
                    val csrf = session.csrfToken()
                    if (csrf != null && STATE_CHANGING.contains(original.method)) {
                        builder.header("X-CSRF-Token", csrf)
                    }
                }
            }
        }

        val response = chain.proceed(builder.build())
        response.header("X-CSRF-Token")?.let { session.setCsrfToken(it) }
        return response
    }

    companion object {
        private val STATE_CHANGING = setOf("POST", "PUT", "PATCH", "DELETE")

        /**
         * Internal request marker: tells [AuthHeaderInterceptor] to withhold
         * the bearer token and tells [NoSessionCredentialsNetworkInterceptor]
         * to strip `Cookie` — never sent on the wire itself, since the latter
         * removes it before the request is written. CONTRACT.md §24.1's
         * `setup/register/{start,finish}` pair is the only caller.
         */
        internal const val NO_SESSION_CREDENTIALS_HEADER = "X-Axiam-Internal-No-Session-Credentials"

        /**
         * Internal request marker: tells [NoSessionCredentialsNetworkInterceptor]
         * to strip `Cookie` while leaving `Authorization` (the device bearer
         * token, already set above) untouched — CONTRACT.md §6.1 rule 6.
         * Distinct from [NO_SESSION_CREDENTIALS_HEADER], which strips both.
         */
        internal const val STRIP_COOKIE_HEADER = "X-Axiam-Internal-Strip-Cookie"
    }
}

/**
 * The [NO_SESSION_CREDENTIALS_HEADER][AuthHeaderInterceptor.NO_SESSION_CREDENTIALS_HEADER]
 * half that [AuthHeaderInterceptor] cannot do itself.
 *
 * Registered as an OkHttp **network** interceptor
 * (`OkHttpClient.Builder.addNetworkInterceptor`), which runs after
 * `BridgeInterceptor` has already applied the shared `CookieJar` — the one
 * point downstream of the jar and upstream of the wire, so this is where a
 * cookie the jar attached can still be removed before the request is
 * serialized. Every other request is untouched: `chain.proceed(original)`,
 * with nothing rebuilt, so no header ordering or casing changes for the
 * common case.
 */
internal class NoSessionCredentialsNetworkInterceptor : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val noSessionCredentials = original.header(AuthHeaderInterceptor.NO_SESSION_CREDENTIALS_HEADER) != null
        val stripCookieOnly = original.header(AuthHeaderInterceptor.STRIP_COOKIE_HEADER) != null
        if (!noSessionCredentials && !stripCookieOnly) {
            return chain.proceed(original)
        }
        val stripped = original.newBuilder()
            .removeHeader(AuthHeaderInterceptor.NO_SESSION_CREDENTIALS_HEADER)
            .removeHeader(AuthHeaderInterceptor.STRIP_COOKIE_HEADER)
            .removeHeader("Cookie")
            .build()
        return chain.proceed(stripped)
    }
}
