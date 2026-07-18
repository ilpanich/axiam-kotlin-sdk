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
 * The reactive 401 → single-flight refresh path lives in the coroutine layer
 * ([io.axiam.sdk.AxiamClient]), not here — an OkHttp interceptor cannot call a
 * `suspend` refresh — so this interceptor performs no refresh itself.
 */
class AuthHeaderInterceptor(private val session: SessionState) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val sameHost = session.isBaseHost(original.url.host)

        val builder = original.newBuilder()
        if (sameHost) {
            builder.header("X-Tenant-ID", session.tenantId())
            session.cachedAccessToken()?.let { builder.header("Authorization", "Bearer $it") }
            val csrf = session.csrfToken()
            if (csrf != null && STATE_CHANGING.contains(original.method)) {
                builder.header("X-CSRF-Token", csrf)
            }
        }

        val response = chain.proceed(builder.build())
        response.header("X-CSRF-Token")?.let { session.setCsrfToken(it) }
        return response
    }

    companion object {
        private val STATE_CHANGING = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
