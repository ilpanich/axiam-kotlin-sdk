package io.axiam.sdk.internal

import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.OkHttpClient

/**
 * A transport that carries none of the SDK's session.
 *
 * Some calls present a bearer of their own that is NOT the SDK's session — an
 * RFC 7592 registration access token (CONTRACT.md §28.12.2 rule 3), an SSF
 * receiver's client-credentials token (§32.7) — and must go out with nothing
 * else: no session cookie, no SDK access token, no CSRF header, no §9 refresh
 * on a `401`, and no redirect that could carry the bearer to another host.
 *
 * Derived from the client's own [OkHttpClient] via [OkHttpClient.newBuilder],
 * so the §6 TLS policy (system trust store, optional custom CA, the §6.1
 * identity), the timeouts and the connection pool are the same; only the
 * session-carrying parts are dropped:
 *
 *  - every application and network interceptor — [AuthHeaderInterceptor] is
 *    what attaches the access token, the CSRF token and `X-Tenant-ID`;
 *  - the cookie jar ([CookieJar.NO_COOKIES]);
 *  - any `401` [Authenticator];
 *  - redirect following, for both schemes;
 *
 * OkHttp's own retry on a connection failure is OFF: every retry of a sessionless call is §16's,
 * where it is counted and reported, and OkHttp 5 no longer replays the idempotent RFC 7592 read
 * on top of it (C164-55 — with the flag on, OkHttp 5 recovers that `GET` more than once). On OkHttp 5
 * the flag no longer gates the fallback to the next resolved address — fast fallback races the
 * routes while connecting, before anything is sent — so C164-50's dual-stack delivery holds with it
 * off. The writes keep their [OneShotBody]s regardless, so they stay at most once even if a caller's
 * client turns OkHttp's retry back on elsewhere.
 *
 * Internal plumbing: module-visible only.
 */
internal object Sessionless {

    /**
     * Derives the session-free transport from [client].
     *
     * @param client the client's decorated transport
     * @return a transport with the same TLS configuration and none of the session
     */
    fun of(client: OkHttpClient): OkHttpClient {
        val builder = client.newBuilder()
        builder.interceptors().clear()
        builder.networkInterceptors().clear()
        return builder
            .cookieJar(CookieJar.NO_COOKIES)
            .authenticator(Authenticator.NONE)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()
    }
}
