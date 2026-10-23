package io.axiam.sdk.internal

import okhttp3.MediaType
import okhttp3.RequestBody
import okio.BufferedSink

/**
 * A request body OkHttp will not replay once it has been sent (C164-39, C164-44, C164-50).
 *
 * `retryOnConnectionFailure(false)` would also switch off OkHttp 4's fallback to the next
 * resolved address, so a host whose first address refuses would fail every attempt of a call
 * that sent nothing. A one-shot body keeps that fallback (a connect failure is not a send) and
 * refuses what must not be repeated: the silent resend after the request was written, the `408`
 * and `503` + `Retry-After: 0` follow-ups, and a `307`/`308` re-POST. §27.4 rule 8 and §34.2 P11
 * forbid resending a management write; §33.7 rule 1 a `cibaInitiate`; §16.1 counts a poll's
 * attempts (three in total) in the §16 runner alone.
 *
 * Wrap a request body in this for every request that must be sent at most once, bodiless
 * `DELETE` included (as an empty body).
 */
internal class OneShotBody(private val delegate: RequestBody) : RequestBody() {
    override fun contentType(): MediaType? = delegate.contentType()
    override fun contentLength(): Long = delegate.contentLength()
    override fun writeTo(sink: BufferedSink) = delegate.writeTo(sink)
    override fun isOneShot(): Boolean = true
}
