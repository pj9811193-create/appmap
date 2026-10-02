package com.appmap

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.time.Duration
import javax.net.ssl.SSLException

data class RedirectHop(val statusCode: Int, val url: String, val location: String?)

data class HttpResult(
    val requestedUrl: String,
    var finalUrl: String? = null,
    var scheme: String? = null,
    var statusCode: Int? = null,
    var reason: String? = null,
    var redirectChain: MutableList<RedirectHop> = mutableListOf(),
    var headers: Map<String, String> = emptyMap(),
    var contentType: String? = null,
    var server: String? = null,
    var hints: Map<String, String> = emptyMap(),
    var tlsUsed: Boolean = false,
    var elapsedMs: Double? = null,
    var error: String? = null,
    var ok: Boolean = false,
) {
    fun asMap(): Map<String, Any?> = linkedMapOf(
        "requested_url" to requestedUrl,
        "final_url" to finalUrl,
        "scheme" to scheme,
        "status_code" to statusCode,
        "reason" to reason,
        "redirect_chain" to redirectChain.map {
            linkedMapOf("status_code" to it.statusCode, "url" to it.url, "location" to it.location)
        },
        "headers" to headers,
        "content_type" to contentType,
        "server" to server,
        "hints" to hints,
        "tls_used" to tlsUsed,
        "elapsed_ms" to elapsedMs,
        "error" to error,
        "ok" to ok,
    )
}

/**
 * Makes one ordinary GET request per target (following redirects manually so the
 * chain can be recorded), reading metadata only - the body is discarded.
 */
class HttpAnalyzer(private val timeoutMs: Long = 8000) {
    companion object {
        const val USER_AGENT = "AppMap/1.0 (+defensive metadata inspection)"
        const val MAX_HOPS = 10
        val HINT_HEADERS = listOf(
            "Server", "Via", "X-Powered-By", "X-AspNet-Version", "X-Generator",
            "X-Drupal-Cache", "X-Backend-Server", "X-Served-By", "X-Cache",
            "CF-Ray", "X-Varnish",
        )
    }

    fun analyze(url: String): HttpResult {
        val result = HttpResult(requestedUrl = url)
        val client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofMillis(timeoutMs))
            .build()

        val start = System.nanoTime()
        try {
            var current = url
            var hops = 0
            while (true) {
                val request = HttpRequest.newBuilder(URI.create(current))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("User-Agent", USER_AGENT)
                    .header("Accept", "*/*")
                    .GET()
                    .build()

                val response = client.send(request, HttpResponse.BodyHandlers.discarding())
                val status = response.statusCode()
                val location = response.headers().firstValue("Location").orElse(null)
                result.redirectChain.add(RedirectHop(status, current, location))

                if (status in 300..399 && location != null && hops < MAX_HOPS) {
                    current = URI.create(current).resolve(location).toString()
                    hops++
                    continue
                }

                result.finalUrl = current
                result.scheme = runCatching { URI.create(current).scheme }.getOrNull()
                result.statusCode = status
                result.reason = reasonPhrase(status)
                result.headers = response.headers().map().entries
                    .associate { it.key to it.value.joinToString(", ") }
                result.contentType = response.headers().firstValue("Content-Type").orElse(null)
                result.server = response.headers().firstValue("Server").orElse(null)
                result.hints = HINT_HEADERS
                    .filter { response.headers().firstValue(it).isPresent }
                    .associateWith { response.headers().firstValue(it).get() }
                result.tlsUsed = result.scheme == "https"
                result.elapsedMs = (System.nanoTime() - start) / 1_000_000.0
                result.ok = true
                break
            }
        } catch (e: Exception) {
            result.error = describe(e)
        }
        return result
    }

    private fun describe(e: Exception): String {
        var cause: Throwable? = e
        while (cause != null) {
            when (cause) {
                is SSLException -> return "TLS/SSL error: ${cause.message}"
                is HttpTimeoutException -> return "request timed out"
                is java.net.ConnectException -> return "connection error: ${cause.message}"
                is java.net.UnknownHostException -> return "DNS resolution failed: ${cause.message}"
                is IllegalArgumentException -> return "invalid URL: ${cause.message}"
                else -> {}
            }
            cause = cause.cause
        }
        return "${e.javaClass.simpleName}: ${e.message}"
    }

    private fun reasonPhrase(code: Int): String = when (code) {
        200 -> "OK"; 201 -> "Created"; 202 -> "Accepted"; 204 -> "No Content"
        301 -> "Moved Permanently"; 302 -> "Found"; 303 -> "See Other"
        304 -> "Not Modified"; 307 -> "Temporary Redirect"; 308 -> "Permanent Redirect"
        400 -> "Bad Request"; 401 -> "Unauthorized"; 403 -> "Forbidden"
        404 -> "Not Found"; 405 -> "Method Not Allowed"; 429 -> "Too Many Requests"
        500 -> "Internal Server Error"; 502 -> "Bad Gateway"
        503 -> "Service Unavailable"; 504 -> "Gateway Timeout"
        else -> ""
    }
}
