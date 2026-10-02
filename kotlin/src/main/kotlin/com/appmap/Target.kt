package com.appmap

/** Raised when the user-supplied target cannot be understood. */
class InputError(message: String) : Exception(message)

data class ParsedTarget(val hostname: String, val url: String, val scheme: String)

private val HOSTNAME_RE =
    Regex("^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\\.?$")
private val IPV4_RE = Regex("^(\\d{1,3}\\.){3}\\d{1,3}$")

/** Validates and normalises a hostname or URL, mirroring the Python CLI. */
object Target {
    fun parse(raw: String?): ParsedTarget {
        if (raw == null) throw InputError("no target supplied")
        val target = raw.trim()
        if (target.isEmpty()) throw InputError("target is empty")
        if (target.length > 2048) throw InputError("target is unreasonably long")
        if (target.any { it == ' ' || it == '\t' || it == '\n' || it == '\r' }) {
            throw InputError("target contains whitespace")
        }

        var scheme = "https"
        val hostname: String
        val url: String

        if (target.contains("://")) {
            val idx = target.indexOf("://")
            scheme = target.substring(0, idx).lowercase()
            if (scheme != "http" && scheme != "https") {
                throw InputError("unsupported scheme: '$scheme'")
            }
            val rest = target.substring(idx + 3)
            var host = rest.substringBefore('/').substringBefore('?').substringBefore('#')
            val at = host.lastIndexOf('@')
            if (at >= 0) host = host.substring(at + 1)
            if (host.count { it == ':' } == 1) host = host.substringBefore(':')
            if (host.isEmpty()) throw InputError("could not extract a hostname from the URL")
            hostname = host
            url = target
        } else {
            hostname = target.substringBefore('/')
            val path = target.substring(hostname.length)
            url = "https://$hostname$path"
        }

        if (!HOSTNAME_RE.matches(hostname) && !IPV4_RE.matches(hostname)) {
            throw InputError("invalid hostname: '$hostname'")
        }
        if (IPV4_RE.matches(hostname)) {
            for (octet in hostname.split('.')) {
                if (octet.toInt() > 255) throw InputError("invalid IPv4 address: '$hostname'")
            }
        }
        return ParsedTarget(hostname.trimEnd('.'), url, scheme)
    }
}
