package com.appmap

/**
 * Builds the AppMap relationship graph:
 *
 *   Domain -> DNS -> Web service -> TLS certificate -> application metadata
 *
 * Produced as a nested map (JSON-friendly) and renderable as an ASCII tree.
 */
class GraphBuilder(
    private val hostname: String,
    private val dns: DnsResult,
    private val http: HttpResult? = null,
    private val tls: TlsResult? = null,
) {
    private fun node(name: String, type: String, children: List<Map<String, Any?>> = emptyList()) =
        linkedMapOf<String, Any?>("name" to name, "type" to type, "children" to children)

    fun build(): Map<String, Any?> {
        val children = mutableListOf<Map<String, Any?>>()

        // DNS
        val dnsChildren = mutableListOf<Map<String, Any?>>()
        for (type in DnsAnalyzer.ORDER) {
            for (value in dns.records[type] ?: emptyList()) {
                dnsChildren.add(node("$type $value", "dns_record"))
            }
        }
        if (dnsChildren.isEmpty()) dnsChildren.add(node("(no records)", "note"))
        children.add(node("DNS", "dns", dnsChildren))

        // Web service
        http?.let { h ->
            val scheme = (h.scheme ?: "http").uppercase()
            val webChildren = mutableListOf<Map<String, Any?>>()
            if (h.ok) {
                webChildren.add(node("Status ${h.statusCode} ${h.reason ?: ""}".trim(), "http_status"))
                h.contentType?.let { webChildren.add(node("Content-Type: $it", "http_meta")) }
                h.server?.let { webChildren.add(node("Server: $it", "http_meta")) }
                for ((k, v) in h.hints) {
                    if (k != "Server") webChildren.add(node("$k: $v", "http_meta"))
                }
            } else {
                webChildren.add(node("unavailable: ${h.error}", "note"))
            }
            children.add(node("$scheme service", "web_service", webChildren))
        }

        // TLS
        tls?.let { t ->
            if (t.connected || t.error != null) {
                val tlsChildren = mutableListOf<Map<String, Any?>>()
                t.tlsVersion?.let { tlsChildren.add(node(it, "tls_meta")) }
                if (t.subject.isNotEmpty()) {
                    tlsChildren.add(node("subject CN=${t.subject["commonName"] ?: "?"}", "tls_meta"))
                }
                if (t.issuer.isNotEmpty()) {
                    val org = t.issuer["organizationName"] ?: t.issuer["commonName"] ?: "?"
                    tlsChildren.add(node("issuer $org", "tls_meta"))
                }
                t.daysUntilExpiry?.let { tlsChildren.add(node("expires in $it days", "tls_meta")) }
                if (t.sans.isNotEmpty()) {
                    val shown = t.sans.take(5).joinToString(", ")
                    val suffix = if (t.sans.size > 5) " ..." else ""
                    tlsChildren.add(node("SANs (${t.sans.size}): $shown$suffix", "tls_meta"))
                }
                t.error?.let { tlsChildren.add(node(it, "note")) }
                children.add(node("TLS", "tls", tlsChildren))
            }
        }

        return linkedMapOf("name" to hostname, "type" to "domain", "children" to children)
    }

    @Suppress("UNCHECKED_CAST")
    fun renderAscii(): String {
        val sb = StringBuilder()
        fun walk(n: Map<String, Any?>, prefix: String, isLast: Boolean, isRoot: Boolean) {
            val name = n["name"].toString()
            if (isRoot) sb.append(name).append("\n")
            else sb.append(prefix).append(if (isLast) "└── " else "├── ").append(name).append("\n")
            val kids = (n["children"] as? List<Map<String, Any?>>) ?: emptyList()
            val childPrefix = if (isRoot) "" else prefix + (if (isLast) "    " else "│   ")
            kids.forEachIndexed { i, child -> walk(child, childPrefix, i == kids.size - 1, false) }
        }
        walk(build(), "", true, true)
        return sb.toString().trimEnd('\n')
    }

    @Suppress("UNCHECKED_CAST")
    fun buildNodesEdges(): Map<String, Any?> {
        val nodes = mutableListOf<Map<String, Any?>>()
        val edges = mutableListOf<Map<String, Any?>>()
        var counter = 0
        fun walk(n: Map<String, Any?>, parentId: String?) {
            val id = "n${counter++}"
            nodes.add(linkedMapOf("id" to id, "label" to n["name"], "type" to n["type"]))
            if (parentId != null) edges.add(linkedMapOf("from" to parentId, "to" to id))
            (n["children"] as? List<Map<String, Any?>>)?.forEach { walk(it, id) }
        }
        walk(build(), null)
        return linkedMapOf("nodes" to nodes, "edges" to edges)
    }
}
