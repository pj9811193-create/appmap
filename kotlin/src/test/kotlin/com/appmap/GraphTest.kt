package com.appmap

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GraphTest {
    private fun dns(): DnsResult {
        val d = DnsResult("example.com")
        d.records["A"] = mutableListOf("93.184.216.34")
        d.records["NS"] = mutableListOf("ns1.example.com")
        return d
    }

    private fun http(): HttpResult {
        val h = HttpResult("https://example.com")
        h.ok = true
        h.finalUrl = "https://example.com/"
        h.scheme = "https"
        h.statusCode = 200
        h.reason = "OK"
        h.contentType = "text/html"
        h.server = "nginx"
        h.hints = mapOf("X-Powered-By" to "Express")
        return h
    }

    private fun tls(): TlsResult {
        val t = TlsResult("example.com")
        t.connected = true
        t.tlsVersion = "TLS 1.3"
        t.subject = mapOf("commonName" to "example.com")
        t.issuer = mapOf("organizationName" to "Example CA")
        t.daysUntilExpiry = 100
        t.sans = listOf("example.com", "www.example.com")
        return t
    }

    @Test fun buildsTopLevelSections() {
        val tree = GraphBuilder("example.com", dns(), http(), tls()).build()
        @Suppress("UNCHECKED_CAST")
        val names = (tree["children"] as List<Map<String, Any?>>).map { it["name"] }
        assertTrue(names.contains("DNS"))
        assertTrue(names.contains("HTTPS service"))
        assertTrue(names.contains("TLS"))
    }

    @Test fun asciiContainsNodes() {
        val ascii = GraphBuilder("example.com", dns(), http(), tls()).renderAscii()
        assertTrue(ascii.contains("example.com"))
        assertTrue(ascii.contains("TLS 1.3"))
        assertTrue(ascii.contains("A 93.184.216.34"))
    }

    @Test fun nodesEdgesFormTree() {
        val view = GraphBuilder("example.com", dns(), http(), tls()).buildNodesEdges()
        @Suppress("UNCHECKED_CAST")
        val nodes = view["nodes"] as List<*>
        @Suppress("UNCHECKED_CAST")
        val edges = view["edges"] as List<*>
        assertEquals(nodes.size, edges.size + 1)
    }

    @Test fun handlesDnsOnly() {
        val tree = GraphBuilder("example.com", dns()).build()
        @Suppress("UNCHECKED_CAST")
        val names = (tree["children"] as List<Map<String, Any?>>).map { it["name"] }
        assertEquals(listOf("DNS"), names)
    }
}
