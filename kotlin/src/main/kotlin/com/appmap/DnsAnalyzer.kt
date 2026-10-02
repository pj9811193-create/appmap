package com.appmap

import java.util.Hashtable
import javax.naming.directory.InitialDirContext

data class DnsResult(
    val hostname: String,
    val records: MutableMap<String, MutableList<String>> = linkedMapOf(),
    val errors: MutableList<String> = mutableListOf(),
    val resolver: String = "jndi",
) {
    fun asMap(): Map<String, Any?> = linkedMapOf(
        "hostname" to hostname,
        "resolver" to resolver,
        "records" to records,
        "errors" to errors,
    )
}

/**
 * Gathers A, AAAA, MX, NS, CNAME and TXT records using the JDK's built-in JNDI
 * DNS provider - no third-party dependency, and only ordinary recursive lookups.
 */
class DnsAnalyzer(private val timeoutMs: Long = 5000) {
    companion object {
        val ORDER = listOf("A", "AAAA", "MX", "NS", "CNAME", "TXT")
    }

    fun analyze(hostname: String, types: List<String> = ORDER): DnsResult {
        val result = DnsResult(hostname)
        val env = Hashtable<String, String>()
        env["java.naming.factory.initial"] = "com.sun.jndi.dns.DnsContextFactory"
        env["com.sun.jndi.dns.timeout.initial"] = timeoutMs.toString()
        env["com.sun.jndi.dns.timeout.retries"] = "1"

        val ctx = try {
            InitialDirContext(env)
        } catch (e: Exception) {
            for (t in types) result.records[t] = mutableListOf()
            result.errors.add("resolver init failed: ${e.message}")
            return result
        }

        for (type in types) {
            val list = mutableListOf<String>()
            try {
                val attrs = ctx.getAttributes(hostname, arrayOf(type))
                val attr = attrs.get(type)
                if (attr != null) {
                    val e = attr.all
                    while (e.hasMore()) {
                        val raw = e.next().toString()
                        val value = clean(type, raw)
                        if (value.isNotEmpty()) list.add(value)
                    }
                }
            } catch (e: Exception) {
                result.errors.add("$type: ${e.message}")
            }
            result.records[type] = list
        }
        return result
    }

    private fun clean(type: String, value: String): String = when (type) {
        "TXT" -> value.trim('"')
        "MX" -> {
            val parts = value.trim().split(Regex("\\s+"))
            if (parts.size == 2) "${parts[0]} ${parts[1].trimEnd('.')}" else value.trimEnd('.')
        }
        "NS", "CNAME" -> value.trimEnd('.')
        else -> value
    }
}
