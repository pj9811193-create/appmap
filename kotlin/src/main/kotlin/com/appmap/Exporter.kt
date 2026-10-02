package com.appmap

import java.io.File
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Writes AppMap results to JSON and a one-row CSV summary. */
class Exporter(private val outputDir: String = ".") {

    private fun ensureDir() {
        if (outputDir.isNotEmpty()) File(outputDir).mkdirs()
    }

    private fun stamp(): String =
        DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC)
            .format(java.time.Instant.now())

    fun exportJson(result: Map<String, Any?>, path: String? = null): String {
        ensureDir()
        val safeHost = (result["target"] as? String ?: "target")
            .replace("/", "_").replace(":", "_")
        val target = path ?: "$outputDir/appmap_${safeHost}_${stamp()}.json"
        File(target).writeText(Json.write(result))
        return target
    }

    fun exportCsvSummary(result: Map<String, Any?>, path: String? = null): String {
        ensureDir()
        val target = path ?: "$outputDir/appmap_summary_${stamp()}.csv"

        @Suppress("UNCHECKED_CAST")
        val dns = (result["dns"] as? Map<String, Any?>)
        @Suppress("UNCHECKED_CAST")
        val dnsRecords = dns?.get("records") as? Map<String, List<String>> ?: emptyMap()
        @Suppress("UNCHECKED_CAST")
        val http = result["http"] as? Map<String, Any?> ?: emptyMap()
        @Suppress("UNCHECKED_CAST")
        val tls = result["tls"] as? Map<String, Any?> ?: emptyMap()
        @Suppress("UNCHECKED_CAST")
        val issuer = tls["issuer"] as? Map<String, Any?> ?: emptyMap()

        val row = linkedMapOf(
            "target" to (result["target"] ?: ""),
            "scanned_at" to (result["scanned_at"] ?: ""),
            "a_records" to (dnsRecords["A"] ?: emptyList<String>()).joinToString(";"),
            "status_code" to (http["status_code"] ?: ""),
            "final_url" to (http["final_url"] ?: ""),
            "content_type" to (http["content_type"] ?: ""),
            "server" to (http["server"] ?: ""),
            "tls_version" to (tls["tls_version"] ?: ""),
            "cert_issuer" to (issuer["organizationName"] ?: ""),
            "cert_expires" to (tls["not_after"] ?: ""),
            "days_until_expiry" to (tls["days_until_expiry"] ?: ""),
        )

        val header = row.keys.joinToString(",")
        val values = row.values.joinToString(",") { csv(it) }
        File(target).writeText("$header\n$values\n")
        return target
    }

    private fun csv(v: Any?): String {
        val s = v?.toString() ?: ""
        return if (s.contains(',') || s.contains('"') || s.contains('\n')) {
            "\"" + s.replace("\"", "\"\"") + "\""
        } else s
    }
}
