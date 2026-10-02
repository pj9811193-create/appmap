package com.appmap

import java.time.Instant
import kotlin.system.exitProcess

const val VERSION = "1.0.0"

val AUTHORIZATION_NOTICE = """
AppMap - application-layer discovery (defensive use only)
=========================================================
By using AppMap you confirm you own the target or have explicit written
authorisation to test it. AppMap makes only ordinary, low-rate requests and
never attempts exploitation, brute forcing, credential attacks, or any attempt
to bypass access controls.
""".trimIndent()

/** Runs the full AppMap pipeline for one target and returns the result map. */
fun scan(
    rawTarget: String,
    timeoutMs: Long = 8000,
    doHttp: Boolean = true,
    doTls: Boolean = true,
): Map<String, Any?> {
    val parsed = Target.parse(rawTarget)
    val hostname = parsed.hostname
    val url = parsed.url

    val dns = DnsAnalyzer(timeoutMs).analyze(hostname)

    var http: HttpResult? = null
    if (doHttp) {
        http = HttpAnalyzer(timeoutMs).analyze(url)
        if (doTls) Thread.sleep(500) // gentle pacing between requests
    }

    var tls: TlsResult? = null
    if (doTls) {
        tls = TlsAnalyzer(timeoutMs).analyze(hostname, 443)
    }

    val builder = GraphBuilder(hostname, dns, http, tls)

    return linkedMapOf(
        "tool" to "AppMap",
        "version" to VERSION,
        "runtime" to "kotlin/jvm",
        "target" to hostname,
        "url" to url,
        "scanned_at" to Instant.now().toString(),
        "authorized_use_only" to true,
        "dns" to dns.asMap(),
        "http" to http?.asMap(),
        "tls" to tls?.asMap(),
        "graph" to builder.build(),
        "graph_ascii" to builder.renderAscii(),
    )
}

/** Renders the human-readable terminal report. */
fun renderTerminal(result: Map<String, Any?>): String {
    val out = StringBuilder()
    out.appendLine("AppMap")
    out.appendLine("─".repeat(40))
    out.appendLine("Target: ${result["target"]}")
    out.appendLine("URL:    ${result["url"]}")
    out.appendLine()

    @Suppress("UNCHECKED_CAST")
    val dns = result["dns"] as? Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val records = dns?.get("records") as? Map<String, List<String>> ?: emptyMap()

    out.appendLine("DNS")
    var any = false
    for (type in listOf("A", "AAAA", "MX", "NS", "CNAME", "TXT")) {
        (records[type] ?: emptyList()).forEachIndexed { i, v ->
            val label = if (i == 0) type else ""
            out.appendLine("%-6s %s".format(label, v))
            any = true
        }
    }
    if (!any) out.appendLine("(no records resolved)")
    out.appendLine()

    @Suppress("UNCHECKED_CAST")
    val http = result["http"] as? Map<String, Any?>
    if (http != null) {
        out.appendLine("HTTP/HTTPS")
        if (http["ok"] == true) {
            out.appendLine("Status: ${http["status_code"]} ${http["reason"] ?: ""}".trimEnd())
            http["final_url"]?.let { out.appendLine("Final:  $it") }
            @Suppress("UNCHECKED_CAST")
            val chain = http["redirect_chain"] as? List<Map<String, Any?>>
            if (chain != null && chain.size > 1) {
                out.appendLine("Redirects:")
                for (hop in chain) {
                    val loc = hop["location"]?.let { " -> $it" } ?: ""
                    out.appendLine("  ${hop["status_code"]} ${hop["url"]}$loc")
                }
            }
            http["content_type"]?.let { out.appendLine("Content-Type: $it") }
            http["server"]?.let { out.appendLine("Server: $it") }
            @Suppress("UNCHECKED_CAST")
            val hints = http["hints"] as? Map<String, Any?> ?: emptyMap()
            for ((k, v) in hints) if (k != "Server") out.appendLine("$k: $v")
            (http["elapsed_ms"] as? Number)?.let { out.appendLine("Response time: %.1f ms".format(it.toDouble())) }
        } else {
            out.appendLine("Unavailable: ${http["error"]}")
        }
        out.appendLine()
    }

    @Suppress("UNCHECKED_CAST")
    val tls = result["tls"] as? Map<String, Any?>
    if (tls != null) {
        out.appendLine("TLS")
        if (tls["connected"] == true) {
            out.appendLine("Version: ${tls["tls_version"] ?: "unknown"}")
            tls["cipher"]?.let { out.appendLine("Cipher:  $it") }
            @Suppress("UNCHECKED_CAST")
            val subj = tls["subject"] as? Map<String, Any?> ?: emptyMap()
            @Suppress("UNCHECKED_CAST")
            val iss = tls["issuer"] as? Map<String, Any?> ?: emptyMap()
            if (subj.isNotEmpty()) out.appendLine("Certificate: CN=${subj["commonName"] ?: "?"}")
            if (iss.isNotEmpty()) {
                out.appendLine("Issuer:      ${iss["organizationName"] ?: iss["commonName"] ?: "?"}")
            }
            tls["not_after"]?.let { na ->
                val days = tls["days_until_expiry"]?.let { " ($it days)" } ?: ""
                out.appendLine("Expires:     $na$days")
            }
            @Suppress("UNCHECKED_CAST")
            val sans = tls["sans"] as? List<String> ?: emptyList()
            if (sans.isNotEmpty()) {
                out.appendLine("SANs:        ${sans.take(8).joinToString(", ")}${if (sans.size > 8) " ..." else ""}")
            }
            if (tls["verified"] == false) {
                out.appendLine("Note:        certificate did not verify (metadata shown unverified)")
            }
            tls["error"]?.let { out.appendLine("Note:        $it") }
        } else {
            out.appendLine("Unavailable: ${tls["error"]}")
        }
        out.appendLine()
    }

    out.appendLine("APPLICATION")
    if (http != null && http["ok"] == true) {
        out.appendLine("HTTP detected")
        http["content_type"]?.let { out.appendLine("Content-Type: $it") }
    } else {
        out.appendLine("No HTTP service metadata available")
    }
    out.appendLine()
    out.appendLine("Graph:")
    out.appendLine(result["graph_ascii"]?.toString() ?: "")
    return out.toString()
}

private fun usage(): String = """
    usage: appmap [options] <hostname|url>

    Options:
      --json PATH        write full results to a JSON file
      --csv PATH         write a one-row CSV summary
      --output-dir DIR   directory for exports (default: .)
      --timeout SECONDS  per-request timeout (default: 8)
      --no-http          skip the HTTP request
      --no-tls           skip TLS inspection
      --quiet            suppress the authorisation notice
      --version          print the version
      --help             show this help

    Example: appmap example.com --json out.json
""".trimIndent()

fun main(args: Array<String>) {
    var target: String? = null
    var jsonPath: String? = null
    var csvPath: String? = null
    var outputDir = "."
    var timeoutSec = 8.0
    var doHttp = true
    var doTls = true
    var quiet = false

    var i = 0
    while (i < args.size) {
        when (val a = args[i]) {
            "--json" -> jsonPath = args.getOrNull(++i)
            "--csv" -> csvPath = args.getOrNull(++i)
            "--output-dir" -> outputDir = args.getOrNull(++i) ?: "."
            "--timeout" -> timeoutSec = args.getOrNull(++i)?.toDoubleOrNull() ?: 8.0
            "--no-http" -> doHttp = false
            "--no-tls" -> doTls = false
            "--quiet" -> quiet = true
            "--version" -> { println("AppMap $VERSION (kotlin/jvm)"); return }
            "--help", "-h" -> { println(usage()); return }
            else -> if (a.startsWith("-")) {
                System.err.println("error: unknown option '$a'")
                exitProcess(2)
            } else target = a
        }
        i++
    }

    if (target == null) {
        System.err.println(usage())
        exitProcess(2)
    }

    if (!quiet) println(AUTHORIZATION_NOTICE + "\n")

    val result = try {
        scan(target!!, timeoutMs = (timeoutSec * 1000).toLong(), doHttp = doHttp, doTls = doTls)
    } catch (e: InputError) {
        System.err.println("error: ${e.message}")
        exitProcess(2)
    } catch (e: Exception) {
        System.err.println("error: unexpected failure: ${e.javaClass.simpleName}: ${e.message}")
        exitProcess(1)
    }

    println(renderTerminal(result))

    val exporter = Exporter(outputDir)
    jsonPath?.let { println("\nJSON written to ${exporter.exportJson(result, it)}") }
    csvPath?.let { println("CSV summary written to ${exporter.exportCsvSummary(result, it)}") }
}
