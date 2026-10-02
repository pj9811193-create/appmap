package com.appmap

import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import javax.naming.ldap.LdapName
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class TlsResult(
    val hostname: String,
    val port: Int = 443,
    var connected: Boolean = false,
    var tlsVersion: String? = null,
    var cipher: String? = null,
    var subject: Map<String, String> = emptyMap(),
    var issuer: Map<String, String> = emptyMap(),
    var notBefore: String? = null,
    var notAfter: String? = null,
    var daysUntilExpiry: Long? = null,
    var expired: Boolean? = null,
    var sans: List<String> = emptyList(),
    var serialNumber: String? = null,
    var verified: Boolean? = null,
    var error: String? = null,
) {
    fun asMap(): Map<String, Any?> = linkedMapOf(
        "hostname" to hostname,
        "port" to port,
        "connected" to connected,
        "tls_version" to tlsVersion,
        "cipher" to cipher,
        "subject" to subject,
        "issuer" to issuer,
        "not_before" to notBefore,
        "not_after" to notAfter,
        "days_until_expiry" to daysUntilExpiry,
        "expired" to expired,
        "sans" to sans,
        "serial_number" to serialNumber,
        "verified" to verified,
        "error" to error,
    )
}

/**
 * Performs a normal TLS handshake and reads the negotiated protocol version and
 * the peer certificate. A verified handshake is attempted first; if that fails
 * we record what the server presented, unverified, purely as metadata.
 */
class TlsAnalyzer(private val timeoutMs: Long = 8000) {
    private val fmt = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy 'GMT'").withZone(ZoneOffset.UTC)

    fun analyze(hostname: String, port: Int = 443): TlsResult {
        val result = TlsResult(hostname, port)

        try {
            handshake(hostname, port, verified = true, result = result)
            result.verified = true
            result.connected = true
            return result
        } catch (e: Exception) {
            result.verified = false
            result.error = "certificate verification failed: ${e.message}"
        }

        // best-effort unverified pass
        try {
            handshake(hostname, port, verified = false, result = result)
            result.connected = true
        } catch (e: Exception) {
            if (result.error == null) result.error = "${e.javaClass.simpleName}: ${e.message}"
        }
        return result
    }

    private fun handshake(hostname: String, port: Int, verified: Boolean, result: TlsResult) {
        val factory: SSLSocketFactory = if (verified) {
            SSLContext.getDefault().socketFactory
        } else {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, java.security.SecureRandom())
            ctx.socketFactory
        }

        val socket = factory.createSocket() as SSLSocket
        socket.use {
            socket.connect(InetSocketAddress(hostname, port), timeoutMs.toInt())
            socket.soTimeout = timeoutMs.toInt()
            val params = socket.sslParameters
            params.serverNames = listOf(SNIHostName(hostname))
            if (verified) params.endpointIdentificationAlgorithm = "HTTPS"
            socket.sslParameters = params
            socket.startHandshake()
            populate(result, socket)
        }
    }

    private fun populate(result: TlsResult, socket: SSLSocket) {
        val session = socket.session
        result.tlsVersion = friendlyVersion(session.protocol)
        result.cipher = session.cipherSuite

        val cert = session.peerCertificates.firstOrNull() as? X509Certificate ?: return
        result.subject = nameMap(cert.subjectX500Principal.name)
        result.issuer = nameMap(cert.issuerX500Principal.name)
        result.serialNumber = cert.serialNumber.toString(16).uppercase()

        val nb = cert.notBefore.toInstant()
        val na = cert.notAfter.toInstant()
        result.notBefore = fmt.format(nb)
        result.notAfter = fmt.format(na)
        result.daysUntilExpiry = TimeUnit.MILLISECONDS.toDays(na.toEpochMilli() - Instant.now().toEpochMilli())
        result.expired = na.isBefore(Instant.now())

        result.sans = cert.subjectAlternativeNames
            ?.filter { it.size >= 2 && (it[0] as? Int) == 2 }
            ?.mapNotNull { it[1]?.toString() }
            ?: emptyList()
    }

    private fun friendlyVersion(protocol: String): String = when (protocol) {
        "TLSv1.3" -> "TLS 1.3"
        "TLSv1.2" -> "TLS 1.2"
        "TLSv1.1" -> "TLS 1.1"
        "TLSv1" -> "TLS 1.0"
        else -> protocol
    }

    private fun nameMap(dn: String): Map<String, String> {
        val out = linkedMapOf<String, String>()
        try {
            for (rdn in LdapName(dn).rdns) {
                when (rdn.type.lowercase()) {
                    "cn" -> out["commonName"] = rdn.value.toString()
                    "o" -> out["organizationName"] = rdn.value.toString()
                    "ou" -> out["organizationalUnitName"] = rdn.value.toString()
                    "c" -> out["countryName"] = rdn.value.toString()
                }
            }
        } catch (_: Exception) {
            out["name"] = dn
        }
        return out
    }
}
