"""Tests for the TLS analyzer helpers and metadata population."""
import ssl
from datetime import timezone

from tls_analyzer import TLSAnalyzer, TLSResult, _flatten_name, _parse_cert_time


def test_flatten_name():
    parts = ((("commonName", "example.com"),), (("organizationName", "Example Inc"),))
    flat = _flatten_name(parts)
    assert flat["commonName"] == "example.com"
    assert flat["organizationName"] == "Example Inc"


def test_flatten_name_empty():
    assert _flatten_name(None) == {}
    assert _flatten_name(()) == {}


def test_parse_cert_time():
    dt = _parse_cert_time("Jan  1 00:00:00 2027 GMT")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2027


def test_parse_cert_time_invalid():
    assert _parse_cert_time("not a date") is None
    assert _parse_cert_time(None) is None


class FakeSSLSocket:
    """Mimics the parts of ssl.SSLSocket that _populate reads."""

    def __init__(self):
        self._cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Example CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "serialNumber": "ABCDEF",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

    def version(self):
        return ssl.TLSVersion.TLSv1_3

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def getpeercert(self):
        return self._cert


def test_populate_reads_certificate():
    result = TLSResult(hostname="example.com")
    TLSAnalyzer._populate(result, FakeSSLSocket())
    assert result.tls_version == "TLS 1.3"
    assert result.cipher == "TLS_AES_128_GCM_SHA256"
    assert result.subject["commonName"] == "example.com"
    assert result.issuer["organizationName"] == "Example CA"
    assert result.sans == ["example.com", "www.example.com"]
    assert result.serial_number == "ABCDEF"
    assert result.expired is False
    assert result.days_until_expiry is not None


def test_analyze_handles_unreachable_host():
    # 127.0.0.1:1 should refuse immediately, exercising the error path offline.
    result = TLSAnalyzer(timeout=1.0).analyze("127.0.0.1", port=1)
    assert result.connected is False
    assert result.error is not None
