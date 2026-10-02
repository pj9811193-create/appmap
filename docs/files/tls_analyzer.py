"""tls_analyzer.py - read-only TLS metadata inspection.

Opens a normal TLS connection (the same handshake a browser performs) and reads
the negotiated protocol version and the peer certificate. It performs no
manipulation of the connection and never attempts to downgrade or attack it.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

# Map ssl protocol constants to friendly names where possible.
_TLS_VERSION_NAMES = {
    getattr(ssl.TLSVersion, "TLSv1", None): "TLS 1.0",
    getattr(ssl.TLSVersion, "TLSv1_1", None): "TLS 1.1",
    getattr(ssl.TLSVersion, "TLSv1_2", None): "TLS 1.2",
    getattr(ssl.TLSVersion, "TLSv1_3", None): "TLS 1.3",
}


@dataclass
class TLSResult:
    hostname: str
    port: int = 443
    connected: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    expired: Optional[bool] = None
    sans: List[str] = field(default_factory=list)
    serial_number: Optional[str] = None
    verified: Optional[bool] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "connected": self.connected,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_until_expiry": self.days_until_expiry,
            "expired": self.expired,
            "sans": self.sans,
            "serial_number": self.serial_number,
            "verified": self.verified,
            "error": self.error,
        }


def _flatten_name(parts) -> dict:
    """Turn the tuple-of-tuples returned by getpeercert into a flat dict."""
    out = {}
    for rdn in parts or ():
        for key, value in rdn:
            out[key] = value
    return out


def _parse_cert_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # Python returns e.g. 'Oct  2 12:00:00 2026 GMT'
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


class TLSAnalyzer:
    """Performs a standard TLS handshake and reads the negotiated metadata."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze(self, hostname: str, port: int = 443) -> TLSResult:
        result = TLSResult(hostname=hostname, port=port)

        # Verified context first (the honest, browser-like default).
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    self._populate(result, tls)
                    result.verified = True
                    result.connected = True
            return result
        except ssl.SSLCertVerificationError as exc:
            # Certificate could not be verified. We still record what the
            # server presented, without validating it, purely as metadata.
            result.verified = False
            result.error = f"certificate verification failed: {exc.verify_message if hasattr(exc, 'verify_message') else exc}"
        except ssl.SSLError as exc:
            result.error = f"TLS error: {exc}"
        except socket.timeout:
            result.error = "TLS connection timed out"
        except ConnectionRefusedError:
            result.error = "connection refused"
        except socket.gaierror as exc:
            result.error = f"DNS resolution failed: {exc}"
        except OSError as exc:
            result.error = f"{type(exc).__name__}: {exc}"

        # Second, best-effort unverified pass to capture the presented cert.
        try:
            unverified = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with unverified.wrap_socket(sock, server_hostname=hostname) as tls:
                    self._populate(result, tls)
                    result.connected = True
        except Exception:
            pass
        return result

    @staticmethod
    def _populate(result: TLSResult, tls: ssl.SSLSocket) -> None:
        result.tls_version = _TLS_VERSION_NAMES.get(tls.version(), tls.version())
        try:
            result.cipher = tls.cipher()[0] if tls.cipher() else None
        except Exception:
            result.cipher = None

        cert = tls.getpeercert()
        if not cert:
            return
        result.subject = _flatten_name(cert.get("subject"))
        result.issuer = _flatten_name(cert.get("issuer"))
        result.serial_number = cert.get("serialNumber")
        result.sans = [value for typ, value in cert.get("subjectAltName", ()) if typ == "DNS"]

        result.not_before = cert.get("notBefore")
        result.not_after = cert.get("notAfter")
        nb = _parse_cert_time(result.not_before)
        na = _parse_cert_time(result.not_after)
        now = datetime.now(timezone.utc)
        if na:
            result.days_until_expiry = (na - now).days
            result.expired = na < now
