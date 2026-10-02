"""dns_analyzer.py - safe, read-only DNS lookups for AppMap.

Only ordinary recursive DNS queries (A, AAAA, MX, NS, CNAME, TXT) are issued.
If the third-party ``dnspython`` package is available it is used; otherwise a
small, self-contained standard-library resolver is used so AppMap keeps working
with no external dependencies.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # optional dependency
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore

    _HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover - exercised only when dnspython is absent
    _HAVE_DNSPYTHON = False


# Record type -> numeric code, for the built-in resolver.
_RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}

# Query order used for the CLI / graph.
RECORD_ORDER = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]


class DNSLookupError(Exception):
    """Raised when a DNS lookup cannot be completed (non-fatal to AppMap)."""


@dataclass
class DNSResult:
    """Container for all DNS records gathered for a single hostname."""

    hostname: str
    records: Dict[str, List[str]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    resolver: str = ""

    def has_records(self) -> bool:
        return any(self.records.values())

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "resolver": self.resolver,
            "records": self.records,
            "errors": self.errors,
        }


# --------------------------------------------------------------------------- #
# Built-in, dependency-free resolver
# --------------------------------------------------------------------------- #
class _MiniResolver:
    """A minimal UDP DNS client built on the standard library only.

    It supports the record types AppMap needs and honours name compression in
    responses. It is deliberately simple: one query per type, one retry, and a
    short timeout. No recursion beyond the resolver is attempted.
    """

    def __init__(self, nameserver: Optional[str] = None, timeout: float = 5.0):
        self.timeout = timeout
        self.nameserver = nameserver or self._system_nameserver()

    @staticmethod
    def _system_nameserver() -> str:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except OSError:
            pass
        return "8.8.8.8"

    @staticmethod
    def _encode_name(name: str) -> bytes:
        out = b""
        for label in name.rstrip(".").split("."):
            encoded = label.encode("idna") if label else b""
            out += struct.pack("!B", len(encoded)) + encoded
        return out + b"\x00"

    @staticmethod
    def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
        labels: List[str] = []
        jumped = False
        next_offset = offset
        safety = 0
        while True:
            safety += 1
            if safety > 128:
                raise DNSLookupError("malformed DNS name (loop detected)")
            if offset >= len(data):
                raise DNSLookupError("truncated DNS name")
            length = data[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    next_offset = offset
                break
            if length & 0xC0 == 0xC0:  # compression pointer
                if offset + 1 >= len(data):
                    raise DNSLookupError("truncated DNS pointer")
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    next_offset = offset + 2
                offset = pointer
                jumped = True
                continue
            offset += 1
            labels.append(data[offset : offset + length].decode("latin-1"))
            offset += length
        return ".".join(labels), next_offset

    def query(self, name: str, rtype: str) -> List[str]:
        if rtype not in _RECORD_TYPES:
            raise DNSLookupError(f"unsupported record type: {rtype}")

        query_id = random.randint(0, 0xFFFF)
        header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        question = self._encode_name(name) + struct.pack(
            "!HH", _RECORD_TYPES[rtype], 1
        )
        packet = header + question

        last_error = "no response"
        for _ in range(2):  # one retry
            try:
                answers = self._exchange(packet, query_id)
                return answers
            except DNSLookupError as exc:
                last_error = str(exc)
            except (socket.timeout, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        raise DNSLookupError(last_error)

    def _exchange(self, packet: bytes, query_id: int) -> List[str]:
        family = socket.AF_INET
        try:
            ipaddress.IPv6Address(self.nameserver)
            family = socket.AF_INET6
        except ValueError:
            pass

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(packet, (self.nameserver, 53))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        return self._parse_response(data, query_id)

    def _parse_response(self, data: bytes, query_id: int) -> List[str]:
        if len(data) < 12:
            raise DNSLookupError("short DNS response")
        (resp_id, flags, qd, an, _ns, _ar) = struct.unpack("!HHHHHH", data[:12])
        if resp_id != query_id:
            raise DNSLookupError("DNS response id mismatch")
        rcode = flags & 0x000F
        if rcode == 3:
            raise DNSLookupError("NXDOMAIN (name does not exist)")
        if rcode != 0:
            raise DNSLookupError(f"DNS server returned rcode {rcode}")

        offset = 12
        for _ in range(qd):  # skip the question section
            _, offset = self._decode_name(data, offset)
            offset += 4

        results: List[str] = []
        for _ in range(an):
            _, offset = self._decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10
            rdata_start = offset
            rdata_end = offset + rdlength

            if rtype == 1 and rdlength == 4:
                results.append(str(ipaddress.IPv4Address(data[rdata_start:rdata_end])))
            elif rtype == 28 and rdlength == 16:
                results.append(str(ipaddress.IPv6Address(data[rdata_start:rdata_end])))
            elif rtype in (2, 5):  # NS, CNAME
                target, _ = self._decode_name(data, rdata_start)
                results.append(target)
            elif rtype == 15:  # MX
                if rdlength >= 3:
                    pref = struct.unpack("!H", data[rdata_start : rdata_start + 2])[0]
                    exch, _ = self._decode_name(data, rdata_start + 2)
                    results.append(f"{pref} {exch}")
            elif rtype == 16:  # TXT
                results.append(self._parse_txt(data, rdata_start, rdata_end))
            offset = rdata_end
        return results

    @staticmethod
    def _parse_txt(data: bytes, start: int, end: int) -> str:
        chunks: List[str] = []
        offset = start
        while offset < end:
            length = data[offset]
            offset += 1
            chunks.append(data[offset : offset + length].decode("latin-1"))
            offset += length
        return "".join(chunks)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
class DNSAnalyzer:
    """Gathers A, AAAA, MX, NS, CNAME and TXT records for a hostname."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._mini = _MiniResolver(timeout=timeout)

    @property
    def backend(self) -> str:
        return "dnspython" if _HAVE_DNSPYTHON else "builtin"

    def analyze(self, hostname: str, record_types: Optional[List[str]] = None) -> DNSResult:
        record_types = record_types or RECORD_ORDER
        result = DNSResult(hostname=hostname, resolver=self.backend)
        for rtype in record_types:
            try:
                values = self._lookup(hostname, rtype)
            except DNSLookupError as exc:
                # "no records of this type" is normal, not an error worth
                # shouting about; record it for transparency.
                result.errors.append(f"{rtype}: {exc}")
                result.records[rtype] = []
                continue
            except Exception as exc:  # pragma: no cover - defensive
                result.errors.append(f"{rtype}: {type(exc).__name__}: {exc}")
                result.records[rtype] = []
                continue
            result.records[rtype] = values
        return result

    def _lookup(self, hostname: str, rtype: str) -> List[str]:
        if _HAVE_DNSPYTHON:
            return self._lookup_dnspython(hostname, rtype)
        return self._mini.query(hostname, rtype)

    def _lookup_dnspython(self, hostname: str, rtype: str) -> List[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answers = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as exc:
            raise DNSLookupError(f"NXDOMAIN: {exc}") from exc
        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(f"no nameservers: {exc}") from exc
        except dns.exception.Timeout as exc:
            raise DNSLookupError("query timed out") from exc
        except dns.resolver.NoAnswer:
            return []
        except Exception as exc:
            raise DNSLookupError(f"{type(exc).__name__}: {exc}") from exc

        if answers.rrset is None:
            return []

        values: List[str] = []
        for rdata in answers:
            if rtype == "MX":
                values.append(f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}")
            elif rtype in ("NS", "CNAME"):
                values.append(rdata.target.to_text(omit_final_dot=True))
            elif rtype == "TXT":
                values.append("".join(
                    part.decode("latin-1") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ))
            else:
                values.append(rdata.address if hasattr(rdata, "address") else rdata.to_text())
        return values
