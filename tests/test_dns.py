"""Tests for the DNS analyzer, including the dependency-free resolver."""
import struct

import pytest

from dns_analyzer import DNSAnalyzer, DNSResult, DNSLookupError, _MiniResolver


def _build_response(qid, qname, rtype_code, answers):
    """Build a synthetic DNS response packet.

    ``answers`` is a list of (name, type, rdata_bytes) tuples.
    """
    question = _MiniResolver._encode_name(qname) + struct.pack("!HH", rtype_code, 1)
    body = b""
    for name, atype, rdata in answers:
        body += _MiniResolver._encode_name(name)
        body += struct.pack("!HHIH", atype, 1, 300, len(rdata)) + rdata
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, len(answers), 0, 0)
    return header + question + body


def test_encode_name_basic():
    assert _MiniResolver._encode_name("example.com") == b"\x07example\x03com\x00"


def test_decode_name_roundtrip():
    data = _MiniResolver._encode_name("www.example.com")
    name, offset = _MiniResolver._decode_name(data, 0)
    assert name == "www.example.com"
    assert offset == len(data)


def test_decode_name_compression_pointer():
    base = _MiniResolver._encode_name("example.com")
    data = base + b"\xc0\x00"  # pointer to offset 0
    name, offset = _MiniResolver._decode_name(data, len(base))
    assert name == "example.com"
    assert offset == len(base) + 2


def test_parse_txt_multichunk():
    payload = b"\x05hello\x05world"
    assert _MiniResolver._parse_txt(payload, 0, len(payload)) == "helloworld"


def test_query_unsupported_type():
    with pytest.raises(DNSLookupError):
        _MiniResolver().query("example.com", "SOA")


def test_parse_response_a_record():
    qid = 0x1234
    packet = _build_response(qid, "example.com", 1, [("example.com", 1, bytes([93, 184, 216, 34]))])
    assert _MiniResolver()._parse_response(packet, qid) == ["93.184.216.34"]


def test_parse_response_mx_and_ns():
    qid = 0x2222
    mx_rdata = struct.pack("!H", 10) + _MiniResolver._encode_name("mail.example.com")
    ns_rdata = _MiniResolver._encode_name("ns1.example.com")
    packet = _build_response(
        qid,
        "example.com",
        15,
        [("example.com", 15, mx_rdata), ("example.com", 2, ns_rdata)],
    )
    values = _MiniResolver()._parse_response(packet, qid)
    assert "10 mail.example.com" in values
    assert "ns1.example.com" in values


def test_parse_response_aaaa_record():
    qid = 0x3333
    import ipaddress
    rdata = ipaddress.IPv6Address("2606:2800:220:1::1").packed
    packet = _build_response(qid, "example.com", 28, [("example.com", 28, rdata)])
    assert _MiniResolver()._parse_response(packet, qid) == ["2606:2800:220:1::1"]


def test_parse_response_nxdomain():
    qid = 0x4444
    # rcode 3 (NXDOMAIN) in the low nibble of the flags
    header = struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 0, 0)
    question = _MiniResolver._encode_name("nope.example") + struct.pack("!HH", 1, 1)
    with pytest.raises(DNSLookupError):
        _MiniResolver()._parse_response(header + question, qid)


def test_dns_result_as_dict():
    res = DNSResult(hostname="example.com", resolver="builtin")
    res.records["A"] = ["1.2.3.4"]
    d = res.as_dict()
    assert d["hostname"] == "example.com"
    assert d["records"]["A"] == ["1.2.3.4"]
    assert d["resolver"] == "builtin"


def test_analyzer_backend_reported():
    assert DNSAnalyzer().backend in ("dnspython", "builtin")
