"""Tests for graph construction and rendering."""
from dns_analyzer import DNSResult
from graph import GraphBuilder
from http_analyzer import HTTPResult, RedirectHop
from tls_analyzer import TLSResult


def _dns():
    d = DNSResult(hostname="example.com", resolver="builtin")
    d.records = {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"], "NS": ["ns1.example.com"]}
    return d


def _http():
    r = HTTPResult(requested_url="https://example.com")
    r.ok = True
    r.final_url = "https://example.com"
    r.scheme = "https"
    r.status_code = 200
    r.reason = "OK"
    r.content_type = "text/html"
    r.server = "nginx"
    r.hints = {"X-Powered-By": "Express"}
    r.redirect_chain = [RedirectHop(200, "https://example.com")]
    return r


def _tls():
    r = TLSResult(hostname="example.com")
    r.connected = True
    r.tls_version = "TLS 1.3"
    r.subject = {"commonName": "example.com"}
    r.issuer = {"organizationName": "Example CA"}
    r.days_until_expiry = 100
    r.sans = ["example.com", "www.example.com"]
    r.verified = True
    return r


def test_graph_build_structure():
    tree = GraphBuilder("example.com", _dns(), _http(), _tls()).build()
    assert tree["name"] == "example.com"
    names = [c["name"] for c in tree["children"]]
    assert "DNS" in names
    assert "HTTPS service" in names
    assert "TLS" in names


def test_graph_ascii_contains_nodes():
    tree = GraphBuilder("example.com", _dns(), _http(), _tls()).build()
    ascii_tree = GraphBuilder.render_ascii(tree)
    assert "example.com" in ascii_tree
    assert "TLS 1.3" in ascii_tree
    assert "A 93.184.216.34" in ascii_tree


def test_graph_nodes_edges():
    view = GraphBuilder("example.com", _dns(), _http(), _tls()).build_nodes_edges()
    assert len(view["nodes"]) == len(view["edges"]) + 1  # a tree with one root
    root = view["nodes"][0]
    assert root["label"] == "example.com"


def test_graph_without_http_or_tls():
    tree = GraphBuilder("example.com", _dns()).build()
    names = [c["name"] for c in tree["children"]]
    assert names == ["DNS"]


def test_graph_handles_empty_dns():
    d = DNSResult(hostname="example.com")
    d.records = {k: [] for k in ("A", "AAAA", "MX", "NS", "CNAME", "TXT")}
    tree = GraphBuilder("example.com", d).build()
    dns_node = tree["children"][0]
    assert dns_node["children"][0]["name"] == "(no records)"
