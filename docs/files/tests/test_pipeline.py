"""End-to-end pipeline test with analyzers stubbed (no network access)."""
from dns_analyzer import DNSResult
from http_analyzer import HTTPResult
from tls_analyzer import TLSResult
import appmap


def test_scan_pipeline(monkeypatch):
    def fake_dns(self, hostname, record_types=None):
        d = DNSResult(hostname=hostname, resolver="builtin")
        d.records = {"A": ["93.184.216.34"]}
        return d

    def fake_http(self, url):
        r = HTTPResult(requested_url=url)
        r.ok = True
        r.final_url = url
        r.scheme = "https"
        r.status_code = 200
        r.reason = "OK"
        r.content_type = "text/html"
        r.server = "nginx"
        return r

    def fake_tls(self, hostname, port=443):
        r = TLSResult(hostname=hostname)
        r.connected = True
        r.tls_version = "TLS 1.3"
        r.subject = {"commonName": hostname}
        r.issuer = {"organizationName": "Example CA"}
        r.verified = True
        return r

    monkeypatch.setattr(appmap.DNSAnalyzer, "analyze", fake_dns)
    monkeypatch.setattr(appmap.HTTPAnalyzer, "analyze", fake_http)
    monkeypatch.setattr(appmap.TLSAnalyzer, "analyze", fake_tls)
    monkeypatch.setattr(appmap, "INTER_REQUEST_DELAY", 0)

    result = appmap.scan("example.com")
    assert result["target"] == "example.com"
    assert result["dns"]["records"]["A"] == ["93.184.216.34"]
    assert result["http"]["status_code"] == 200
    assert result["tls"]["tls_version"] == "TLS 1.3"
    assert "graph_ascii" in result
    assert "example.com" in result["graph_ascii"]


def test_render_terminal_contains_sections(monkeypatch):
    def fake_dns(self, hostname, record_types=None):
        d = DNSResult(hostname=hostname, resolver="builtin")
        d.records = {"A": ["1.1.1.1"]}
        return d

    monkeypatch.setattr(appmap.DNSAnalyzer, "analyze", fake_dns)
    monkeypatch.setattr(appmap, "INTER_REQUEST_DELAY", 0)
    result = appmap.scan("example.com", do_http=False, do_tls=False)
    text = appmap.render_terminal(result)
    assert "AppMap" in text
    assert "DNS" in text
    assert "1.1.1.1" in text
