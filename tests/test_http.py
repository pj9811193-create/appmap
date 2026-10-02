"""Tests for the HTTP analyzer using a stubbed requests.get (no network)."""
from datetime import timedelta

import pytest
import requests

from http_analyzer import HTTPAnalyzer


class FakeResponse:
    def __init__(self, url, status_code=200, reason="OK", headers=None, history=None):
        self.url = url
        self.status_code = status_code
        self.reason = reason
        self.headers = headers or {}
        self.history = history or []
        self.elapsed = timedelta(milliseconds=123)
        self.closed = False

    def close(self):
        self.closed = True


def test_analyze_success(monkeypatch):
    def fake_get(url, **kwargs):
        return FakeResponse(
            url,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Server": "nginx/1.24",
                "X-Powered-By": "Express",
            },
        )

    monkeypatch.setattr(requests, "get", fake_get)
    result = HTTPAnalyzer().analyze("https://example.com")
    assert result.ok
    assert result.status_code == 200
    assert result.content_type == "text/html; charset=utf-8"
    assert result.server == "nginx/1.24"
    assert result.hints["X-Powered-By"] == "Express"
    assert result.tls_used is True
    assert result.elapsed_ms == 123.0


def test_analyze_redirect_chain(monkeypatch):
    hop = FakeResponse("http://example.com", 301, "Moved Permanently",
                       headers={"Location": "https://example.com"})

    def fake_get(url, **kwargs):
        return FakeResponse("https://example.com", 200, "OK", history=[hop])

    monkeypatch.setattr(requests, "get", fake_get)
    result = HTTPAnalyzer().analyze("http://example.com")
    assert len(result.redirect_chain) == 2
    assert result.redirect_chain[0].status_code == 301
    assert result.redirect_chain[0].location == "https://example.com"


@pytest.mark.parametrize(
    "exc,needle",
    [
        (requests.exceptions.SSLError("bad cert"), "TLS/SSL error"),
        (requests.exceptions.ConnectTimeout(), "timed out"),
        (requests.exceptions.ConnectionError("refused"), "connection error"),
        (requests.exceptions.TooManyRedirects(), "too many redirects"),
    ],
)
def test_analyze_errors_are_graceful(monkeypatch, exc, needle):
    def fake_get(url, **kwargs):
        raise exc

    monkeypatch.setattr(requests, "get", fake_get)
    result = HTTPAnalyzer().analyze("https://example.com")
    assert result.ok is False
    assert needle in (result.error or "")


def test_analyze_missing_schema(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.MissingSchema()

    monkeypatch.setattr(requests, "get", fake_get)
    result = HTTPAnalyzer().analyze("example.com")
    assert result.ok is False
    assert "invalid URL" in (result.error or "")
