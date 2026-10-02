"""Tests for target parsing and input validation."""
import pytest

from appmap import parse_target, InputError


@pytest.mark.parametrize(
    "raw,hostname",
    [
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com/path?q=1", "example.com"),
        ("sub.example.co.in", "sub.example.co.in"),
        ("example.com/foo/bar", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("  example.com  ", "example.com"),
        ("example.com.", "example.com"),
    ],
)
def test_parse_target_valid(raw, hostname):
    parsed = parse_target(raw)
    assert parsed["hostname"] == hostname
    assert parsed["url"].startswith(("http://", "https://"))


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "exa mple.com",
        "http://",
        "ftp://example.com",
        "-bad.example.com",
        "example..com",
        "a" * 300 + ".com",
        "256.1.1.1",
    ],
)
def test_parse_target_invalid(raw):
    with pytest.raises(InputError):
        parse_target(raw)


def test_parse_target_scheme_preserved():
    assert parse_target("http://example.com")["scheme"] == "http"
    assert parse_target("https://example.com")["scheme"] == "https"
    assert parse_target("example.com")["scheme"] == "https"
