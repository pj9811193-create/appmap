#!/usr/bin/env python3
"""appmap.py - AppMap: safe OSI Layer 7 service & metadata discovery.

AppMap is a *defensive* tool. Given a hostname or URL that you own or are
explicitly authorised to test, it gathers publicly exposed application-layer
metadata: DNS records, a normal HTTP/HTTPS response, TLS certificate details,
and a relationship graph of what it found.

It deliberately does NOT perform port scanning, packet flooding, exploitation,
brute forcing, credential testing, vulnerability exploitation, or any attempt to
bypass authentication, rate limits, WAFs, CAPTCHAs or access controls. Only
ordinary, low-rate requests are made.

Usage:
    python appmap.py example.com
    python appmap.py https://example.com --json out.json
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from dns_analyzer import DNSAnalyzer
from exporter import Exporter
from graph import GraphBuilder
from http_analyzer import HTTPAnalyzer
from tls_analyzer import TLSAnalyzer

__version__ = "1.0.0"

AUTHORIZATION_NOTICE = """\
AppMap - application-layer discovery (defensive use only)
=========================================================
By using AppMap you confirm you own the target or have explicit written
authorisation to test it. AppMap makes only ordinary, low-rate requests and
never attempts exploitation, brute forcing, credential attacks, or any attempt
to bypass access controls.
"""

# Conservative defaults: one request per endpoint, with a small pause between
# the HTTP and TLS steps so we never look like a scanner hammering a host.
DEFAULT_TIMEOUT = 8.0
INTER_REQUEST_DELAY = 0.5

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class InputError(ValueError):
    """Raised when the user-supplied target cannot be understood."""


def parse_target(raw: str) -> dict:
    """Validate and normalise a hostname or URL.

    Returns a dict with ``hostname``, ``url`` and ``scheme``. Raises
    :class:`InputError` on anything invalid so callers can fail gracefully.
    """
    if raw is None:
        raise InputError("no target supplied")
    target = raw.strip()
    if not target:
        raise InputError("target is empty")
    if len(target) > 2048:
        raise InputError("target is unreasonably long")
    if any(ch in target for ch in (" ", "\t", "\n", "\r")):
        raise InputError("target contains whitespace")
    # Strip a trailing path/query defensively if a bare hostname was given.
    scheme = "https"
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise InputError(f"unsupported scheme: {parsed.scheme!r}")
        hostname = parsed.hostname
        scheme = parsed.scheme
        if not hostname:
            raise InputError("could not extract a hostname from the URL")
        url = target
    else:
        # bare host, optionally with a path like example.com/foo
        hostname = target.split("/", 1)[0]
        path = target[len(hostname):]
        url = f"{scheme}://{hostname}{path}"

    if not _HOSTNAME_RE.match(hostname) and not _IP_RE.match(hostname):
        raise InputError(f"invalid hostname: {hostname!r}")
    if _IP_RE.match(hostname):
        for octet in hostname.split("."):
            if int(octet) > 255:
                raise InputError(f"invalid IPv4 address: {hostname!r}")
    return {"hostname": hostname.rstrip("."), "url": url, "scheme": scheme}


def scan(
    raw_target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    do_http: bool = True,
    do_tls: bool = True,
    record_types=None,
) -> dict:
    """Run the full AppMap pipeline for one target and return a result dict.

    This is the single entry point reused by both the CLI and the dashboard.
    """
    parsed = parse_target(raw_target)
    hostname = parsed["hostname"]
    url = parsed["url"]

    result: dict = {
        "tool": "AppMap",
        "version": __version__,
        "target": hostname,
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "authorized_use_only": True,
        "dns": None,
        "http": None,
        "tls": None,
        "graph": None,
    }

    # --- DNS -------------------------------------------------------------
    dns_analyzer = DNSAnalyzer(timeout=timeout)
    dns_result = dns_analyzer.analyze(hostname, record_types=record_types)
    result["dns"] = dns_result.as_dict()

    # --- HTTP ------------------------------------------------------------
    http_result = None
    if do_http:
        http_analyzer = HTTPAnalyzer(timeout=timeout)
        http_result = http_analyzer.analyze(url)
        result["http"] = http_result.as_dict()
        if do_tls:
            time.sleep(INTER_REQUEST_DELAY)  # gentle pacing between requests

    # --- TLS -------------------------------------------------------------
    tls_result = None
    if do_tls:
        tls_analyzer = TLSAnalyzer(timeout=timeout)
        tls_result = tls_analyzer.analyze(hostname, port=443)
        result["tls"] = tls_result.as_dict()

    # --- Graph -----------------------------------------------------------
    builder = GraphBuilder(hostname, dns_result, http_result, tls_result)
    result["graph"] = builder.build()
    result["graph_ascii"] = GraphBuilder.render_ascii(result["graph"])
    return result


# --------------------------------------------------------------------------- #
# Terminal rendering
# --------------------------------------------------------------------------- #
def _hr(char: str = "-", width: int = 40) -> str:
    return char * width


def render_terminal(result: dict) -> str:
    out: list[str] = []
    out.append("AppMap")
    out.append("─" * 40)
    out.append(f"Target: {result['target']}")
    out.append(f"URL:    {result['url']}")
    out.append("")

    dns = result.get("dns") or {}
    out.append("DNS")
    records = dns.get("records", {})
    any_records = False
    for rtype in ("A", "AAAA", "MX", "NS", "CNAME", "TXT"):
        values = records.get(rtype) or []
        for i, value in enumerate(values):
            label = rtype if i == 0 else ""
            out.append(f"{label:<6} {value}")
            any_records = True
    if not any_records:
        out.append("(no records resolved)")
    out.append("")

    http = result.get("http")
    if http is not None:
        out.append("HTTP/HTTPS")
        if http.get("ok"):
            out.append(f"Status: {http.get('status_code')} {http.get('reason') or ''}".rstrip())
            if http.get("final_url"):
                out.append(f"Final:  {http['final_url']}")
            if len(http.get("redirect_chain", [])) > 1:
                out.append("Redirects:")
                for hop in http["redirect_chain"]:
                    arrow = f" -> {hop['location']}" if hop.get("location") else ""
                    out.append(f"  {hop['status_code']} {hop['url']}{arrow}")
            if http.get("content_type"):
                out.append(f"Content-Type: {http['content_type']}")
            if http.get("server"):
                out.append(f"Server: {http['server']}")
            for name, value in (http.get("hints") or {}).items():
                if name == "Server":
                    continue
                out.append(f"{name}: {value}")
            if http.get("elapsed_ms") is not None:
                out.append(f"Response time: {http['elapsed_ms']} ms")
        else:
            out.append(f"Unavailable: {http.get('error')}")
        out.append("")

    tls = result.get("tls")
    if tls is not None:
        out.append("TLS")
        if tls.get("connected"):
            out.append(f"Version: {tls.get('tls_version') or 'unknown'}")
            if tls.get("cipher"):
                out.append(f"Cipher:  {tls['cipher']}")
            subj = tls.get("subject") or {}
            iss = tls.get("issuer") or {}
            if subj:
                out.append(f"Certificate: CN={subj.get('commonName', '?')}")
            if iss:
                out.append(
                    "Issuer:      "
                    + (iss.get("organizationName") or iss.get("commonName") or "?")
                )
            if tls.get("not_after"):
                days = tls.get("days_until_expiry")
                suffix = f" ({days} days)" if days is not None else ""
                out.append(f"Expires:     {tls['not_after']}{suffix}")
            if tls.get("sans"):
                out.append(f"SANs:        {', '.join(tls['sans'][:8])}"
                           + (" ..." if len(tls["sans"]) > 8 else ""))
            if tls.get("verified") is False:
                out.append("Note:        certificate did not verify (metadata shown unverified)")
            if tls.get("error"):
                out.append(f"Note:        {tls['error']}")
        else:
            out.append(f"Unavailable: {tls.get('error')}")
        out.append("")

    out.append("APPLICATION")
    http = result.get("http") or {}
    if http.get("ok"):
        out.append("HTTP detected")
        if http.get("content_type"):
            out.append(f"Content-Type: {http['content_type']}")
    else:
        out.append("No HTTP service metadata available")
    out.append("")

    out.append("Graph:")
    out.append(result.get("graph_ascii", ""))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appmap",
        description="AppMap - safe OSI Layer 7 service and metadata discovery "
                    "(defensive use only).",
        epilog="Example: python appmap.py example.com --json out.json",
    )
    parser.add_argument("target", help="hostname or URL, e.g. example.com")
    parser.add_argument("--json", metavar="PATH", help="write full results to a JSON file")
    parser.add_argument("--csv", metavar="PATH", help="write a one-row CSV summary")
    parser.add_argument("--output-dir", default=".", help="directory for exports (default: .)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--no-http", action="store_true", help="skip the HTTP request")
    parser.add_argument("--no-tls", action="store_true", help="skip the TLS inspection")
    parser.add_argument("--quiet", action="store_true", help="suppress the authorization notice")
    parser.add_argument("--version", action="version", version=f"AppMap {__version__}")
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.quiet:
        print(AUTHORIZATION_NOTICE)

    try:
        parsed = parse_target(args.target)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = scan(
            args.target,
            timeout=args.timeout,
            do_http=not args.no_http,
            do_tls=not args.no_tls,
        )
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - last-resort guard
        print(f"error: unexpected failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(render_terminal(result))

    exporter = Exporter(output_dir=args.output_dir)
    if args.json:
        path = exporter.export_json(result, args.json)
        print(f"\nJSON written to {path}")
    if args.csv:
        path = exporter.export_csv_summary(result, args.csv)
        print(f"CSV summary written to {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
