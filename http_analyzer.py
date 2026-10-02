"""http_analyzer.py - safe, single-request HTTP/HTTPS metadata collection.

AppMap makes one ordinary GET request per scheme (following redirects, which is
normal browser behaviour) and records only what the server chooses to expose:
status code, redirect chain, response headers, content type and any explicit
server/application hints. It never sends attack payloads, never attempts to
bypass authentication, rate limits, WAFs or CAPTCHAs, and never repeats a
request in a tight loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

# Headers that are safe and useful to surface as "application hints".
HINT_HEADERS = [
    "Server",
    "Via",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Backend-Server",
    "X-Served-By",
    "X-Cache",
    "CF-Ray",
    "X-Varnish",
]

DEFAULT_USER_AGENT = "AppMap/1.0 (+defensive metadata inspection)"


@dataclass
class RedirectHop:
    status_code: int
    url: str
    location: Optional[str] = None

    def as_dict(self) -> dict:
        return {"status_code": self.status_code, "url": self.url, "location": self.location}


@dataclass
class HTTPResult:
    requested_url: str
    final_url: Optional[str] = None
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    server: Optional[str] = None
    hints: Dict[str, str] = field(default_factory=dict)
    tls_used: bool = False
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None
    ok: bool = False

    def as_dict(self) -> dict:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "reason": self.reason,
            "redirect_chain": [h.as_dict() for h in self.redirect_chain],
            "headers": self.headers,
            "content_type": self.content_type,
            "server": self.server,
            "hints": self.hints,
            "tls_used": self.tls_used,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "ok": self.ok,
        }


class HTTPAnalyzer:
    """Issues a single, conservative HTTP request and records the metadata."""

    def __init__(self, timeout: float = 8.0, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent

    def analyze(self, url: str) -> HTTPResult:
        result = HTTPResult(requested_url=url)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,  # we do not read the body; metadata only
            )
        except requests.exceptions.SSLError as exc:
            result.error = f"TLS/SSL error: {exc}"
            return result
        except requests.exceptions.ConnectTimeout:
            result.error = "connection timed out"
            return result
        except requests.exceptions.ReadTimeout:
            result.error = "read timed out"
            return result
        except requests.exceptions.TooManyRedirects:
            result.error = "too many redirects"
            return result
        except requests.exceptions.ConnectionError as exc:
            result.error = f"connection error: {exc}"
            return result
        except requests.exceptions.MissingSchema:
            result.error = "invalid URL (missing scheme)"
            return result
        except requests.exceptions.InvalidURL as exc:
            result.error = f"invalid URL: {exc}"
            return result
        except requests.exceptions.RequestException as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        # Release the connection without downloading the body.
        try:
            resp.close()
        except Exception:
            pass

        result.ok = True
        result.final_url = resp.url
        result.scheme = requests.utils.urlparse(resp.url).scheme
        result.status_code = resp.status_code
        result.reason = resp.reason
        result.tls_used = result.scheme == "https"
        result.elapsed_ms = round(resp.elapsed.total_seconds() * 1000, 1)

        result.headers = {k: v for k, v in resp.headers.items()}
        result.content_type = resp.headers.get("Content-Type")
        result.server = resp.headers.get("Server")
        result.hints = {
            name: resp.headers[name] for name in HINT_HEADERS if name in resp.headers
        }

        for hop in resp.history:
            result.redirect_chain.append(
                RedirectHop(
                    status_code=hop.status_code,
                    url=hop.url,
                    location=hop.headers.get("Location"),
                )
            )
        result.redirect_chain.append(
            RedirectHop(status_code=resp.status_code, url=resp.url, location=None)
        )
        return result
