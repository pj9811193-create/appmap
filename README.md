# AppMap

**AppMap** is a defensive, Nmap-inspired discovery tool focused **exclusively on
OSI Layer 7 (the Application Layer)**. Given a hostname or URL that you own or
are explicitly authorised to test, it safely identifies and visualises the
application-layer services and metadata a server publicly exposes: DNS records,
a normal HTTP/HTTPS response, TLS certificate details, and a relationship graph
tying them together.

AppMap is **not** an attack tool. It does not perform port scanning, packet
flooding, exploitation, brute forcing, credential testing, vulnerability
exploitation, or any attempt to bypass authentication, rate limits, WAFs,
CAPTCHAs or access controls. It issues only ordinary, low-rate requests.

---

## Authorised use only

> By using AppMap you confirm that you own the target or hold explicit written
> authorisation to test it. Scanning systems you do not own or are not
> authorised to test may be illegal in your jurisdiction.

The CLI prints this notice on every run (suppress it with `--quiet`).

---

## Features

1. Accepts a hostname or URL (e.g. `example.com` or `https://example.com/path`).
2. Validates and normalises the target, rejecting malformed input.
3. Performs DNS lookups for **A, AAAA, MX, NS, CNAME, TXT**.
4. Makes a single, ordinary HTTP/HTTPS request and records the **status code,
   redirect chain, response headers, content type** and explicit server /
   application hints.
5. Inspects **TLS metadata** for HTTPS: version, cipher, certificate subject,
   issuer, expiry, and Subject Alternative Names.
6. Builds a **relationship graph**: Domain -> DNS -> Web service -> TLS
   certificate -> application metadata.
7. Provides a clear **terminal output** and an optional **local web dashboard**.
8. **Exports results to JSON** (and a one-row CSV summary).
9. Handles timeouts, DNS failures, invalid URLs, TLS errors, redirects and
   unavailable services gracefully.
10. Keeps the architecture **modular** so additional safe application protocols
    can be added later.

---

## Project structure

```
appmap/
├── appmap.py          # CLI entry point + pipeline orchestration + input validation
├── dns_analyzer.py    # DNS lookups (dnspython, with a stdlib fallback resolver)
├── http_analyzer.py   # single safe HTTP/HTTPS request + metadata
├── tls_analyzer.py    # TLS handshake + certificate metadata
├── graph.py           # relationship graph (nested dict, ASCII tree, nodes/edges)
├── exporter.py        # JSON / CSV export
├── dashboard.py       # web interface (Flask + single-page UI + JSON API)
├── requirements.txt
├── Dockerfile         # container image for hosting the interface
├── .dockerignore
├── Procfile           # for Heroku-style / gunicorn hosts
├── render.yaml        # Render.com blueprint for one-click hosting
├── README.md
├── conftest.py        # makes the flat layout importable under pytest
└── tests/
    ├── test_input.py
    ├── test_dns.py
    ├── test_http.py
    ├── test_tls.py
    ├── test_graph.py
    ├── test_exporter.py
    └── test_pipeline.py
```

---

## Installation

Requires **Python 3.8+**. From inside the `appmap/` directory:

```bash
# (optional but recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# install dependencies
pip install -r requirements.txt
```

The core CLI works with the Python standard library alone. `requests` is used
for the HTTP step, `dnspython` enriches DNS lookups (a built-in fallback
resolver is used automatically if it is not installed), and `Flask` is only
needed for the dashboard.

---

## Running the CLI

```bash
python appmap.py example.com
```

Write full results to JSON and a CSV summary:

```bash
python appmap.py example.com --json results.json --csv summary.csv
```

Other options:

| Flag | Meaning |
| --- | --- |
| `--json PATH` | write full results to a JSON file |
| `--csv PATH` | write a one-row CSV summary |
| `--output-dir DIR` | directory for exports (default: `.`) |
| `--timeout SECONDS` | per-request timeout (default: `8`) |
| `--no-http` | skip the HTTP request |
| `--no-tls` | skip TLS inspection |
| `--quiet` | suppress the authorisation notice |
| `--version` | print the version |

### Example output

```
AppMap
────────────────────────────────────────
Target: example.com
URL:    https://example.com

DNS
A      93.184.216.34
MX     0 .
NS     a.iana-servers.net
NS     b.iana-servers.net

HTTP/HTTPS
Status: 200 OK
Final:  https://example.com/
Content-Type: text/html; charset=UTF-8
Response time: 142.3 ms

TLS
Version: TLS 1.3
Cipher:  TLS_AES_128_GCM_SHA256
Certificate: CN=example.com
Issuer:      DigiCert Inc
Expires:     Oct 2 23:59:59 2026 GMT (365 days)
SANs:        example.com, www.example.com

APPLICATION
HTTP detected
Content-Type: text/html; charset=UTF-8

Graph:
example.com
├── DNS
│   ├── A 93.184.216.34
│   └── NS a.iana-servers.net
├── HTTPS service
│   ├── Status 200 OK
│   └── Content-Type: text/html; charset=UTF-8
└── TLS
    ├── TLS 1.3
    ├── subject CN=example.com
    └── issuer DigiCert Inc
```

---

## Web interface

The interface is a single-page app served by Flask. It calls the exact same
pipeline as the CLI and shows a summary bar (target, HTTP status, TLS version,
certificate expiry), tables for DNS / HTTP / TLS, a relationship tree, and a
raw-JSON panel with a one-click download.

```bash
python dashboard.py
```

Then open <http://127.0.0.1:5000> and enter a target. It binds to localhost only
by default.

A JSON API backs the interface and is available for scripting:

```
GET /api/scan?target=example.com    # full scan result as JSON
GET /api/health                     # liveness probe
```

There is also a standalone, offline preview of the interface with baked-in
sample data: open `appmap-demo.html` in any browser - no server needed.

---

## Hosting the interface

### Option A - run locally

```bash
python dashboard.py            # http://127.0.0.1:5000
```

### Option B - Docker (self-host anywhere)

```bash
docker build -t appmap .
docker run -p 8000:8000 appmap   # then open http://127.0.0.1:8000
```

The image runs behind **gunicorn**, not the Flask development server.

### Option C - a managed host (Render / Railway / Fly / Heroku)

This repo ships the files these platforms expect:

- `Procfile` -> `web: gunicorn -w 2 -b 0.0.0.0:$PORT --timeout 60 dashboard:app`
- `render.yaml` -> a Render.com blueprint (push to GitHub, then *New > Blueprint*)
- `Dockerfile` -> for Fly.io, Railway, or any container host

The app reads `APPMAP_HOST` and `APPMAP_PORT` from the environment, so it binds
to `0.0.0.0` and the platform-assigned port automatically.

> **Note on hosting:** a public deployment is reachable by anyone, so only
deploy it where you intend to offer it, and keep the authorisation notice in
place. Because AppMap makes outbound requests on behalf of whoever submits a
target, some shared hosts block outbound DNS - the HTTP step will still work
through an HTTP proxy, but DNS/TLS may report "unavailable" there.

### Running behind gunicorn manually

```bash
gunicorn -w 2 -b 0.0.0.0:8000 --timeout 60 dashboard:app
```

---

## Programmatic use

```python
from appmap import scan

result = scan("example.com")
print(result["dns"]["records"]["A"])
print(result["graph_ascii"])
```

---

## Running the tests

```bash
python -m pytest -q
```

The suite (49 tests) covers input validation, the DNS packet parser, HTTP
metadata extraction and error handling, TLS certificate helpers, graph
construction/rendering, export, and the end-to-end pipeline. It uses stubs for
all network calls, so it runs offline.

---

## Safety and engineering notes

- **Ordinary requests only.** One HTTP request (plus normal redirect following)
  and one TLS handshake per target, with a short pause between them.
- **No offensive behaviour.** No port scanning, flooding, exploitation, brute
  forcing, credential testing, or access-control bypass.
- **Timeouts everywhere.** Every network call has a conservative timeout.
- **Graceful failure.** DNS failures, invalid URLs, TLS errors, redirects and
  unreachable services are recorded as notes rather than crashing the run.
- **Input validation.** Targets are validated and normalised before any request.
- **Modular design.** Each analyzer is an independent class with a single
  `analyze()` entry point, so new safe application protocols (e.g. a plain
  HTTPS `HEAD` probe, a `robots.txt` fetch) can be added without touching the
  rest of the pipeline.

---

## Limitations

- AppMap reports only what a service **publicly exposes**; absence of a hint
  does not mean absence of a service.
- TLS inspection connects to port 443 by default.
- DNS lookups require outbound DNS access from the machine running AppMap.
