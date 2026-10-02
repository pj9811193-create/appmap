"""dashboard.py - AppMap's local web interface.

Run it with:   python dashboard.py
Open:          http://127.0.0.1:5000

The server exposes:
    GET /                 the single-page interface
    GET /api/scan?target= JSON scan result (same pipeline as the CLI)
    GET /api/health       liveness probe (used by hosting platforms)

For hosting behind a real server, run it with gunicorn:
    gunicorn -w 2 -b 0.0.0.0:8000 dashboard:app
"""

from __future__ import annotations

import os

from flask import Flask, Response, jsonify, request

from appmap import InputError, __version__, parse_target, scan

app = Flask(__name__)

# When hosted, allow overriding the bind address via environment variables.
HOST = os.environ.get("APPMAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("APPMAP_PORT", "5000"))


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AppMap - application-layer discovery</title>
<style>
  :root {
    --bg:#0b0e13; --panel:#141821; --panel2:#1b212c; --line:#2a3140;
    --fg:#e8ecf3; --muted:#93a0b4; --accent:#4da3ff; --accent2:#7c5cff;
    --ok:#3ddc97; --warn:#ffb454; --bad:#ff6b6b;
  }
  * { box-sizing: border-box; }
  html,body { margin:0; padding:0; }
  body {
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: radial-gradient(1200px 600px at 70% -10%, #16233a 0%, var(--bg) 55%);
    color: var(--fg); min-height:100vh; -webkit-font-smoothing:antialiased;
  }
  code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  a { color: var(--accent); }
  header {
    padding: 26px 28px 18px; border-bottom:1px solid var(--line);
    display:flex; align-items:center; gap:14px; flex-wrap:wrap;
    background: rgba(11,14,19,.6); backdrop-filter: blur(8px);
    position: sticky; top:0; z-index:5;
  }
  .logo {
    width:38px; height:38px; border-radius:10px; flex:0 0 auto;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    display:grid; place-items:center; font-weight:800; color:#05121f; font-size:18px;
  }
  header h1 { margin:0; font-size:19px; letter-spacing:.3px; }
  header .sub { color:var(--muted); font-size:12.5px; margin-top:2px; }
  .badge { font-size:11px; color:var(--muted); border:1px solid var(--line);
    padding:2px 9px; border-radius:20px; margin-left:8px; }
  main { max-width:1080px; margin:0 auto; padding:26px 20px 80px; }
  .search { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:8px; }
  .search .field { flex:1; min-width:240px; position:relative; }
  .search input {
    width:100%; padding:14px 16px; border-radius:12px; border:1px solid var(--line);
    background:var(--panel); color:var(--fg); font-size:15px; outline:none;
    transition:border-color .15s, box-shadow .15s;
  }
  .search input:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(77,163,255,.15); }
  .search button {
    padding:14px 22px; border-radius:12px; border:none; cursor:pointer; font-size:15px;
    font-weight:600; color:#04121f; background:linear-gradient(135deg,var(--accent),#5fb0ff);
    transition:transform .08s, filter .15s;
  }
  .search button:hover { filter:brightness(1.06); }
  .search button:active { transform:translateY(1px); }
  .search button:disabled { opacity:.6; cursor:default; }
  .notice { color:var(--muted); font-size:12px; line-height:1.6; margin:6px 2px 22px; }
  .notice b { color:var(--warn); font-weight:600; }
  .empty { text-align:center; color:var(--muted); padding:60px 20px; }
  .empty .big { font-size:44px; margin-bottom:10px; opacity:.5; }
  .spinner { width:16px; height:16px; border:2px solid rgba(255,255,255,.3);
    border-top-color:#04121f; border-radius:50%; display:inline-block;
    animation:spin .7s linear infinite; vertical-align:-2px; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:20px; }
  .stat { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px 16px; }
  .stat .k { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:1px; }
  .stat .v { font-size:20px; margin-top:6px; font-weight:600; word-break:break-word; }
  .stat .v.ok { color:var(--ok); } .stat .v.warn { color:var(--warn); } .stat .v.bad { color:var(--bad); }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:14px;
    padding:18px 20px; margin-bottom:16px; }
  .card > h2 { margin:0 0 14px; font-size:12px; text-transform:uppercase; letter-spacing:1.4px;
    color:var(--accent); display:flex; align-items:center; gap:8px; }
  .card > h2 .count { color:var(--muted); font-weight:400; letter-spacing:0; text-transform:none; }
  table.kv { width:100%; border-collapse:collapse; font-size:13.5px; }
  table.kv td { padding:7px 0; border-bottom:1px solid rgba(42,49,64,.55); vertical-align:top; }
  table.kv tr:last-child td { border-bottom:none; }
  table.kv td:first-child { color:var(--muted); width:190px; padding-right:14px; }
  .tag { display:inline-block; font-size:11px; padding:1px 8px; border-radius:6px;
    background:var(--panel2); border:1px solid var(--line); color:var(--muted); margin-right:6px; }
  .tag.a { color:#7fd0ff; } .tag.aaaa { color:#b8a6ff; } .tag.mx { color:#ffc98a; }
  .tag.ns { color:#9be6c4; } .tag.txt { color:#e6b8ff; } .tag.cname { color:#ffb0c8; }
  ul.tree { list-style:none; margin:0; padding-left:20px; }
  ul.tree.root { padding-left:2px; }
  ul.tree li { position:relative; padding:3px 0 3px 18px; font-size:13.5px; }
  ul.tree li::before { content:""; position:absolute; left:0; top:0; bottom:0;
    border-left:1px solid var(--line); }
  ul.tree li:last-child::before { bottom:auto; height:16px; }
  ul.tree li::after { content:""; position:absolute; left:0; top:16px; width:12px;
    border-top:1px solid var(--line); }
  ul.tree.root > li { padding-left:0; }
  ul.tree.root > li::before, ul.tree.root > li::after { display:none; }
  .node-type { font-size:10.5px; color:var(--muted); margin-left:8px; }
  .json-head { display:flex; justify-content:space-between; align-items:center; }
  .btn-ghost { background:var(--panel2); border:1px solid var(--line); color:var(--fg);
    padding:7px 14px; border-radius:9px; cursor:pointer; font-size:12.5px; }
  .btn-ghost:hover { border-color:var(--accent); }
  pre.json { max-height:420px; overflow:auto; background:#0d1017; border:1px solid var(--line);
    border-radius:10px; padding:14px; font-size:12.5px; line-height:1.5; margin:14px 0 0; }
  .alert { border-radius:12px; padding:14px 16px; font-size:13.5px; margin-bottom:16px; }
  .alert.err { background:rgba(255,107,107,.08); border:1px solid rgba(255,107,107,.4); color:#ffb3b3; }
  footer { text-align:center; color:var(--muted); font-size:11.5px; padding:30px 20px; }
</style>
</head>
<body>
<header>
  <div class="logo">A</div>
  <div>
    <h1>AppMap <span class="badge">v__VERSION__</span></h1>
    <div class="sub">Safe OSI Layer 7 service &amp; metadata discovery</div>
  </div>
</header>
<main>
  <form class="search" id="form">
    <div class="field">
      <input id="target" name="target" type="text" placeholder="example.com  or  https://example.com/path"
             autocomplete="off" spellcheck="false" autofocus>
    </div>
    <button id="go" type="submit">Map it</button>
  </form>
  <p class="notice">
    <b>Defensive use only.</b> Scan only hosts you own or are explicitly authorised to test.
    AppMap makes ordinary, low-rate requests and never attempts exploitation, brute forcing,
    credential attacks, or bypassing access controls.
  </p>
  <div id="out"><div class="empty"><div class="big">&#9783;</div>
    Enter a hostname or URL to map its application-layer services.</div></div>
</main>
<footer>AppMap v__VERSION__ &middot; results are informational and reflect only what a service publicly exposes.</footer>
<script>
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const out = $("#out");
let lastResult = null;

$("#form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("#target").value.trim();
  if (!target) return;
  const btn = $("#go");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Mapping';
  out.innerHTML = '<div class="empty">Contacting the target and collecting metadata&hellip;</div>';
  try {
    const res = await fetch("/api/scan?target=" + encodeURIComponent(target));
    const data = await res.json();
    if (!res.ok || data.error) { renderError(data.error || ("HTTP " + res.status)); }
    else { lastResult = data; render(data); }
  } catch (err) {
    renderError("Request failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Map it";
  }
});

function renderError(msg) {
  out.innerHTML = '<div class="alert err"><b>Could not map target.</b><br>' + esc(msg) + '</div>';
}

function tagFor(t) { return '<span class="tag ' + esc((t||"").toLowerCase()) + '">' + esc(t) + '</span>'; }

function render(d) {
  const dns = d.dns || {}, http = d.http || {}, tls = d.tls || {};
  const records = dns.records || {};

  // ---- summary stat cards ----
  const statusVal = http.ok ? (http.status_code + " " + (http.reason||"")).trim() : "unreachable";
  const statusCls = http.ok ? (http.status_code < 400 ? "ok" : "warn") : "bad";
  const tlsCls = tls.connected ? "ok" : "bad";
  let expCls = "", expVal = "n/a";
  if (tls.not_after) {
    expVal = (tls.days_until_expiry != null ? tls.days_until_expiry + " days" : "unknown");
    expCls = tls.days_until_expiry != null && tls.days_until_expiry < 14 ? "warn" : "ok";
  }
  const aCount = (records.A||[]).length;
  let html = '<div class="cards">'
    + stat("Target", d.target, "")
    + stat("HTTP status", statusVal, statusCls)
    + stat("TLS", tls.tls_version || (tls.connected ? "connected" : "n/a"), tlsCls)
    + stat("Cert expiry", expVal, expCls)
    + '</div>';

  // ---- DNS ----
  let dnsRows = "";
  const order = ["A","AAAA","MX","NS","CNAME","TXT"];
  order.forEach(function (t) {
    (records[t]||[]).forEach(function (v) { dnsRows += kvRow(tagFor(t), esc(v)); });
  });
  if (!dnsRows) dnsRows = kvRow('<span class="tag">none</span>', '<span style="color:var(--muted)">no records resolved</span>');
  html += card("DNS records", dnsRows + dnsErrors(dns.errors));

  // ---- HTTP ----
  const httpRows =
      kvRow("Status", esc(http.ok ? ((http.status_code + " " + (http.reason||"")).trim()) : (http.error||"unavailable")))
    + kvRow("Final URL", esc(http.final_url))
    + kvRow("Content-Type", esc(http.content_type))
    + kvRow("Server", esc(http.server))
    + kvRow("Response time", http.elapsed_ms != null ? esc(http.elapsed_ms) + " ms" : "")
    + Object.keys(http.hints||{}).filter(k => k !== "Server").map(k => kvRow(esc(k), esc(http.hints[k]))).join("")
    + redirects(http.redirect_chain);
  html += card("HTTP / HTTPS", httpRows);

  // ---- TLS ----
  const subj = tls.subject||{}, iss = tls.issuer||{};
  const tlsRows =
      kvRow("Version", esc(tls.tls_version))
    + kvRow("Cipher", esc(tls.cipher))
    + kvRow("Subject", esc(subj.commonName))
    + kvRow("Issuer", esc(iss.organizationName || iss.commonName))
    + kvRow("Valid from", esc(tls.not_before))
    + kvRow("Expires", esc(tls.not_after) + (tls.days_until_expiry != null ? ' <span class="node-type">(' + esc(tls.days_until_expiry) + ' days)</span>' : ""))
    + kvRow("SANs", (tls.sans||[]).map(s => '<span class="tag">' + esc(s) + '</span>').join(" "))
    + kvRow("Verified", tls.verified === true ? '<span style="color:var(--ok)">yes</span>' : (tls.verified === false ? '<span style="color:var(--warn)">no</span>' : ""))
    + kvRow("Note", esc(tls.error));
  html += card("TLS certificate", tlsRows);

  // ---- Graph ----
  html += '<div class="card"><h2>Relationship graph</h2>'
        + '<ul class="tree root">' + tree(d.graph) + '</ul></div>';

  // ---- JSON ----
  html += '<div class="card"><div class="json-head"><h2 style="margin:0">Raw JSON</h2>'
        + '<button class="btn-ghost" id="dl">Download JSON</button></div>'
        + '<pre class="json">' + esc(JSON.stringify(d, null, 2)) + '</pre></div>';

  out.innerHTML = html;
  const dl = $("#dl");
  if (dl) dl.addEventListener("click", downloadJson);
}

function stat(k, v, cls) {
  return '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v ' + cls + '">' + esc(v) + '</div></div>';
}
function card(title, inner) { return '<div class="card"><h2>' + esc(title) + '</h2><table class="kv">' + inner + '</table></div>'; }
function kvRow(k, v) { if (v === "" || v == null) return ""; return '<tr><td>' + k + '</td><td>' + v + '</td></tr>'; }
function dnsErrors(errs) {
  if (!errs || !errs.length) return "";
  return kvRow("Notes", '<span style="color:var(--muted)">' + esc(errs.slice(0,6).join("; ")) + '</span>');
}
function redirects(chain) {
  if (!chain || chain.length < 2) return "";
  const hops = chain.map(h => esc(h.status_code) + " " + esc(h.url) + (h.location ? " &rarr; " + esc(h.location) : "")).join("<br>");
  return kvRow("Redirects", hops);
}
function tree(node) {
  if (!node) return "";
  const kids = node.children || [];
  const label = esc(node.name) + (node.type && node.type !== "domain" && node.type !== "dns" ? '<span class="node-type">' + esc(node.type) + '</span>' : "");
  return "<li>" + label + (kids.length ? '<ul class="tree">' + kids.map(tree).join("") + "</ul>" : "") + "</li>";
}
function downloadJson() {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], {type:"application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "appmap_" + (lastResult.target||"target").replace(/[^a-z0-9.-]/gi,"_") + ".json";
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(a.href);
}
</script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index() -> Response:
    return Response(_INDEX_HTML.replace("__VERSION__", __version__), mimetype="text/html")


@app.route("/api/scan", methods=["GET"])
def api_scan():
    """JSON API mirroring the CLI, used by the interface and by scripts."""
    target = (request.args.get("target") or "").strip()
    if not target:
        return jsonify({"error": "missing 'target' query parameter"}), 400
    try:
        parse_target(target)
    except InputError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        result = scan(target)
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
    return jsonify(result)


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "tool": "AppMap", "version": __version__})


def main() -> None:
    print(f"AppMap interface running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    print("Defensive use only - scan hosts you own or are authorised to test.")
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
