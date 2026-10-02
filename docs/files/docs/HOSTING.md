# Hosting AppMap (without Render)

AppMap has two parts:

- a **static interface** (HTML/CSS/JS) - hostable anywhere, including GitHub Pages;
- a **Python backend** that does the actual DNS/HTTP/TLS work - needs a real server.

GitHub Pages can only serve the static interface. To get a *working* scanner on a
public URL, run the backend on one of the options below. None of them require
Render.

---

## Option 1 - GitHub Codespaces (GitHub-native, no other signup)

The fastest GitHub-only route. A `.devcontainer/` is included.

1. Repo page → **Code → Codespaces → Create codespace on main**.
2. In the terminal: `python dashboard.py`
3. Open the **Ports** tab, right-click port **5000** → **Port Visibility → Public**.

You get a live `https://<codespace>-5000.app.github.dev` URL that runs the real
scanner. The URL lives only while the codespace runs, and Codespaces has a
monthly free quota - stop it when you're done.

---

## Option 2 - a public URL from your own machine (no account at all)

Run AppMap locally and expose it through a tunnel. Nothing to sign up for:

```bash
python dashboard.py            # terminal 1

# terminal 2 - pick one:
cloudflared tunnel --url http://localhost:5000     # Cloudflare quick tunnel
ssh -R 80:localhost:5000 nokey@localhost.run       # localhost.run over SSH
```

Both print a public `https://…` URL instantly. It lives only while the tunnel
process runs. This is ideal for a quick demo or showing it to someone.

---

## Option 3 - Fly.io (Docker, free allowance)

A `fly.toml` is included.

```bash
fly launch --no-deploy     # links/creates the app, reads fly.toml
fly deploy
```

Fly builds the Dockerfile and gives you `https://<app>.fly.dev`. Set
`primary_region` in `fly.toml` to the region nearest you.

---

## Option 4 - Railway

A `railway.json` is included; Railway detects the Dockerfile.

1. New Project → **Deploy from GitHub repo** → pick `appmap`.
2. Railway builds the Dockerfile and assigns a public domain (Settings →
   Networking → Generate Domain).

The Dockerfile honours the platform's `$PORT`, so no extra config is needed.

---

## Option 5 - Hugging Face Spaces (Docker SDK, free, public URL)

1. Create a new Space → SDK: **Docker** → Blank.
2. Add these files to the Space repo: `Dockerfile`, `dashboard.py`,
   `appmap.py`, `dns_analyzer.py`, `http_analyzer.py`, `tls_analyzer.py`,
   `graph.py`, `exporter.py`, `requirements.txt`.
3. The Space's own `README.md` needs this front-matter at the top:

   ```yaml
   ---
   title: AppMap
   emoji: 🛰️
   colorFrom: blue
   colorTo: indigo
   sdk: docker
   app_port: 8000
   ---
   ```

   (Keep this file in the Space, separate from the project README.)
4. Commit. The Space builds and serves a public `https://<user>-<space>.hf.space`
   URL. Free Spaces sleep after inactivity.

---

## Option 6 - Any VPS or Docker host

```bash
docker build -t appmap .
docker run -d -p 8000:8000 --name appmap appmap
```

Put it behind nginx/Caddy for TLS. Works on any VPS (DigitalOcean, Hetzner,
Lightsail, Oracle Cloud free tier, ...).

---

## A note on outbound network access

AppMap makes outbound requests on behalf of whoever submits a target, so the
host must allow outbound **DNS (UDP/53)** and **TCP (443)**. Some free/PaaS
platforms restrict raw DNS or outbound sockets; there, the HTTP step still works
through their proxy but DNS/TLS may report "unavailable". A VPS, a container
host with open egress, Codespaces, or a local tunnel all work fully.

## Security

A public deployment is reachable by anyone. Keep the authorisation notice in
place, and consider adding a simple access gate (HTTP basic auth or an allowlist)
if you don't intend it to be fully open.
