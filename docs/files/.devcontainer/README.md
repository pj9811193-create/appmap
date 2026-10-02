# Run AppMap in GitHub Codespaces (no Render, GitHub-native)

1. On the repo page: **Code → Codespaces → Create codespace on main**.
   Dependencies install automatically from `requirements.txt`.
2. In the Codespaces terminal:

   ```bash
   python dashboard.py
   ```

3. A notification offers to open the forwarded port. Open the **Ports** tab,
   right-click port **5000**, and set **Port Visibility → Public** if it isn't
   already. The forwarded `https://<codespace>-5000.app.github.dev` URL is a
   live, working AppMap scanner (real DNS/HTTP/TLS), reachable by anyone you
   share it with.

Codespaces includes a monthly free quota; stop the codespace when you're done
to conserve it. Note that the public URL only lives while the codespace is
running.
