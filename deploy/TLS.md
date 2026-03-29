# TLS for the centralized MCP service

The SSE listener run by **`mcp-proxy`** is **HTTP only** (there are no `--cert` / `--key` flags for the server side). Production HTTPS should use **TLS termination in front** of the app container.

## Host certificate layout (this deployment)

Wildcard (or site) PEM files live on the host at:

**`/opt/certs/wild/`**

Use **read-only** mounts into the TLS container (see `opnsense-mcp-caddy.container.example`). Typical filenames (adjust to match your PKI):

| File | Role |
|------|------|
| `fullchain.pem` | Server certificate + intermediates |
| `privkey.pem` | Private key |

If your files use different names, update the `tls` directive in `caddyfile.example` or add symlinks on the host.

## DNS

Create a **DNS A** (or **AAAA**) record so clients resolve the MCP host to the pod:

| Name | Type | Value |
|------|------|--------|
| **`opnsense-mcp.freeblizz.com`** | A (or AAAA) | Pod / macvlan IP (e.g. `10.0.10.3`) |

The default **`deploy/caddyfile.example`** uses that hostname in the site block. Your certificate must include **`opnsense-mcp.freeblizz.com`** or a **wildcard** `*.freeblizz.com` that covers it.

MCP clients use **`https://opnsense-mcp.freeblizz.com/sse`** (after TLS trust is satisfied).

## Recommended stack

1. **`opnsense-mcp-app.container`** — `mcp-proxy` + `main.py`, listens on **8765** inside the pod (reachable from Caddy on the pod network; no host **`PublishPort`** in the default pod quadlet).
2. **`opnsense-mcp-caddy.container`** — **Caddy** in the same pod as the app, TLS on **443**, reverse proxy to `http://127.0.0.1:8765`. Mount `/opt/certs/wild` read-only and keep **`$INSTALL_ROOT/Caddyfile`** (default **`/opt/containerdata/opnsense-mcp/Caddyfile`**) on the host, mounted into the container as `/etc/caddy/Caddyfile`.

The default **`deploy/caddyfile.example`** (copied on first install) uses **manual TLS** only (`tls` with PEM paths) — **no automatic Let’s Encrypt**. The site name **`opnsense-mcp.freeblizz.com`** matches the intended DNS record; change it if you use another FQDN.

Clients use **`https://opnsense-mcp.freeblizz.com/sse`** (or your edited hostname), with trust depending on your cert (wildcard/SAN).


## Operations

- Renew or replace PEMs under `/opt/certs/wild` and reload Caddy (`systemctl reload …` for the Caddy unit) when certificates rotate.
- Keep firewall rules so **only** 443 (and SSH/admin as needed) face untrusted networks from the pod’s IP; avoid exposing **8765** outside the pod unless you intentionally want plain HTTP.

## Alternatives

Any reverse proxy (nginx, Traefik, HAProxy) with TLS and `proxy_pass` to `http://127.0.0.1:8765` is equivalent; Caddy is documented here as a minimal two-file example.
