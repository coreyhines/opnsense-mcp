# Deploying OPNsense MCP (container + quadlet)

Canonical spec: **[`docs/CENTRALIZED_DEPLOY_SPEC.md`](../docs/CENTRALIZED_DEPLOY_SPEC.md)** (install, uninstall, manual steps).

**Install (Linux, root):** `sudo bash deploy/install.sh` or `curl -fsSL 'https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/raw/feat/centralized-deploy/deploy/install.sh' | sudo bash` (use `main` in the URL after `deploy/` lands there).

**Podman quadlet options** (pod name, network, static IP, DNS, container names, TLS cert path): set env vars — see **`docs/CENTRALIZED_DEPLOY_SPEC.md`** (`OPNSENSE_MCP_POD_NAME`, `OPNSENSE_MCP_NETWORK`, …). Prompts run only when stdin is a TTY (`curl|bash` is non-interactive; use `sudo env … bash` or edit **`*.pod` / `*.container`** under **`/etc/containers/systemd/`** after install).

## TLS (read first)

**HTTPS is provided by a reverse proxy**, not by `mcp-proxy` inside the image. Host PEMs are expected under **`/opt/certs/wild`**. See **[TLS.md](TLS.md)**, **`caddyfile.example`**, and **`opnsense-mcp-caddy.container.example`**.

## Image

Build from the repository root (uses the repo-root `.dockerignore`):

```bash
podman build -f deploy/Containerfile -t localhost/opnsense-mcp:test .
```

The container runs **`mcp-proxy`** in SSE→stdio mode against `python3 main.py`, listening on **8765** (HTTP). With TLS, clients use **`https://opnsense-mcp.freeblizz.com/sse`** via Caddy (DNS + `deploy/caddyfile.example`).

## Secrets

Copy `environment.example` to **`/opt/containerdata/opnsense-mcp/environment`** (same dir as the install root volume), `chmod 600`, set `OPNSENSE_*` and `MCP_SECRET_KEY`. Quadlet: `EnvironmentFile=` that path and mount `/opt/containerdata/opnsense-mcp` read-only.

## Quadlet order

Quadlet files are written **directly under** **`/etc/containers/systemd/`** (flat layout: Podman before 4.7 does not scan subdirectories). Filenames use an **`opnsense-mcp-`** prefix (pod + app + caddy).

1. **`opnsense-mcp.pod`** — **`PodName=opnsense-mcp-pod`** (default); quadlet appends **`-pod`** to the stem → generated unit **`opnsense-mcp-pod.service`**; optional **`Network=`** / **`IP=`** (e.g. macvlan); no **`PublishPort`** by default.
2. **`opnsense-mcp-app.container`** — app (**`ContainerName=opnsense-mcp-app`**); **`Pod=opnsense-mcp.pod`**; unit **`opnsense-mcp-app.service`**.
3. **`$INSTALL_ROOT/Caddyfile`** (default **`/opt/containerdata/opnsense-mcp/Caddyfile`**) from `caddyfile.example`, then **`opnsense-mcp-caddy.container`** (**`ContainerName=opnsense-mcp-caddy`**, unit **`opnsense-mcp-caddy.service`**).
