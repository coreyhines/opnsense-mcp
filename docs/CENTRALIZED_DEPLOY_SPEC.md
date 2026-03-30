# Centralized OPNsense MCP — deploy spec (canonical)

Single planning/implementation reference for the **network service** path. **IDE / stdio** stays the default dev story; this doc does not replace local `python main.py`.

---

## Goals

- **One MCP core** (same tools, same Python package) for stdio and centralized use.
- **Centralized:** long-lived service, **Linux amd64** only for now (no macOS/ARM in scope).
- **Installer:** **`curl | bash`** loading the script from **raw on `main`** (treat merges as production).
- **Source / build:** **GitLab is primary** for clone or archive URLs; **build the image on the host** from this repo’s `deploy/Containerfile` (no registry pull required for v1).
- **Podman** is the blessed server path (**rootful**, **UID 1000** convention for volume ownership where it matters).
- **Docker:** supported as a first-class alternative; **do not** force Podman on Docker users.
- **TLS:** **Caddy** in front; **TLS by default**; works with **real CA PEMs** or **self-signed** (paths to `fullchain` + `privkey` — client trust is the operator’s problem for self-signed).
- **Secrets:** never in images; host files only.
- **Install:** **idempotent** (safe to re-run).
- **Uninstall:** script plus **manual** steps documented.

---

## Architecture

| Piece | Role |
|--------|------|
| `mcp-proxy` | **SSE → stdio**; listens **HTTP** on **8765** inside the app container; spawns `python3 main.py`. |
| App container | Built from **`deploy/Containerfile`** (local build). |
| **Caddy** | **TLS termination**; mounts host PEMs (e.g. **`/opt/certs/wild`**); reverse-proxies to **`http://127.0.0.1:8765`**. |
| Clients | **`https://opnsense-mcp.freeblizz.com/sse`** (after TLS; DNS A/AAAA to pod IP — see **`deploy/TLS.md`**). |

**Why Caddy:** `mcp-proxy` has **no** server-side TLS flags; HTTPS is always **in front**.

---

## Environment file (data volume, not `/etc`)

- **Host path:** **`$OPNSENSE_MCP_INSTALL_ROOT/environment`** (default **`/opt/containerdata/opnsense-mcp/environment`**). Keep secrets on the **volume** under **`/opt/containerdata/opnsense-mcp`**, not under `/etc`.
- **Quadlet:** `EnvironmentFile=` and **`Environment=OPNSENSE_MCP_INSTALL_ROOT=...`**; **`Volume=`** mounts the data dir read-only at the same path in-container so `load_opnsense_env()` sees the file.
- **`load_opnsense_env()`** resolves **`$OPNSENSE_MCP_INSTALL_ROOT/environment`** (default root **`/opt/containerdata/opnsense-mcp`**), then **`OPNSENSE_ENV_FILE`**, then home-directory dotenv files starting with **`~/.env`** (see `tests/test_opnsense_env.py` and `opnsense_mcp/utils/env.py`).

---

## Installer (v1)

- **Scripts:** `deploy/install.sh`, `deploy/uninstall.sh` (run as **root**).
- **Default clone URL (GitLab):** `https://gitlab.freeblizz.com/coreyhines/opensense-mcp.git` — override with **`OPNSENSE_MCP_REPO_URL`**.
- **Default git ref:** **`feat/centralized-deploy`** (until `deploy/` is merged to **`main`**, override with **`OPNSENSE_MCP_GIT_REF=main`**).
- **Install root:** **`OPNSENSE_MCP_INSTALL_ROOT`** (default **`/opt/containerdata/opnsense-mcp`**); checkout lives at **`$INSTALL_ROOT/src`**.
- **Podman (default):** clones/updates repo, **`podman build`**, installs **`<PodName>.pod`** (default **`opnsense-mcp-pod.pod`** when **`OPNSENSE_MCP_POD_NAME`** is unset or **`opnsense-mcp-pod`**), **`opnsense-mcp-app.container`**, and **`opnsense-mcp-caddy.container`** **directly under** **`/etc/containers/systemd/`** (not in a subdirectory: Podman before **4.7** does not recurse, so nested paths never produce units). Creates **`$INSTALL_ROOT/environment`** and **`$INSTALL_ROOT/Caddyfile`** if missing, then **`systemctl enable`** on those paths (or **`start`** if the distro rejects `enable` on generated quadlet services — see Red Hat / Podman quadlet notes). Re-run install removes prior copies under **`/etc/containers/systemd/opnsense-mcp/`** to avoid duplicate quadlets on 4.7+.
- **Docker:** `deploy/install.sh --runtime docker` runs **`docker compose -p opnsense-mcp -f deploy/docker-compose.yml up -d --build`** from the checkout.
- **One-liner (raw script on the branch that contains `deploy/`):**
  ```bash
  curl -fsSL 'https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/raw/feat/centralized-deploy/deploy/install.sh' | sudo bash
  ```
  If you must pull `main` from Git but `main` does not include `deploy/` yet, set **`OPNSENSE_MCP_GIT_REF=feat/centralized-deploy`** so the clone has the Containerfile and quadlet examples.
- **Uninstall:** `sudo bash deploy/uninstall.sh` (from checkout) or copy the script to the host. **Docker:** `--runtime docker`. Optional **`--purge-env`** removes **`$INSTALL_ROOT/environment`**.

### Manual uninstall (no script)

- **Podman:** `systemctl disable --now opnsense-mcp-caddy.service opnsense-mcp-app.service opnsense-mcp-pod.service opnsense-mcp.service caddy-opnsense-mcp.service` (also **`opnsense-mcp-pod-pod.service`**, **`pod-opnsense-mcp.service`**, **`pod-opnsense-mcp-pod.service`** for legacy installs); remove **`opnsense-mcp.pod`**, **`opnsense-mcp-pod.pod`**, **`opnsense-mcp-app.container`**, **`opnsense-mcp-caddy.container`** from **`/etc/containers/systemd/`** and any copies under **`/etc/containers/systemd/opnsense-mcp/`**; `systemctl daemon-reload`; `podman rmi localhost/opnsense-mcp:latest` if desired.
- **Docker:** from the git checkout, `docker compose -p opnsense-mcp -f deploy/docker-compose.yml down --rmi local`.
- Remove or edit **`/opt/containerdata/opnsense-mcp/environment`** (or **`$INSTALL_ROOT/environment`**), **`$INSTALL_ROOT/Caddyfile`**, and the clone under **`/opt/containerdata/opnsense-mcp/src`** (default) as needed.

### Quadlet variables (Podman)

Set via **environment** before running `install.sh`, add the same keys to **`$INSTALL_ROOT/environment`** (the installer **sources** that file before generating quadlets so **`curl|bash`** picks them up without `export`), or answer prompts when **stdin is a TTY** (not when using `curl|bash`).

| Variable | Role |
|----------|------|
| `OPNSENSE_MCP_POD_NAME` | **`[Pod]` `PodName=`** (default **`opnsense-mcp-pod`**). The quadlet file is always **`opnsense-mcp.pod`**; quadlet appends **`-pod`** to the stem → generated unit **`opnsense-mcp-pod.service`**. **`Pod=`** in containers references **`opnsense-mcp.pod`**. |
| `OPNSENSE_MCP_CONTAINER_NAME` | App **`ContainerName=`** (default **`opnsense-mcp-app`**; quadlet **`opnsense-mcp-app.container`** → **`opnsense-mcp-app.service`**). |
| `OPNSENSE_MCP_CADDY_CONTAINER_NAME` | Caddy **`ContainerName=`** (default **`opnsense-mcp-caddy`**; quadlet **`opnsense-mcp-caddy.container`** → **`opnsense-mcp-caddy.service`**). |
| `OPNSENSE_MCP_NETWORK` | Podman `Network=` on the **pod** (optional). |
| `OPNSENSE_MCP_IP` | Podman `IP=` static IPv4 on the **pod** (optional). |
| `OPNSENSE_MCP_IP6` | Podman `IP6=` static IPv6 on the **pod** (optional). |
| `OPNSENSE_MCP_DNS` | Space-separated resolvers → multiple `DNS=` lines on the **pod** (optional). |
| `OPNSENSE_MCP_TLS_CERTS` | Host directory with PEMs, mounted at `/opt/certs/wild` in containers (default `/opt/certs/wild`). |

The installer does **not** set **`PublishPort`** on the pod (typical **macvlan** / static **`IP=`** setups expose **443** and **8765** on the pod’s address instead of mapping host ports). Both containers set **`Pod=<PodName>.pod`** (default **`opnsense-mcp-pod.pod`**). Add **`PublishPort=`** in the generated **`<PodName>.pod`** only if you use bridge/NAT and need host port forwarding.

**Example (non-interactive):**

```bash
sudo env OPNSENSE_MCP_NETWORK=net-10 OPNSENSE_MCP_IP=10.0.10.50 OPNSENSE_MCP_TLS_CERTS=/opt/certs/wild bash deploy/install.sh
```

### Install troubleshooting (strongpod / quadlet)

- **Diverged git clone:** the installer **`git reset --hard origin/<branch>`** so `/opt/containerdata/.../src` always matches GitLab (no lingering local commits).
- **`Failed to enable unit: ... transient or generated`:** quadlet-generated `.service` units sometimes cannot be enabled by name; the script enables the **`.container`** file path, then **`start`**, as a fallback.
- **Unit not found after install:** (1) Quadlet files must live **directly in** **`/etc/containers/systemd/`** on Podman before **4.7** (subdirectories ignored — [containers/podman#20236](https://github.com/containers/podman/issues/20236)). (2) Quadlet names `.pod` units as **`<stem>-pod.service`** (appends `-pod`), **not** `pod-<stem>.service`: **`opnsense-mcp.pod`** → **`opnsense-mcp-pod.service`**. Container **`Requires=`** must match. (3) **`systemctl daemon-reload`**; ensure **`podman-quadlet`** is installed. (4) Dry-run: `sudo /usr/lib/systemd/system-generators/podman-system-generator --dryrun 2>&1 | grep opnsense-mcp`.

---

## Security (summary)

- Prefer exposing **HTTPS (443)** to clients; keep **8765** on the pod network only unless you intentionally need plain HTTP from outside the pod.
- **Certificates:** read-only mount; rotate on host; reload Caddy.

---

## Related files in repo

| Path | Purpose |
|------|--------|
| `deploy/Containerfile` | Image definition (local build). |
| `deploy/TLS.md` | TLS/Caddy details. |
| `deploy/caddyfile.example` | Caddy vhost + PEM paths. |
| `deploy/opnsense-mcp.pod.example`, `deploy/opnsense-mcp-app.container.example`, `deploy/opnsense-mcp-caddy.container.example` | Quadlet examples (pod + containers). |
| `deploy/environment.example` | Variable template. |
| `deploy/install.sh` | Root installer (`curl \| bash` entry). |
| `deploy/uninstall.sh` | Removes quadlet units or Docker Compose stack. |
| `deploy/docker-compose.yml` | Docker Compose stack (Caddy + app). |

---

## Deferred / later

- **CI push** to a container registry and **pull-only** install (optional; not v1).
- **Option B** (native HTTP in-process) — out of scope unless revisited.

---

## Revision

Update this file when decisions change; avoid duplicating the same content in other docs.
