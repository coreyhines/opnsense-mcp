# Deploying OPNsense MCP (Streamable HTTP Mode)

Centralized Podman quadlet deployment with **Caddy** TLS and a pinned image from **`hub.freeblizz.com`**.

For local IDE usage (`STDIO`), use the root quickstart instead:
[`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md).

## Fast path

Canonical reference:
[`../docs/CENTRALIZED_DEPLOY_SPEC.md`](../docs/CENTRALIZED_DEPLOY_SPEC.md)

On the host (as root):

```bash
sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh
```

GitLab CI on `main` pushes `hub.freeblizz.com/opnsense-mcp:<version>-dev.<sha>` (version from `pyproject.toml`).
Git tag `v1.0.0` publishes `hub.freeblizz.com/opnsense-mcp:1.0.0`.

After TLS and DNS are in place, clients connect to:

```text
https://opnsense-mcp.freeblizz.com/mcp
```

## Image modes

| Mode | Command |
|------|---------|
| Pull from registry (default) | `sudo bash deploy/install.sh` (auto tag) or `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh` |
| Refresh quadlets only | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --skip-image` |
| Local dev build | `sudo OPNSENSE_MCP_IMAGE_TAG=dev-test bash deploy/install.sh --build-local` |
| Build and push to registry | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --build-push` |

`:latest` is rejected. Tags must be a git short SHA from CI or an explicit semver.

## Runtime summary

- App container runs FastMCP natively (`python3 main.py --transport streamable-http --host 0.0.0.0 --port 8765`).
- App listens on HTTP `8765` inside the pod/network; MCP endpoint is `/mcp`.
- TLS is terminated by Caddy (`deploy/TLS.md`).

## Required follow-ups

- Configure secrets in `environment` (see `environment.example`).
- Configure certs and hostname in [`TLS.md`](TLS.md).
- Set `OPNSENSE_MCP_IMAGE_TAG` to a tag that exists in `hub.freeblizz.com`.
