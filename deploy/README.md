# Deploying OPNsense MCP (SSE Mode)

This folder is for the centralized `SSE` deployment path.

For local IDE usage (`STDIO`), use the root quickstart instead:
[`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md).

## Fast Path

Canonical reference:
[`../docs/CENTRALIZED_DEPLOY_SPEC.md`](../docs/CENTRALIZED_DEPLOY_SPEC.md)

Install on Linux as root:

```bash
sudo bash deploy/install.sh
```

After TLS and DNS are in place, clients connect to:

```text
https://<your-hostname>/sse
```

## Runtime Summary

- App container runs `mcp-proxy` in `SSE -> stdio` mode against `python3 main.py`.
- App listens on HTTP `8765` inside the pod/network.
- TLS is terminated by Caddy (`deploy/TLS.md`).

## Required Follow-ups

- Configure secrets in `environment` (see `environment.example`).
- Configure certs and hostname in [`TLS.md`](TLS.md).
- Adjust quadlet variables only if defaults do not match your host network.
