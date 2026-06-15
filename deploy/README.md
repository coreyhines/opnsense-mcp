# Deploying OPNsense MCP (Streamable HTTP Mode)

This folder is for the centralized `Streamable HTTP` deployment path.

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
https://<your-hostname>/mcp
```

## Runtime Summary

- App container runs FastMCP natively (`python3 main.py --transport streamable-http --host 0.0.0.0 --port 8765`).
- App listens on HTTP `8765` inside the pod/network; MCP endpoint is `/mcp` (Streamable HTTP, MCP spec 2025-03-26).
- TLS is terminated by Caddy (`deploy/TLS.md`).

## Required Follow-ups

- Configure secrets in `environment` (see `environment.example`).
- Configure certs and hostname in [`TLS.md`](TLS.md).
- Adjust quadlet variables only if defaults do not match your host network.
