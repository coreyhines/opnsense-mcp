# OPNsense MCP Project Guide

Developer-focused orientation for current architecture and runtime paths.

## Runtime Model

The project supports two operational modes using the same MCP tool implementation:

- `STDIO`: local MCP process (`mcp_start.sh` or `python main.py`) for IDE clients.
- `SSE`: centralized network service via `mcp-proxy` (`SSE -> stdio`) behind TLS.

`STDIO` is the default development path. `SSE` is the deployment path.

## Core Architecture

- Entry points:
  - `main.py` (local stdio launcher)
  - `opnsense_mcp/server.py` (server implementation used by launchers/proxy)
- Tool implementation: `opnsense_mcp/tools/`
- OPNsense API client: `opnsense_mcp/utils/api_optimized.py`
- Environment loading: `~/.env` plus deploy paths (`$OPNSENSE_MCP_INSTALL_ROOT/environment`, `OPNSENSE_ENV_FILE`); see `opnsense_mcp/utils/env.py`.

## Local Dev Setup

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
cp examples/.env.example ~/.env
```

Run tests/lint:

```bash
uv run pytest tests/
uv run ruff check .
uv run ruff format .
```

## Deployment Docs

- Canonical centralized spec: [`../CENTRALIZED_DEPLOY_SPEC.md`](../CENTRALIZED_DEPLOY_SPEC.md)
- Deploy quick notes: [`../../deploy/README.md`](../../deploy/README.md)
- TLS details: [`../../deploy/TLS.md`](../../deploy/TLS.md)

## Security

- Keep all secrets in env files or secret stores, never in source.
- Do not commit credentials.
- For centralized mode, keep TLS certs on host and mount read-only.
