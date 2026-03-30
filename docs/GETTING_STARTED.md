# Getting Started

This guide is optimized for first run.

## Choose Your Mode

- `STDIO`: local process started by your MCP client (Cursor, Claude Code, Continue).
- `SSE`: centralized network service over HTTPS for shared access.

If you are unsure, start with `STDIO`.

## Prerequisites

- Python 3.12+
- `uv`
- OPNsense API key/secret with required permissions
- Network reachability to the firewall host

## Base Setup (both modes)

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
cp examples/.env.example ~/.env
```

Set credentials in `~/.env`:

```env
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
OPNSENSE_FIREWALL_HOST=your.firewall.host
MCP_SECRET_KEY=replace_me
```

## Mode 1: STDIO

Use `mcp_start.sh` in your MCP client config.

### Cursor

File: `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/absolute/path/to/opnsense-mcp/mcp_start.sh"],
      "cwd": "/absolute/path/to/opnsense-mcp"
    }
  }
}
```

### Claude Code

File: your Claude Code MCP config file (`mcpServers` section)

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/absolute/path/to/opnsense-mcp/mcp_start.sh"],
      "cwd": "/absolute/path/to/opnsense-mcp"
    }
  }
}
```

### Continue

File: `~/.continue/mcp.json`

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/absolute/path/to/opnsense-mcp/mcp_start.sh"],
      "cwd": "/absolute/path/to/opnsense-mcp"
    }
  }
}
```

Restart your client after changes.

## Mode 2: SSE (Centralized)

For long-lived shared service on Linux (Podman + quadlet + Caddy):

```bash
sudo bash deploy/install.sh
```

Client endpoint:

```text
https://<your-hostname>/sse
```

Read before production:

- [`docs/CENTRALIZED_DEPLOY_SPEC.md`](CENTRALIZED_DEPLOY_SPEC.md)
- [`../deploy/README.md`](../deploy/README.md)
- [`../deploy/TLS.md`](../deploy/TLS.md)

## Fast Validation

- `STDIO`: start your client and run a simple prompt: `show system status`
- `SSE`: verify `/sse` is reachable from the MCP client and run the same prompt

## Troubleshooting

- Missing Python deps: `uv pip install -r requirements.txt`
- Credentials not loading: verify `~/.env` values and file permissions (`chmod 600 ~/.env`)
- Script permissions: `chmod +x mcp_start.sh`
- SSE TLS issues: check cert paths and hostname in `deploy/TLS.md`

## Next Docs

- Tool reference: [`REFERENCE/FUNCTION_REFERENCE.md`](REFERENCE/FUNCTION_REFERENCE.md)
- Claude Code specifics: [`CLAUDE_CODE_INTEGRATION.md`](CLAUDE_CODE_INTEGRATION.md)
- Examples: [`EXAMPLES/BASIC_EXAMPLES.md`](EXAMPLES/BASIC_EXAMPLES.md)
