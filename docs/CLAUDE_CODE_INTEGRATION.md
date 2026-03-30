# Claude Code Integration

Fast path for using this MCP server from Claude Code.

## Recommended: STDIO in Claude Code

1. Complete base setup from [`GETTING_STARTED.md`](GETTING_STARTED.md).

1. Add this server entry to your Claude Code MCP config (`mcpServers` section):

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

1. Reload/restart Claude Code.

1. Validate with:

```text
show system status
```

## Optional: Centralized SSE Backend

If you deploy centralized mode (`deploy/install.sh`), use:

```text
https://<your-hostname>/sse
```

Use SSE only if your Claude Code MCP configuration supports remote SSE servers in your environment. Keep `STDIO` as fallback.

## Troubleshooting

- `mcp_start.sh` not executable:
  `chmod +x /absolute/path/to/opnsense-mcp/mcp_start.sh`
- Credentials missing: verify `~/.env`
- SSE fails: verify cert trust, DNS, and Caddy config (`../deploy/TLS.md`)

## Related Docs

- Main quickstart: [`GETTING_STARTED.md`](GETTING_STARTED.md)
- Deployment spec: [`CENTRALIZED_DEPLOY_SPEC.md`](CENTRALIZED_DEPLOY_SPEC.md)
- TLS details: [`../deploy/TLS.md`](../deploy/TLS.md)
