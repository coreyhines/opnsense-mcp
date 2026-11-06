![opnsense-mcp](assets/logo.png)

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

## Optional: Centralized HTTP Backend

If you deploy centralized mode (`deploy/install.sh`), use:

```text
https://<your-hostname>/mcp
```

This is streamable HTTP, with `Authorization: Bearer <MCP_SECRET_KEY>`:
`claude mcp add --transport http opnsense https://<your-hostname>/mcp --header "Authorization: Bearer <key>"`.
There is no `/sse` endpoint. Keep `STDIO` as fallback.

## Troubleshooting

- `mcp_start.sh` not executable:
  `chmod +x /absolute/path/to/opnsense-mcp/mcp_start.sh`
- Credentials missing: verify `~/.env`
- HTTP connection fails: verify cert trust, DNS, the bearer key, and Caddy config (`../deploy/TLS.md`)

## Related Docs

- Main quickstart: [`GETTING_STARTED.md`](GETTING_STARTED.md)
- Deployment spec: [`CENTRALIZED_DEPLOY_SPEC.md`](CENTRALIZED_DEPLOY_SPEC.md)
- TLS details: [`../deploy/TLS.md`](../deploy/TLS.md)
