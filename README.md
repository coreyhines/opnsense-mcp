# OPNsense MCP Server

MCP server for OPNsense firewall operations (ARP, DHCP, logs, rules, interfaces, system status, packet capture).

Use one of two deployment modes:

- `STDIO` (local): best for Cursor/Claude Code/Continue running the server process directly.
- `SSE` (centralized): best for shared, long-lived service over HTTPS.

## Quick Start

### 1) Local setup (required for both modes)

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
cp examples/.opnsense-env ~/.opnsense-env
```

Edit `~/.opnsense-env`:

```env
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
OPNSENSE_FIREWALL_HOST=your.firewall.host
MCP_SECRET_KEY=replace_me
```

### 2) Choose mode

#### Mode A: `STDIO` (local IDE/client)

Configure your MCP client to launch `mcp_start.sh`:

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

See full guide: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).

#### Mode B: `SSE` (centralized service)

Run the Linux installer (Podman + quadlet + Caddy TLS):

```bash
sudo bash deploy/install.sh
```

Clients connect to:

```text
https://<your-hostname>/sse
```

See deployment docs:

- [`docs/CENTRALIZED_DEPLOY_SPEC.md`](docs/CENTRALIZED_DEPLOY_SPEC.md)
- [`deploy/README.md`](deploy/README.md)
- [`deploy/TLS.md`](deploy/TLS.md)

## What Is Available

Primary tools:

- Discovery: `arp`, `dhcp`, `lldp`
- Monitoring: `system`, `get_logs`, `packet_capture`
- Firewall rules: `fw_rules`, `mkfw_rule`, `rmfw_rule`, `ssh_fw_rule`
- Interfaces: `interface_list`

Full reference: [`docs/REFERENCE/FUNCTION_REFERENCE.md`](docs/REFERENCE/FUNCTION_REFERENCE.md)

## Documentation Map

- Start here: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- Claude Code specifics: [`docs/CLAUDE_CODE_INTEGRATION.md`](docs/CLAUDE_CODE_INTEGRATION.md)
- Centralized SSE spec: [`docs/CENTRALIZED_DEPLOY_SPEC.md`](docs/CENTRALIZED_DEPLOY_SPEC.md)
- Contributor guide: [`docs/DEVELOPMENT/CONTRIBUTING.md`](docs/DEVELOPMENT/CONTRIBUTING.md)
