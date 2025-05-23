# OPNsense MCP Server

This server provides OPNsense API functionality through a Model Context Protocol (MCP) interface (JSON-RPC over stdio), not HTTP REST endpoints.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your OPNsense credentials in a `.env` file (in the project root) or in `~/.opnsense-env`:

```env
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
OPNSENSE_API_HOST=your.opnsense.host
MCP_SECRET_KEY=your_jwt_secret_key
```

You can use a `.env` file in the project root, or set these in your shell environment. The server will automatically load from `~/.opnsense-env` if present.

## Running the Server

Start the server with:
```bash
python main.py
```

## IDE Integration

- The server is designed for integration with Cursor IDE and other MCP-compatible IDEs.
- All secrets should be stored in `.env` files or `~/.opnsense-env`, not in code.
- If using an IDE that does not support all dependencies, ensure your environment is activated or install missing packages.

#### Example Environment Setup

```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env
```

## Tool Discovery and Invocation

- Tools are discovered and invoked via the MCP protocol (JSON-RPC over stdio), not via HTTP endpoints.
- The server will advertise available tools (e.g., ARP, DHCP, firewall, system status) to the IDE or MCP client.
- Tool invocation is handled by sending a JSON-RPC request with the tool name and arguments.

## Authentication

- The server uses JWT-based authentication for internal operations. All secrets and keys must be stored in `.env` or a secure store.

## Available Tools (Examples)

- **ARP Table Tool**: Retrieves both IPv4 ARP and IPv6 NDP tables from OPNsense.
- **DHCP Lease Tool**: Shows DHCPv4 and DHCPv6 lease tables.
- **System Status Tool**: Gets system status information including CPU, memory, and filesystem usage.
- **Firewall Rules Tool**: Manages firewall rules on OPNsense.
- **LLDP Tool**: Shows LLDP neighbor table (if supported by the API).

## Troubleshooting

- **Import errors**: Ensure all dependencies are installed
- **Port conflicts**: Change the port in your config or launch arguments
- **Missing dependencies**: Install the missing package
- **Authentication fails**: Check your environment and credentials

## Verification

- All core functionality and tests should pass after cleanup
- Project is ready for further development

## Notes

- For production, always use the main server with all dependencies installed
- The server communicates via MCP protocol (JSON-RPC over stdio), not HTTP REST endpoints
- Podman is the preferred container runtime
- Use vi/vim for editing; VS Code is supported as an IDE only
- Always clean up temporary and test files (use `tmp_` or `test_` prefixes)
- Store all secrets in `.env` or a secure store, never in code
