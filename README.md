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
- If using an IDE that does not support all dependencies, activate your Python virtual environment (venv) or install any missing packages as needed.

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

## Available Tools

The following tools are typically available via the MCP server (actual availability may depend on your OPNsense configuration):

- **arp**: Retrieves both IPv4 ARP and IPv6 NDP tables from OPNsense.
- **dhcp**: Shows DHCPv4 and DHCPv6 lease tables.
- **system**: Gets system status information including CPU, memory, and filesystem usage.
- **firewall**: Lists firewall rules on OPNsense.
- **lldp**: Shows LLDP neighbor table (if supported by the OPNsense API).

> **Note:** Tool names and availability may change based on your OPNsense version and configuration. Use your IDE's tool discovery feature to see the current list.

## Example MCP Tool Output

Here are some example queries and anonymized responses you might see when interacting with the MCP server via a chat interface:

---

**User:** Tell me about hostA.

**MCP Response:**
Host: `hostA`
IP Address: `192.168.1.42`
MAC Address: `AA:BB:CC:DD:EE:01`
DHCP Lease: Active (expires in 2 hours)
ARP Entry: Present
LLDP Neighbor: Not detected

---

**User:** What is the hostname for this MAC address: `AA:BB:CC:DD:EE:02`?

**MCP Response:**
MAC Address: `AA:BB:CC:DD:EE:02`
Hostname: `printer-01`
IP Address: `192.168.1.55`
DHCP Lease: Active (expires in 1 day)
ARP Entry: Present

---

**User:** List all devices currently on the network.

**MCP Response:**
1. Hostname: `hostA`, IP: `192.168.1.42`, MAC: `AA:BB:CC:DD:EE:01`
2. Hostname: `printer-01`, IP: `192.168.1.55`, MAC: `AA:BB:CC:DD:EE:02`
3. Hostname: `laptop-guest`, IP: `192.168.1.77`, MAC: `AA:BB:CC:DD:EE:03`

---

**User:** Show me the current system status.

**MCP Response:**
CPU Usage: 12%
Memory Usage: 1.2 GB / 8 GB
Filesystem Usage: 40% used
Uptime: 5 days, 3 hours

---

**User:** Who is using IP address `192.168.1.77`?

**MCP Response:**
IP Address: `192.168.1.77`
Hostname: `laptop-guest`
MAC Address: `AA:BB:CC:DD:EE:03`
DHCP Lease: Expired
ARP Entry: Present

---

**User:** Show me recent firewall logs for host `hostA`.

**MCP Response:**
Recent firewall log entries for `hostA` (`192.168.1.42`):

| Time                | Action | Source IP      | Destination IP | Protocol | Port |
|---------------------|--------|---------------|---------------|----------|------|
| 2024-06-20 14:32:10 | Block  | 192.168.1.42  | 8.8.8.8       | UDP      | 53   |
| 2024-06-20 14:31:55 | Pass   | 192.168.1.42  | 192.168.1.1   | TCP      | 443  |
| 2024-06-20 14:30:02 | Pass   | 192.168.1.42  | 10.0.0.5      | TCP      | 22   |

---

**User:** Show LLDP neighbors.

**MCP Response:**
No LLDP neighbors detected.

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
