# OPNsense MCP Server

This server provides OPNsense API functionality through a Model Context Protocol (MCP) interface.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your OPNsense credentials in `vars/key.yaml`:
```yaml
api_key: "your_api_key"
api_secret: "your_api_secret"
firewall_host: "your.opnsense.host"
```

## Project Structure

The project has been thoroughly cleaned up and organized:
- All redundant and legacy files have been removed
- Consistent naming scheme has been established
- No more `_new.py` files - all functionality in standard files
- Streamlined test suite with cleanup capabilities

See `docs/cleanup_summary.md` for details on the cleanup process.

## Project Maintenance

This project follows strict cleanup practices. When working with this code:

- Use vi/vim as the editor of choice
- Always clean up temporary and test files
- Run the cleanup script after testing (`python cleanup.py`)

For more details, see [Cleanup Strategy](docs/cleanup_strategy.md)

## Running the Server

There are multiple ways to run the server:

### Standard Method

Start the server with:
```bash
python main.py
```

Optional arguments:
- `--host`: Host to bind to (default: 127.0.0.1)
- `--port`: Port to bind to (default: 8000)
- `--config`: Path to config file (default: vars/key.yaml)

### IDE Integration

For running the server in VS Code or Cursor IDE environments:

#### VS Code Tasks

Several predefined tasks are available in VS Code:

- **Run Cursor Launcher (Most Compatible)**: Best option for all environments
- **Run IDE Launcher (Recommended)**: Alternative with more features
- **Run Enhanced Minimal MCP Server**: For specific environments

Run a task with: `Ctrl+Shift+P` → `Tasks: Run Task` → Select the desired task

#### Cursor IDE Integration

The server is configured to run directly in Cursor IDE as an MCP server:

1. Open the OPNsense project in Cursor IDE
2. Access it via the MCP servers list in Cursor

See `docs/cursor_ide_integration.md` for details on the IDE integration.

## Authentication

The server uses JWT-based authentication. To access the tools:

1. Get an access token:
```http
POST /token
Content-Type: application/x-www-form-urlencoded

username=admin&password=password
```

2. Use the token in subsequent requests:
```http
GET /tools
Authorization: Bearer <your_access_token>
```

## Available Tools

### ARP Table Tool
Retrieves both IPv4 ARP and IPv6 NDP tables from OPNsense.

Example request:
```http
POST /execute/arp_table
```

Response:
```json
{
    "arp": [
        {
            "hostname": "device1",
            "ip": "192.168.1.100",
            "mac": "00:11:22:33:44:55"
        }
    ],
    "ndp": [
        {
            "hostname": "device2",
            "ip": "fe80::1",
            "mac": "00:11:22:33:44:66"
        }
    ]
}
```

### Interface Configuration Tool
Manage network interfaces on OPNsense.

Example requests:
```http
# List all interfaces
POST /execute/interface_config
{
    "action": "list"
}

# Get specific interface
POST /execute/interface_config
{
    "action": "get",
    "interface": "wan"
}
```

Response:
```json
{
    "interfaces": [
        {
            "name": "wan",
            "device": "em0",
            "ipv4": "192.168.1.1",
            "ipv6": "fe80::1",
            "status": "up",
            "mtu": 1500,
            "media": "1000baseT",
            "enabled": true
        }
    ],
    "status": "success"
}
```

### System Status Tool
Get system status information including CPU, memory, and filesystem usage.

Example request:
```http
POST /execute/system_status
```

Response:
```json
{
    "cpu_usage": 15.5,
    "memory_usage": 45.2,
    "filesystem_usage": {
        "/": 68.5,
        "/var": 34.2
    },
    "uptime": "10 days, 2:15:30",
    "versions": {
        "opnsense": "23.7",
        "kernel": "13.1-RELEASE"
    }
}
```

### Firewall Rules Tool
Manage firewall rules on OPNsense.

Example request:
```http
POST /execute/firewall_rules
```

Response:
```json
{
    "rules": [
        {
            "sequence": 1,
            "description": "Allow LAN to WAN",
            "interface": "lan",
            "protocol": "any",
            "source": "lan net",
            "destination": "any",
            "action": "pass",
            "enabled": true
        }
    ],
    "status": "success"
}
```

## Development

Add new tools by:
1. Creating a new tool class in `mcp_server/tools/`
2. Adding the tool to the available tools list in `MCPServer.get_tool()`
