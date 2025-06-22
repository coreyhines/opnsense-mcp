# OPNsense MCP Standalone Tools

This document describes the standalone tools available in the OPNsense MCP
project. These tools can be used independently of the MCP server for direct
interaction with an OPNsense firewall.

## Overview

The standalone tools provide direct access to OPNsense API functionality without
requiring the full MCP server. They can be used for testing, debugging, or
automation tasks.

## Available Tools

The following standalone tools are available:

- **system_status.py**: Get system status information from OPNsense
- **arp.py**: Retrieve ARP and NDP tables
- **dhcp.py**: Show DHCP lease information
- **firewall_logs.py**: Get firewall logs
- **fw_rules.py**: View firewall rules
- **lldp.py**: Show LLDP neighbor information

## Setup

1. Configure your OPNsense credentials in a `.env` file or in `~/.opnsense-env`:

```env
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
OPNSENSE_API_HOST=your.opnsense.host
```

1. Make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

## Usage

### Running Standalone Tools

You can run the standalone tools directly from the command line:

```bash
# Get system status
python system_status.py

# Get ARP table
python opnsense_mcp/tools/arp.py

# Get DHCP leases
python opnsense_mcp/tools/dhcp.py
```

### Command-Line Arguments

Most tools support common command-line arguments:

- `--help`: Show help information
- `--json`: Output results in JSON format
- `--filter`: Filter results by specific criteria

Example:

```bash
# Get ARP table entries for a specific IP
python opnsense_mcp/tools/arp.py --filter 192.168.1.1

# Get DHCP leases for a specific hostname
python opnsense_mcp/tools/dhcp.py --filter mydevice
```

## Cross-Referencing Features

Some tools provide cross-referencing capabilities to enrich data:

- **dhcp.py**: Can cross-reference with ARP table to show actual online status
- **arp.py**: Can cross-reference with DHCP leases to show hostname information

## Testing

You can test the standalone tools using the test scripts:

```bash
# Test all tools
python test_all_tools.py

# Test specific tool
python test_cross_reference.py
```

## Troubleshooting

- **API Connection Issues**: Verify your credentials and network connectivity
- **Permission Errors**: Ensure your API key has the necessary permissions
- **Missing Data**: Some features may require specific OPNsense plugins or
  configurations

## Notes

- All standalone tools use the same API client library as the MCP server
- Tools are designed to be used both independently and integrated with the MCP
  server
- For production use, consider using the MCP server for better security and
  authentication
