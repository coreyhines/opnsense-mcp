# LM Studio Integration Guide

## Overview

This guide covers how to integrate the OPNsense MCP Server with LM Studio for enhanced network management capabilities through AI chat interfaces.

## Prerequisites

- LM Studio installed and configured
- OPNsense MCP Server properly set up and tested
- Valid OPNsense API credentials

## Configuration

### 1. Create LM Studio MCP Configuration

Create the LM Studio MCP configuration file at `~/.lmstudio/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/Users/corey/vs-code/opnsense-mcp/mcp_start.sh"],
      "cwd": "/Users/corey/vs-code/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    },
    "GitLab communication server": {
      "command": "npx",
      "args": [
        "-y",
        "@zereight/mcp-gitlab"
      ],
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "YOUR_GITLAB_TOKEN_HERE",
        "GITLAB_API_URL": "https://your-gitlab-instance.com/api/v4"
      }
    }
  }
}
```

### 2. Environment Configuration

Ensure your OPNsense credentials are properly configured in `~/.opnsense-env`:

```bash
# Copy the example environment file
cp examples/.opnsense-env ~/.opnsense-env

# Edit with your actual credentials
vi ~/.opnsense-env
```

Example `~/.opnsense-env` content (with redacted values):

```env
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here
OPNSENSE_FIREWALL_HOST=your.opnsense.host
MCP_SECRET_KEY=your_jwt_secret_key_here
```

### 3. Path Configuration

Update the paths in your `~/.lmstudio/mcp.json` to match your actual installation:

- Replace `/Users/corey/vs-code/opnsense-mcp` with the actual path to your OPNsense MCP project
- Ensure the `mcp_start.sh` script is executable: `chmod +x mcp_start.sh`

## Available Tools

Once integrated, the following OPNsense MCP tools will be available in LM Studio:

### Network Management Tools
- **arp**: Show ARP/NDP table with optional filtering
- **dhcp**: Show DHCP lease information
- **lldp**: Show LLDP neighbor table
- **interface**: Get interface status information
- **interface_list**: List available firewall interfaces

### Firewall Management Tools
- **get_logs**: Get firewall logs with optional filtering
- **fw_rules**: List and manage firewall rules
- **mkfw_rule**: Create new firewall rules
- **rmfw_rule**: Delete existing firewall rules

### System & Monitoring Tools
- **system**: Show system status information
- **packet_capture**: Capture and analyze network traffic

## Usage Examples

### Basic Network Queries

**User**: "Show me all devices on the network"

**Assistant**: I'll check the ARP table to show you all devices currently connected to your network.

```
ARP Table Results:
- 192.168.1.1 (aa:bb:cc:dd:ee:ff) - Deciso B.V. - Interface: ax0 - Permanent
- 192.168.1.33 (11:22:33:44:55:66) - iBerg Networks, Inc. - Interface: ax0 - Expires: 1200s
- 192.168.1.64 (aa:bb:cc:dd:ee:ff) - iBerg Networks, Inc. - Interface: ax0 - Expires: 875s
- 192.168.1.69 (d5:5c:e3:36:87:0e) - iBerg Networks, Inc. - Interface: ax0 - Expires: 928s
- 192.168.1.36 (aa:bb:cc:dd:ee:ff) - iBerg Networks, Inc. - Interface: ax0 - Expires: 895s
- 192.168.1.4 (55:40:c7:b6:de:a1) - Zyxel Communications Corporation - Hostname: poesw01 - Expires: 1174s

VLAN 2 Devices:
- 10.0.2.10 (aa:bb:cc:dd:ee:ff) - Raspberry Pi Trading Ltd - Interface: ax0_vlan2 - Expires: 1195s
- 10.0.2.175 (ad:2e:b5:d9:75:c8) - Private - Hostname: coreymbp - Expires: 1152s
- 10.0.2.1 (aa:bb:cc:dd:ee:ff) - Deciso B.V. - Interface: ax0_vlan2 - Permanent
```

**User**: "What's the system status of the firewall?"

**Assistant**: Let me check the current system status of your OPNsense firewall.

```
System Status:
- Hostname: fw.example.com
- OPNsense Version: OPNsense 25.7-amd64
- Kernel: FreeBSD 14.3-RELEASE-p1
- Status: Online and operational
```

**User**: "Show me recent firewall logs"

**Assistant**: I'll retrieve the most recent firewall logs to show you current network activity.

```
Recent Firewall Logs (Last 5 entries):
1. 2025-07-31T08:26:01-05:00 - BLOCK - UDP - 10.0.7.3:123 → 10.0.2.3:123 - Interface: ax0_vlan7 - Rule: Default deny / state violation rule
2. 2025-07-31T08:25:58-05:00 - BLOCK - TCP - 203.0.113.148:53497 → 203.0.113.91:56539 - Interface: ax1 - Rule: Default deny / state violation rule
3. 2025-07-31T08:25:57-05:00 - BLOCK - TCP - 203.0.113.58:40462 → 203.0.113.91:795 - Interface: ax1 - Rule: Default deny / state violation rule
4. 2025-07-31T08:25:53-05:00 - BLOCK - TCP - 203.0.113.148:53497 → 203.0.113.91:56506 - Interface: ax1 - Rule: Default deny / state violation rule
5. 2025-07-31T08:25:52-05:00 - BLOCK - UDP - 10.0.7.4:123 → 10.0.2.3:123 - Interface: ax0_vlan7 - Rule: Default deny / state violation rule
```

### Advanced Network Analysis

**User**: "Capture traffic on the WAN interface for 30 seconds"

**Assistant**: I'll start a packet capture on the WAN interface for 30 seconds to analyze network traffic.

```
Packet Capture Started:
- Interface: ax1 (WAN)
- Duration: 30 seconds
- Filter: None (capturing all traffic)
- Status: Running...

[After 30 seconds]
Packet Capture Complete:
- Captured 1,247 packets
- File saved as: wan_capture_20250731_082600.pcap
- Analysis shows normal internet traffic with some blocked connection attempts
```

**User**: "Create a firewall rule to block traffic from 192.168.1.100"

**Assistant**: I'll create a firewall rule to block all traffic from the specified IP address.

```
Firewall Rule Created:
- Description: Block traffic from 192.168.1.100
- Action: Block
- Interface: LAN
- Protocol: Any
- Source: 192.168.1.100
- Destination: Any
- Direction: In
- Status: Enabled and applied
- Rule UUID: 12345678-1234-1234-1234-123456789abc
```

**User**: "Show me LLDP neighbors to understand network topology"

**Assistant**: I'll check the LLDP neighbor table to show you the network topology and connected devices.

```
LLDP Neighbor Table:
- Interface: igb3
  - Neighbor: iBerg Networks Switch
  - MAC: aa:bb:cc:dd:ee:ff
  - IP: 10.0.9.246
  - Port: Ethernet1/1
  - System: Arista-DCS-7050S-64

- Interface: ax0
  - Neighbor: iBerg Networks AP
  - MAC: 11:22:33:44:55:66
  - IP: 192.168.1.33
  - Port: eth0
  - System: Mojo-AP-1234
```

## Troubleshooting

### Common Issues

1. **MCP Server Not Starting**
   - Check that `mcp_start.sh` is executable
   - Verify Python virtual environment is activated
   - Check environment variables in `~/.opnsense-env`

2. **Authentication Errors**
   - Verify OPNsense API credentials
   - Check firewall host connectivity
   - Ensure API key has proper permissions

3. **Tool Not Found Errors**
   - Restart LM Studio after configuration changes
   - Check MCP server logs for errors
   - Verify tool names match exactly

### Debug Mode

Enable debug mode by setting `DEBUG=1` in the environment:

```json
"env": {
  "PYTHONUNBUFFERED": "1",
  "PYTHONIOENCODING": "utf-8",
  "DEBUG": "1"
}
```

### Logs and Monitoring

- Check LM Studio logs for MCP connection issues
- Monitor OPNsense MCP server output for errors
- Use `system` tool to verify server connectivity

## Security Considerations

- **Token Security**: Never commit tokens to version control
- **Environment Files**: Use `~/.opnsense-env` for sensitive data
- **Network Access**: Ensure proper firewall rules for MCP communication

## Best Practices

1. **Configuration Management**
   - Use environment variables for all sensitive data
   - Keep configuration files in user home directory
   - Use absolute paths for reliable execution

2. **Testing**
   - Test each tool individually before complex queries
   - Verify network connectivity before packet capture
   - Test firewall rule creation in a safe environment

3. **Monitoring**
   - Regularly check system status
   - Monitor firewall logs for unusual activity
   - Keep MCP server and dependencies updated

## Integration with Other MCP Servers

The configuration example above shows integration with:

- **OPNsense MCP**: Network and firewall management
- **GitLab MCP**: GitLab repository and project management

This setup provides comprehensive network management and development workflow capabilities through a single LM Studio interface.

## Support

For issues specific to:
- **OPNsense MCP Server**: Check the main project documentation
- **LM Studio**: Refer to LM Studio documentation
- **MCP Protocol**: Check the Model Context Protocol specification

## Notes

- LM Studio integration provides a powerful interface for network management
- All tools support async operations for better performance
- The MCP protocol ensures secure, standardized communication
- Regular updates to both LM Studio and MCP servers are recommended
