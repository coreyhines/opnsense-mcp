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

```
User: "Show me all devices on the network"
Assistant: [Uses arp and dhcp tools to provide comprehensive device list]

User: "What's the system status of the firewall?"
Assistant: [Uses system tool to show CPU, memory, and uptime]

User: "Show me recent firewall logs"
Assistant: [Uses get_logs tool to display recent firewall activity]
```

### Advanced Network Analysis

```
User: "Capture traffic on the WAN interface for 30 seconds"
Assistant: [Uses packet_capture tool with appropriate parameters]

User: "Create a firewall rule to block traffic from 192.168.1.100"
Assistant: [Uses mkfw_rule tool to create the blocking rule]

User: "Show me LLDP neighbors to understand network topology"
Assistant: [Uses lldp tool to display network device connections]
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
