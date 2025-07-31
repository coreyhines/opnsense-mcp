# Multi-Application MCP Integration Guide

## Overview

This guide covers how to integrate the OPNsense MCP Server with multiple desktop applications that support the Model Context Protocol (MCP). This enables AI-powered network management across different tools and workflows.

## Supported Applications

### **Cursor IDE** - Development Integration
- **Purpose**: Code editor with AI assistance
- **Use Case**: Network-aware development and debugging
- **Configuration**: `~/.cursor/mcp.json`

### **LM Studio** - AI Chat Interface
- **Purpose**: Local AI chat with network tools
- **Use Case**: Natural language network management
- **Configuration**: `~/.lmstudio/mcp.json`

### **Continue** - AI Coding Assistant
- **Purpose**: AI-powered code generation and editing
- **Use Case**: Network-aware code development
- **Configuration**: `~/.continue/mcp.json`

### **Ollama** - Local LLM Interface
- **Purpose**: Local large language model interface
- **Use Case**: Offline AI network management
- **Configuration**: `~/.ollama/mcp.json`

### **Jan** - Alternative AI Chat
- **Purpose**: Open-source AI chat interface
- **Use Case**: Alternative to LM Studio
- **Configuration**: `~/.jan/mcp.json`

### **Web Search** - AI Search Interface
- **Purpose**: AI-powered search with network tools
- **Use Case**: Network research and troubleshooting
- **Configuration**: `~/.websearch/mcp.json`

## Prerequisites

- OPNsense MCP Server properly set up and tested
- Valid OPNsense API credentials configured
- Target applications installed and configured

## Configuration Files

### 1. Cursor IDE Configuration

Create `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    }
  }
}
```

### 2. LM Studio Configuration

Create `~/.lmstudio/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
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

### 3. Continue Configuration

Create `~/.continue/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    }
  }
}
```

### 4. Ollama Configuration

Create `~/.ollama/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    }
  }
}
```

### 5. Jan Configuration

Create `~/.jan/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    }
  }
}
```

### 6. Web Search Configuration

Create `~/.websearch/mcp.json`:

```json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "DEBUG": "1"
      }
    }
  }
}
```

## Environment Configuration

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

## Application-Specific Use Cases

### **Cursor IDE Use Cases**
- **Network-Aware Development**: "Show me the current network status while I'm debugging this network-related code"
- **Firewall Rule Creation**: "Create a firewall rule for the application I'm developing"
- **Network Troubleshooting**: "Check if the network issue I'm experiencing is firewall-related"

### **LM Studio Use Cases**
- **Natural Language Management**: "Show me all devices on the network"
- **System Monitoring**: "What's the current system status?"
- **Traffic Analysis**: "Capture traffic on the WAN interface for 30 seconds"

### **Continue Use Cases**
- **Network-Aware Code Generation**: "Generate code that checks network connectivity"
- **Configuration Management**: "Create a script to manage firewall rules"
- **Monitoring Integration**: "Write code to integrate with the network monitoring system"

### **Ollama Use Cases**
- **Offline Network Management**: "Show me the ARP table without internet access"
- **Local AI Assistance**: "Help me troubleshoot this network issue locally"
- **Privacy-Focused Management**: "Manage network settings without external AI services"

### **Jan Use Cases**
- **Alternative Interface**: "Use Jan instead of LM Studio for network management"
- **Open Source Workflow**: "Integrate with open-source AI tools"
- **Custom AI Models**: "Use custom models for network analysis"

### **Web Search Use Cases**
- **Network Research**: "Search for solutions to this network problem"
- **Troubleshooting**: "Find information about this network error"
- **Best Practices**: "Search for network security best practices"

## Available Tools Across All Applications

Once integrated, the following OPNsense MCP tools will be available in all applications:

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

## Installation and Setup

### 1. Install Applications

```bash
# Cursor IDE (if not already installed)
# Download from https://cursor.sh/

# LM Studio (if not already installed)
# Download from https://lmstudio.ai/

# Continue (if not already installed)
# Download from https://continue.dev/

# Ollama (if not already installed)
curl -fsSL https://ollama.ai/install.sh | sh

# Jan (if not already installed)
# Download from https://jan.ai/

# Web Search (if not already installed)
# Download from https://websearch.ai/
```

### 2. Create Configuration Directories

```bash
# Create configuration directories for each application
mkdir -p ~/.cursor
mkdir -p ~/.lmstudio
mkdir -p ~/.continue
mkdir -p ~/.ollama
mkdir -p ~/.jan
mkdir -p ~/.websearch
```

### 3. Copy Configuration Files

```bash
# Copy the appropriate configuration file for each application
# (Use the examples above as templates)
```

### 4. Update Paths

Replace `/path/to/your/opnsense-mcp` with the actual path to your OPNsense MCP project in all configuration files.

### 5. Restart Applications

Restart each application after configuration to load the MCP tools.

## Troubleshooting

### Common Issues

1. **MCP Server Not Starting**
   - Check that `mcp_start.sh` is executable
   - Verify Python virtual environment is activated
   - Check environment variables in `~/.opnsense-env`

2. **Application Not Recognizing Tools**
   - Restart the application after configuration changes
   - Check application logs for MCP connection issues
   - Verify configuration file syntax

3. **Authentication Errors**
   - Verify OPNsense API credentials
   - Check firewall host connectivity
   - Ensure API key has proper permissions

### Debug Mode

Enable debug mode by setting `DEBUG=1` in the environment:

```json
"env": {
  "PYTHONUNBUFFERED": "1",
  "PYTHONIOENCODING": "utf-8",
  "DEBUG": "1"
}
```

### Application-Specific Troubleshooting

- **Cursor IDE**: Check the Output panel for MCP-related errors
- **LM Studio**: Check the console output for connection issues
- **Continue**: Verify the MCP server is running before starting Continue
- **Ollama**: Ensure Ollama is running and accessible
- **Jan**: Check Jan's log files for MCP connection errors
- **Web Search**: Verify network connectivity for web search functionality

## Security Considerations

- **Token Security**: Never commit tokens to version control
- **Environment Files**: Use `~/.opnsense-env` for sensitive data
- **Network Access**: Ensure proper firewall rules for MCP communication
- **Application Permissions**: Grant necessary permissions to each application

## Best Practices

1. **Configuration Management**
   - Use environment variables for all sensitive data
   - Keep configuration files in user home directory
   - Use absolute paths for reliable execution

2. **Testing**
   - Test each application individually
   - Verify tool functionality in each application
   - Test network connectivity before packet capture

3. **Monitoring**
   - Regularly check system status across applications
   - Monitor firewall logs for unusual activity
   - Keep MCP server and dependencies updated

## Integration Workflows

### **Development Workflow**
1. Use **Cursor IDE** for code development with network context
2. Use **Continue** for AI-assisted code generation
3. Use **LM Studio** for natural language network queries
4. Use **Web Search** for research and troubleshooting

### **Network Management Workflow**
1. Use **LM Studio** or **Jan** for natural language management
2. Use **Ollama** for offline network operations
3. Use **Cursor IDE** for network-aware development
4. Use **Web Search** for finding solutions and best practices

### **Troubleshooting Workflow**
1. Use **Web Search** to research the issue
2. Use **LM Studio** to query network status
3. Use **Cursor IDE** to implement fixes
4. Use **Continue** to generate troubleshooting scripts

## Support

For issues specific to:
- **OPNsense MCP Server**: Check the main project documentation
- **Individual Applications**: Refer to each application's documentation
- **MCP Protocol**: Check the Model Context Protocol specification

## Notes

- Multi-application integration provides comprehensive network management capabilities
- Each application offers unique advantages for different use cases
- All tools support async operations for better performance
- The MCP protocol ensures secure, standardized communication across applications
- Regular updates to both applications and MCP servers are recommended
