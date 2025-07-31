# OPNsense MCP Server

> **AI-Powered Network Management for OPNsense Firewalls**

The OPNsense MCP Server provides comprehensive network management capabilities through the Model Context Protocol (MCP), enabling natural language interaction with your OPNsense firewall. Manage devices, monitor traffic, configure firewall rules, and troubleshoot network issues using AI chat interfaces.

## 🚀 Quick Start (5 minutes)

### 1. Install Dependencies
```bash
# Install UV (fast Python package installer)
pip install uv

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt
```

### 2. Configure Credentials
```bash
# Copy the example environment file
cp examples/.opnsense-env ~/.opnsense-env

# Edit with your actual credentials
vi ~/.opnsense-env
```

Example `~/.opnsense-env`:
```env
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here
OPNSENSE_FIREWALL_HOST=your.opnsense.host
MCP_SECRET_KEY=your_jwt_secret_key_here
```

### 3. Start the Server
```bash
uv run python main.py
```

### 4. Integrate with Your Preferred Tool
- **Cursor IDE**: [Integration Guide](docs/GETTING_STARTED.md#cursor-ide-integration)
- **LM Studio**: [Integration Guide](docs/GETTING_STARTED.md#lm-studio-integration)
- **Continue**: [Integration Guide](docs/GETTING_STARTED.md#continue-integration)

## 🎯 What Can It Do?

The OPNsense MCP Server transforms your firewall management with AI-powered capabilities:

### 🔍 **Network Discovery & Device Management**
- **Find devices**: "Show me all devices on the network"
- **Device identification**: "What is morpheus doing on the network?"
- **Network topology**: "Show me LLDP neighbors"

### 📊 **System Monitoring & Health**
- **System status**: "What's the current system status?"
- **Performance monitoring**: "Check firewall performance"
- **Health diagnostics**: "Is the firewall healthy?"

### 🛡️ **Firewall Management**
- **Rule creation**: "Create a rule to block traffic from 192.168.1.100"
- **Rule analysis**: "Show me current firewall rules"
- **Security assessment**: "Is there suspicious traffic?"

### 🔬 **Traffic Analysis & Troubleshooting**
- **Packet capture**: "Capture traffic on the WAN interface for 30 seconds"
- **Connectivity issues**: "Why can't my thermostat connect to the internet?"
- **Performance problems**: "The guest WiFi seems slow today"

## 🛠️ Integration Options

### **Cursor IDE** - Development Integration
Network-aware coding with real-time firewall context.

**Quick Setup:**
```json
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp"
    }
  }
}
```

[📖 Complete Cursor IDE Guide](docs/GETTING_STARTED.md#cursor-ide-integration)

### **LM Studio** - AI Chat Interface
Perfect for natural language network management and troubleshooting.

**Quick Setup:**
```json
// ~/.lmstudio/mcp.json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp"
    }
  }
}
```

[📖 Complete LM Studio Guide](docs/GETTING_STARTED.md#lm-studio-integration)

### **Continue** - AI Coding Assistant
Network automation and script generation with firewall context.

**Quick Setup:**
```json
// ~/.continue/mcp.json
{
  "mcpServers": {
    "opnsense-mcp": {
      "command": "/bin/bash",
      "args": ["/path/to/your/opnsense-mcp/mcp_start.sh"],
      "cwd": "/path/to/your/opnsense-mcp"
    }
  }
}
```

[📖 Complete Continue Guide](docs/GETTING_STARTED.md#continue-integration)

## 💡 Real-World Examples

### **Device Discovery**
**User:** "What devices are on my network?"

**AI Assistant:** I'll check your network for active devices.

```
ARP Table Results:
- 192.168.1.1 (aa:bb:cc:dd:ee:ff) - Deciso B.V. - Interface: ax0 - Permanent
- 192.168.1.33 (11:22:33:44:55:66) - iBerg Networks, Inc. - Interface: ax0 - Expires: 1200s
- 192.168.1.64 (aa:bb:cc:dd:ee:ff) - iBerg Networks, Inc. - Interface: ax0 - Expires: 875s

VLAN 2 Devices:
- 10.0.2.10 (aa:bb:cc:dd:ee:ff) - Raspberry Pi Trading Ltd - Interface: ax0_vlan2 - Expires: 1195s
- 10.0.2.175 (ad:2e:b5:d9:75:c8) - Private - Hostname: coreymbp - Expires: 1152s
```

### **Security Analysis**
**User:** "Is there suspicious traffic on the network?"

**AI Assistant:** I'll perform a comprehensive security analysis.

```
Security Assessment Results:

🔒 Overall Status: GOOD

Threat Activity:
- 🚫 23 SSH brute-force attempts from external IPs (all blocked ✅)
- ✅ No internal threats detected
- ✅ No unauthorized devices found on trusted networks

Privacy Protection:
- ✅ DNS over HTTPS active on all internal VLANs
- ✅ No DNS leaks detected in guest/solar networks
- ✅ Normal encrypted traffic patterns observed
```

### **Troubleshooting**
**User:** "Why can't my smart thermostat connect to the internet?"

**AI Assistant:** Let me investigate your thermostat's connectivity issue.

```
Device Found:
- Location: IoT VLAN (192.168.100.15)
- MAC Address: aa:bb:cc:dd:ee:10
- DHCP Status: ⚠️ No hostname lease (may be using static IP)

Root Cause Identified:
- 🚫 Firewall rule "Block IoT Internet Access" is preventing HTTPS connections
- ✅ DNS and NTP work (device can resolve names and sync time)
- 🚫 HTTPS to api.nest.com blocked by security policy

Solution:
I can create a specific rule to allow your thermostat to reach Nest's API.
```

[📖 More Examples](docs/EXAMPLES/COMPLEX_EXAMPLES.md)

## 📚 Documentation

### **Getting Started**
- [📖 Complete Setup Guide](docs/GETTING_STARTED.md) - Detailed installation and configuration
- [🔧 Troubleshooting](docs/GETTING_STARTED.md#troubleshooting) - Common issues and solutions

### **Reference**
- [📋 Function Reference](docs/REFERENCE/FUNCTION_REFERENCE.md) - Complete API documentation
- [🔍 Available Tools](docs/REFERENCE/FUNCTION_REFERENCE.md#available-functions) - All supported functions

### **Examples**
- [💡 Basic Examples](docs/EXAMPLES/BASIC_EXAMPLES.md) - Simple use cases
- [🚀 Complex Examples](docs/EXAMPLES/COMPLEX_EXAMPLES.md) - Advanced scenarios

### **Development**
- [👨‍💻 Project Guide](docs/DEVELOPMENT/PROJECT_GUIDE.md) - Development setup and best practices
- [🤝 Contributing](docs/DEVELOPMENT/CONTRIBUTING.md) - How to contribute

## 🔧 Available Functions

The OPNsense MCP Server provides comprehensive network management through 12 main function categories:

### 🔍 **Network Discovery & Device Identification**
- **`arp`** - ARP/NDP table for IP-to-MAC address mapping
- **`dhcp`** - DHCP lease information and hostname resolution  
- **`lldp`** - Network topology discovery via LLDP neighbors

### 📊 **System Monitoring & Health**
- **`system`** - Firewall CPU, memory, disk usage, and diagnostics
- **`get_logs`** - Firewall log analysis with advanced filtering
- **`packet_capture`** - Live network traffic capture and analysis

### 🛡️ **Firewall Management**
- **`fw_rules`** - Current firewall rule inspection and analysis
- **`mkfw_rule`** - Create new firewall rules with full parameter control
- **`rmfw_rule`** - Delete existing firewall rules
- **`ssh_fw_rule`** - SSH-based rule creation (bypasses API limitations)

### ⚙️ **Network Configuration**
- **`interface_list`** - Available network interfaces for rules and monitoring

## 🤖 AI-Powered Complex Queries

The server excels at handling multi-step queries that combine multiple functions:

- **"What is [device] doing on the network?"** → Automatic device identification, traffic analysis, and security assessment
- **"Is there suspicious traffic?"** → Comprehensive security analysis across logs, rules, and live traffic
- **"Why can't [device] reach [service]?"** → Full troubleshooting workflow with actionable recommendations

> **Note:** All functions include built-in parameter validation, error handling, and usage guidance. The AI agent automatically selects and combines the appropriate functions based on your natural language queries.

## 🔐 Security & Authentication

- **JWT-based authentication** for internal operations
- **Environment-based secrets** - All credentials stored in `~/.opnsense-env`
- **No hardcoded secrets** - Secure by design
- **MCP protocol** - JSON-RPC over stdio, not HTTP endpoints

## 🚨 Troubleshooting

### **Common Issues**

**Import errors**: Ensure all dependencies are installed
```bash
uv pip install -r requirements.txt
```

**Authentication fails**: Check your environment and credentials
```bash
# Verify your ~/.opnsense-env file
cat ~/.opnsense-env
```

**Port conflicts**: Change the port in your config or launch arguments

**Missing dependencies**: Install the missing package

### **Getting Help**

1. Check the [Troubleshooting Guide](docs/GETTING_STARTED.md#troubleshooting)
2. Review the [Function Reference](docs/REFERENCE/FUNCTION_REFERENCE.md)
3. See [Complex Examples](docs/EXAMPLES/COMPLEX_EXAMPLES.md) for similar scenarios

## 📝 Notes

- **Production Ready**: Always use the main server with all dependencies installed
- **MCP Protocol**: Server communicates via JSON-RPC over stdio, not HTTP REST endpoints
- **Container Runtime**: Podman is the preferred container runtime (not Docker)
- **Editing**: Use vi/vim for editing; VS Code is supported as an IDE only
- **Cleanup**: Always clean up temporary and test files (use `tmp_` or `test_` prefixes)
- **Secrets**: Store all secrets in `.env` or a secure store, never in code
