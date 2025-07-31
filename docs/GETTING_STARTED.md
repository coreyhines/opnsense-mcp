# Getting Started Guide - OPNsense MCP Server

> **Complete setup and integration guide for AI-powered OPNsense network management**

This guide walks you through installing, configuring, and integrating the OPNsense MCP Server with your preferred AI tools. Follow the sections in order for the best experience.

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.8+** installed on your system
- **OPNsense firewall** with API access enabled
- **API credentials** (key and secret) from your OPNsense firewall
- **Network access** to your OPNsense firewall

## 🚀 Installation & Setup

### Step 1: Clone and Install

```bash
# Clone the repository
git clone https://github.com/your-username/opnsense-mcp.git
cd opnsense-mcp

# Install UV (fast Python package installer)
# UV is significantly faster than pip and provides better dependency resolution
pip install uv

> **💡 Why UV?**
> UV is a fast Python package installer and resolver written in Rust. It's significantly faster than pip, provides better dependency resolution, and offers improved caching. For more information, visit [Astral UV](https://docs.astral.sh/uv/).

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt
```

### Step 2: Configure Credentials

Create your environment configuration file:

```bash
# Copy the example environment file
cp examples/.opnsense-env ~/.opnsense-env

# Edit with your actual credentials
vi ~/.opnsense-env
```

**Required Environment Variables:**
```env
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here
OPNSENSE_FIREWALL_HOST=your.opnsense.host
MCP_SECRET_KEY=your_jwt_secret_key_here
```

**Getting OPNsense API Credentials:**
1. Log into your OPNsense web interface
2. Go to **System** → **Access** → **Users**
3. Create a new user or use an existing one
4. Go to **System** → **Access** → **API**
5. Generate API credentials (key and secret)

### Step 3: Test the Installation

```bash
# Start the server
uv run python main.py
```

You should see output indicating the server is running and ready to accept MCP connections.

## 🛠️ Integration Guides

Choose your preferred AI tool and follow the corresponding integration guide:

### Cursor IDE Integration

**Best for:** Network-aware development and coding

#### Quick Setup

1. **Create Cursor Configuration**
   ```bash
   mkdir -p ~/.cursor
   ```

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

2. **Update Paths**
   Replace `/path/to/your/opnsense-mcp` with the actual path to your project.

3. **Restart Cursor IDE**
   Restart Cursor IDE to load the MCP tools.

#### Usage Examples

Once integrated, you can use AI assistance for network-aware development:

```
User: "Help me write a script to monitor network devices"
Assistant: [Uses arp and system tools to gather data for the script]

User: "Debug this firewall rule configuration"
Assistant: [Uses fw_rules tool to analyze current rules and suggest fixes]

User: "Create a network monitoring dashboard"
Assistant: [Uses multiple tools to gather data for dashboard creation]

User: "Analyze network traffic patterns"
Assistant: [Uses get_logs and packet_capture tools for analysis]
```

#### Troubleshooting

- **MCP Server Not Starting**: Check that `mcp_start.sh` is executable
- **Authentication Errors**: Verify OPNsense API credentials in `~/.opnsense-env`
- **Tool Not Found**: Restart Cursor IDE after configuration changes

### LM Studio Integration

**Best for:** Natural language network management and troubleshooting

#### Quick Setup

1. **Create LM Studio Configuration**
   ```bash
   mkdir -p ~/.lmstudio
   ```

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
       }
     }
   }
   ```

2. **Update Paths**
   Replace `/path/to/your/opnsense-mcp` with the actual path to your project.

3. **Restart LM Studio**
   Restart LM Studio to load the MCP tools.

#### Usage Examples

Once integrated, you can use natural language to manage your network:

```
User: "Show me all devices on the network"
Assistant: [Uses arp and dhcp tools to provide comprehensive device list]

User: "What's the system status of the firewall?"
Assistant: [Uses system tool to show CPU, memory, and uptime]

User: "Show me recent firewall logs"
Assistant: [Uses get_logs tool to display recent firewall activity]

User: "Create a firewall rule to block traffic from 192.168.1.100"
Assistant: [Uses mkfw_rule tool to create the blocking rule]
```

#### Troubleshooting

- **MCP Server Not Starting**: Check that `mcp_start.sh` is executable
- **Authentication Errors**: Verify OPNsense API credentials in `~/.opnsense-env`
- **Tool Not Found**: Restart LM Studio after configuration changes

**Best for:** Network-aware development and coding

#### Quick Setup

1. **Create Cursor Configuration**
   ```bash
   mkdir -p ~/.cursor
   ```

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

2. **Update Paths**
   Replace `/path/to/your/opnsense-mcp` with the actual path to your project.

3. **Restart Cursor IDE**
   Restart Cursor IDE to load the MCP tools.

#### Usage Examples

```
User: "Show me the current network status while I'm debugging this network-related code"
Assistant: [Uses system and interface tools to provide network context]

User: "Create a firewall rule for the application I'm developing"
Assistant: [Uses mkfw_rule tool to create appropriate rules]

User: "Check if the network issue I'm experiencing is firewall-related"
Assistant: [Uses get_logs and fw_rules tools to analyze the issue]
```

### Continue Integration

**Best for:** AI-assisted network automation and script generation

#### Quick Setup

1. **Create Continue Configuration**
   ```bash
   mkdir -p ~/.continue
   ```

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

2. **Update Paths**
   Replace `/path/to/your/opnsense-mcp` with the actual path to your project.

3. **Restart Continue**
   Restart Continue to load the MCP tools.

#### Usage Examples

```
User: "Generate code that checks network connectivity"
Assistant: [Uses system and interface tools to create network monitoring scripts]

User: "Create a script to manage firewall rules"
Assistant: [Uses fw_rules and mkfw_rule tools to generate automation scripts]

User: "Write code to integrate with the network monitoring system"
Assistant: [Uses multiple tools to create comprehensive monitoring solutions]
```

## 🔧 Available Tools

Once integrated, the following OPNsense MCP tools will be available:

### Network Discovery & Device Identification
- **`arp`** - ARP/NDP table for IP-to-MAC address mapping
- **`dhcp`** - DHCP lease information and hostname resolution  
- **`lldp`** - Network topology discovery via LLDP neighbors

### System Monitoring & Health
- **`system`** - Firewall CPU, memory, disk usage, and diagnostics
- **`get_logs`** - Firewall log analysis with advanced filtering
- **`packet_capture`** - Live network traffic capture and analysis

### Firewall Management
- **`fw_rules`** - Current firewall rule inspection and analysis
- **`mkfw_rule`** - Create new firewall rules with full parameter control
- **`rmfw_rule`** - Delete existing firewall rules
- **`ssh_fw_rule`** - SSH-based rule creation (bypasses API limitations)

### Network Configuration
- **`interface_list`** - Available network interfaces for rules and monitoring

## 🚨 Troubleshooting

### Common Issues

#### **Import Errors**
**Problem**: Python can't find required modules
**Solution**: Ensure all dependencies are installed
```bash
uv pip install -r requirements.txt
```

#### **Authentication Fails**
**Problem**: Server can't connect to OPNsense
**Solution**: Check your environment and credentials
```bash
# Verify your ~/.opnsense-env file
cat ~/.opnsense-env

# Test connectivity to your firewall
ping your.opnsense.host
```

#### **MCP Server Not Starting**
**Problem**: Server fails to start or tools not found
**Solution**: Check configuration and permissions
```bash
# Make startup script executable
chmod +x mcp_start.sh

# Check Python environment
python --version
which python
```

#### **Port Conflicts**
**Problem**: Server can't bind to required ports
**Solution**: Change the port in your config or launch arguments

#### **Missing Dependencies**
**Problem**: Specific packages not found
**Solution**: Install the missing package
```bash
uv pip install package_name
```

### Debug Mode

Enable debug mode by setting `DEBUG=1` in the environment:

```json
"env": {
  "PYTHONUNBUFFERED": "1",
  "PYTHONIOENCODING": "utf-8",
  "DEBUG": "1"
}
```

### Getting Help

1. **Check the logs**: Look for error messages in the server output
2. **Verify connectivity**: Ensure you can reach your OPNsense firewall
3. **Test credentials**: Verify your API key and secret are correct
4. **Check permissions**: Ensure the startup script is executable

## 🔐 Security Best Practices

### **Credential Management**
- Store all secrets in `~/.opnsense-env`, never in code
- Use strong, unique API keys and secrets
- Regularly rotate your API credentials
- Never commit credentials to version control

### **Network Security**
- Use HTTPS for OPNsense web interface access
- Restrict API access to trusted IP addresses
- Monitor API usage for unusual activity
- Use firewall rules to limit access to the MCP server

### **Environment Security**
- Keep your Python environment updated
- Use virtual environments to isolate dependencies
- Regularly update the OPNsense MCP Server
- Monitor for security updates in dependencies

## 📚 Next Steps

Now that you have the OPNsense MCP Server set up and integrated:

1. **Explore the Tools**: Try basic queries like "Show me all devices on the network"
2. **Read the Examples**: See [Complex Query Examples](EXAMPLES/COMPLEX_EXAMPLES.md) for advanced usage
3. **Check the Reference**: Review [Function Reference](REFERENCE/FUNCTION_REFERENCE.md) for detailed tool documentation
4. **Join the Community**: Share your experiences and get help from other users

## 🆘 Support

If you need help:

1. **Check this guide** for common issues and solutions
2. **Review the examples** for usage patterns
3. **Check the function reference** for detailed tool documentation
4. **Open an issue** on the project repository with details about your problem

Remember to include:
- Your operating system and Python version
- The specific error message you're seeing
- Steps to reproduce the issue
- Your configuration (with sensitive data redacted) 
