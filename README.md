# OPNsense MCP Server

This server provides OPNsense API functionality through a Model Context Protocol
(MCP) interface (JSON-RPC over stdio), not HTTP REST endpoints.

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

1. Configure your OPNsense credentials in a `.env` file (in the project root) or
   in `~/.opnsense-env`:

```env
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
OPNSENSE_API_HOST=your.opnsense.host
MCP_SECRET_KEY=your_jwt_secret_key
```

You can use a `.env` file in the project root, or set these in your shell
environment. The server will automatically load from `~/.opnsense-env` if present.

## Running the Server

Start the server with:

```bash
python main.py
```

## IDE Integration

- The server is designed for integration with Cursor IDE and other MCP-compatible
  IDEs.
- All secrets should be stored in `.env` files or `~/.opnsense-env`, not in code.
- If using an IDE that does not support all dependencies, activate your Python
  virtual environment (venv) or install any missing packages as needed.

### Example Environment Setup

```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env
```

## LM Studio Integration

The OPNsense MCP Server is fully compatible with LM Studio for enhanced AI-powered network management.

### Quick Setup

1. Create `~/.lmstudio/mcp.json` with the OPNsense MCP server configuration
2. Configure your OPNsense credentials in `~/.opnsense-env`
3. Restart LM Studio to load the MCP tools

### Available Tools in LM Studio

Once integrated, you can use natural language to interact with your OPNsense firewall:

- **Network Analysis**: "Show me all devices on the network"
- **System Monitoring**: "What's the current system status?"
- **Firewall Management**: "Create a rule to block traffic from 192.168.1.100"
- **Traffic Analysis**: "Capture traffic on the WAN interface for 30 seconds"

### Detailed Documentation

For comprehensive LM Studio integration instructions, including:
- Complete configuration examples (with redacted tokens)
- Multi-server setup (OPNsense, CVP, Home Assistant, Grafana)
- Troubleshooting guide
- Security best practices

See: [LM Studio Integration Guide](docs/LM_STUDIO_INTEGRATION.md)

## Multi-Application Integration

The OPNsense MCP Server supports integration with multiple desktop applications for comprehensive AI-powered network management across different workflows.

### Supported Applications

- **Cursor IDE**: Development integration with network-aware coding
- **LM Studio**: AI chat interface for natural language management
- **Continue**: AI coding assistant with network context
- **Ollama**: Local LLM interface for offline management
- **Jan**: Open-source AI chat alternative
- **Web Search**: AI-powered search with network tools

### Quick Setup

1. Install your preferred applications
2. Create the appropriate configuration file (e.g., `~/.cursor/mcp.json`)
3. Configure your OPNsense credentials in `~/.opnsense-env`
4. Restart the application to load MCP tools

### Use Cases by Application

- **Development**: Cursor IDE + Continue for network-aware coding
- **Management**: LM Studio + Jan for natural language control
- **Offline**: Ollama for local network management
- **Research**: Web Search for troubleshooting and best practices

### Detailed Documentation

For comprehensive multi-application integration instructions, including:
- Complete configuration examples for all applications
- Application-specific use cases and workflows
- Troubleshooting guides for each application
- Integration workflows and best practices

See: [Multi-Application Integration Guide](docs/MULTI_APP_INTEGRATION.md)

## Tool Discovery and Invocation

- Tools are discovered and invoked via the MCP protocol (JSON-RPC over stdio),
  not via HTTP endpoints.
- The server will advertise available tools (e.g., ARP, DHCP, firewall, system
  status) to the IDE or MCP client.
- Tool invocation is handled by sending a JSON-RPC request with the tool name
  and arguments.

## Authentication

- The server uses JWT-based authentication for internal operations. All secrets
  and keys must be stored in `.env` or a secure store.

## Available Functions

The OPNsense MCP Server provides comprehensive network management capabilities through 12 main function categories:

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

### 🤖 **AI-Powered Complex Queries**

The server excels at handling multi-step queries that combine multiple functions:

- **"What is [device] doing on the network?"** → Automatic device identification, traffic analysis, and security assessment
- **"Is there suspicious traffic?"** → Comprehensive security analysis across logs, rules, and live traffic
- **"Why can't [device] reach [service]?"** → Full troubleshooting workflow with actionable recommendations

### 📚 **Comprehensive Documentation**

- **[Complete Function Reference](docs/FUNCTION_REFERENCE.md)** - Detailed documentation for every function with parameters, examples, and use cases
- **[Complex Query Examples](docs/COMPLEX_QUERY_EXAMPLES.md)** - Real-world scenarios showing how the AI agent combines multiple functions to answer sophisticated questions like "What is morpheus doing on the network?"

> **Note:** All functions include built-in parameter validation, error handling, and usage guidance. The AI agent automatically selects and combines the appropriate functions based on your natural language queries.

## Quick Start Examples

Here are some example conversations showing how users interact with the OPNsense MCP Server through AI chat interfaces:

---

**User:** "What devices are on my network?"

**AI Assistant:** I'll check your network for active devices.

*[AI automatically runs DHCP and ARP queries]*

I found 12 active devices across your network:

**Wired LAN (VLAN2):**
- **morpheus** (10.0.2.150) - Development workstation, active SSH session
- **trogdor** (10.0.2.180) - Server, running web services
- **printer-office** (10.0.2.25) - Network printer

**Guest WiFi (VLAN4):**
- **guest-phone-1** (10.0.4.45) - Mobile device, streaming video
- **guest-laptop** (10.0.4.67) - Laptop, web browsing

**IoT Network (VLAN100):**
- **thermostat-living** (192.168.100.15) - Smart thermostat
- **camera-front** (192.168.100.22) - Security camera

All devices appear to be legitimate and within expected usage patterns.

---

**User:** "Is trogdor being blocked from anything?"

**AI Assistant:** Let me check trogdor's network activity and firewall status.

*[AI runs system check, firewall logs, and traffic analysis]*

**trogdor Network Status:**
- ✅ **Online and active** (10.0.2.180)
- ✅ **All normal services working** (SSH, HTTPS, internal services)

**Recent Security Events:**
- 🚫 **3 blocked attempts** to reach external SMTP (port 25) - this is expected security policy
- ✅ **No other blocks** - all other traffic flowing normally

**Current Activity:**
- Web server responding to requests
- SSH sessions active
- Normal background traffic

The SMTP blocking is intentional - your firewall is preventing trogdor from sending email directly, which is good security practice. Everything else is working normally.

---

**User:** "The guest WiFi seems slow today. Can you check what's happening?"

**AI Assistant:** I'll investigate the guest network performance for you.

*[AI checks guest network devices, captures traffic, and analyzes patterns]*

**Guest Network Analysis:**

**Current Status:**
- **8 active devices** on guest WiFi
- **Total traffic**: ~20 MB/min (higher than usual)
- **Firewall performance**: Normal (8% CPU usage)

**Performance Issue Identified:**
- 📱 **Device 10.0.4.23** is consuming 75% of guest bandwidth
- 🎬 **Activity**: Heavy video streaming (YouTube/Netflix)
- ⚠️ **Impact**: Other guests experiencing reduced speeds

**Quality of Service:**
- ✅ **Rate limiting active**: 10 Mbps per device
- ✅ **Traffic prioritization**: Guest traffic correctly deprioritized

**Recommendation:**
The guest network is working as designed, but one user is using most of the bandwidth. You could reduce the per-device limit to 5 Mbps for more fair sharing, or this will resolve itself when the streaming session ends.

---

**User:** "Why can't my smart thermostat connect to the internet?"

**AI Assistant:** Let me investigate your thermostat's connectivity issue.

*[AI searches for the device, checks network configuration, and analyzes traffic]*

**Device Found:**
- **Location**: IoT VLAN (192.168.100.15)
- **MAC Address**: aa:bb:cc:dd:ee:10
- **DHCP Status**: ⚠️ No hostname lease (may be using static IP)

**Root Cause Identified:**
- 🚫 **Firewall rule "Block IoT Internet Access"** is preventing HTTPS connections
- ✅ **DNS and NTP work** (device can resolve names and sync time)
- 🚫 **HTTPS to api.nest.com blocked** by security policy

**The Problem:**
Your IoT security policy is blocking all internet access except DNS and NTP. The thermostat can't reach Nest's cloud services.

**Solution:**
I can create a specific rule to allow your thermostat to reach Nest's API. Would you like me to:

1. Allow access to nest.com API endpoints, or
2. Show you how to modify the existing IoT policy?

---

**User:** "Show me any suspicious traffic on the network"

**AI Assistant:** I'll perform a comprehensive security analysis of your network.

*[AI runs system health check, analyzes firewall logs, checks device inventory, and captures traffic patterns]*

**Security Assessment Results:**

**🔒 Overall Status: GOOD**

**Threat Activity:**
- 🚫 **23 SSH brute-force attempts** from external IPs (all blocked ✅)
- ✅ **No internal threats detected**
- ✅ **No unauthorized devices** found on trusted networks

**Privacy Protection:**
- ✅ **DNS over HTTPS active** on all internal VLANs
- ✅ **No DNS leaks detected** in guest/solar networks
- ✅ **Normal encrypted traffic patterns** observed

**Traffic Analysis:**
- **WAN Traffic**: Normal web browsing patterns, no bulk data transfers
- **DNS Traffic**: All queries properly using configured DoH servers
- **Security**: No port scans, DDoS attempts, or data exfiltration detected

**Recommendations:**
- SSH brute-force activity is normal and being blocked effectively
- Consider fail2ban for repeat offenders
- Current security posture is effective

Your network security is working well - all threats are being blocked and privacy protections are active.

For more detailed examples, see [Complex Query Examples](docs/COMPLEX_QUERY_EXAMPLES.md).

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
- The server communicates via MCP protocol (JSON-RPC over stdio), not HTTP
  REST endpoints
- Podman is the preferred container runtime
- Use vi/vim for editing; VS Code is supported as an IDE only
- Always clean up temporary and test files (use `tmp_` or `test_` prefixes)
- Store all secrets in `.env` or a secure store, never in code
