# Ollama + MCP Tools Demo

This demo shows how to integrate Ollama with MCP (Model Context Protocol) tools, specifically OPNsense firewall management tools.

## 🎯 What This Demo Shows

- **Ollama Integration**: Using Ollama's API for chat
- **MCP Tools**: Real OPNsense firewall management tools
- **Combined Workflow**: Chat with Ollama and execute MCP tools
- **Interactive Interface**: Command-line demo for presentations

## 🚀 Quick Start

### Prerequisites

1. **Ollama installed and running**
   ```bash
   # Install Ollama (if not already installed)
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Start Ollama
   ollama serve
   
   # Pull a model (in another terminal)
   ollama pull llama3.2:latest
   ```

2. **OPNsense MCP Server configured**
   - Your OPNsense MCP server should be working
   - Environment variables set up in `~/.opnsense-env`

3. **Python dependencies**
   ```bash
   pip install requests
   ```

### Running the Demo

```bash
# Navigate to the demo directory
cd ~/vs-code

# Run the demo
python3 ollama-mcp-client.py
```

## 🎮 Demo Commands

Once the demo is running, you can use these commands:

- **`tools`** - List all available MCP tools
- **`call arp`** - Call the ARP table tool
- **`call dhcp`** - Call the DHCP leases tool
- **`call system`** - Call the system status tool
- **`chat Hello, how are you?`** - Chat with Ollama
- **`demo`** - Run the automated demonstration
- **`quit`** - Exit the demo

## 📋 Available MCP Tools

The demo connects to your OPNsense MCP server and provides access to:

- **`arp`** - Show ARP/NDP table
- **`dhcp`** - Show DHCP lease information
- **`get_logs`** - Get firewall logs
- **`lldp`** - Show LLDP neighbor table
- **`system`** - Show system status
- **`fw_rules`** - Get firewall rules
- **`packet_capture`** - Start/stop packet capture
- **`interface_list`** - List interfaces

## 🎬 Example Session

```
🎯 Ollama + MCP Tools Demo
==================================================

🚀 Starting OPNsense MCP Server...
✅ MCP Server started with 10 tools

📋 Available MCP tools: arp, dhcp, get_logs, lldp, system, fw_rules, packet_capture, interface_list

💡 Available commands:
  - 'tools': List available MCP tools
  - 'call <tool>': Call an MCP tool (e.g., 'call arp')
  - 'chat <message>': Chat with Ollama
  - 'demo': Run a demonstration
  - 'quit': Exit

🤖 Ollama+MCP> call arp
🔧 Calling MCP tool: arp
✅ Result: {
  "arp": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "interface": "lan"
    }
  ],
  "ndp": [],
  "status": "success"
}

🤖 Ollama+MCP> chat What devices are on my network?
🤖 Ollama: I can help you check what devices are on your network! Let me call the ARP tool to see the current devices...

🤖 Ollama+MCP> demo
🎬 Running demonstration...

1️⃣ Chatting with Ollama:
🤖 Ollama: Hello! I'm demonstrating Ollama with MCP tools.

2️⃣ Calling MCP tool (arp):
🔧 MCP Result: { ... }

3️⃣ Calling MCP tool (system):
🔧 MCP Result: { ... }

✅ Demonstration complete!
```

## 🔧 How It Works

1. **MCP Client**: Connects to your OPNsense MCP server via stdio
2. **Tool Discovery**: Automatically discovers available MCP tools
3. **Ollama Integration**: Uses Ollama's REST API for chat
4. **Interactive Interface**: Provides a simple command-line interface

## 📁 Files

- **`ollama-mcp-client.py`** - Main demo script
- **`ollama-mcp-demo.py`** - Simplified demo (simulated tools)
- **`README_OLLAMA_MCP_DEMO.md`** - This documentation

## 🎯 Use Cases

This demo is perfect for:

- **Presentations**: Show MCP integration capabilities
- **Teaching**: Demonstrate how MCP tools work
- **Testing**: Verify your MCP server is working
- **Development**: Debug MCP tool interactions

## 🔍 Troubleshooting

### Ollama Connection Issues
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if needed
ollama serve
```

### MCP Server Issues
```bash
# Test MCP server directly
cd ~/vs-code/opnsense-mcp
./mcp_start.sh
```

### Python Dependencies
```bash
pip install requests
```

## 🚀 Next Steps

After running this demo, you can:

1. **Integrate with other MCP servers** (GitHub, Brave Search, etc.)
2. **Build a web interface** using the same approach
3. **Create automated workflows** combining Ollama and MCP tools
4. **Extend the demo** with more sophisticated tool calling

## 📚 Resources

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Ollama Documentation](https://ollama.ai/docs)
- [OPNsense MCP Server](https://github.com/your-repo/opnsense-mcp)

---

**Happy demonstrating! 🎉**
