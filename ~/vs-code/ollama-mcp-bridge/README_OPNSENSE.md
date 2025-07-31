# OPNsense MCP Bridge Setup

This directory contains the [ollama-mcp-bridge](https://github.com/patruff/ollama-mcp-bridge) configured to work with your OPNsense MCP server.

## What is this?

The ollama-mcp-bridge is a TypeScript implementation that connects local LLMs (via Ollama) to Model Context Protocol (MCP) servers. This allows you to use your OPNsense firewall management tools with local AI models like Llama.

## Configuration

The bridge is configured in `bridge_config.json` with:

- **OPNsense MCP Server**: Your firewall management tools
- **Filesystem MCP**: File operations in your opnsense-mcp directory
- **Memory MCP**: Persistent memory storage
- **LLM**: llama3.2:latest (via Ollama)

## Usage

### Starting the Bridge

```bash
cd ~/vs-code/ollama-mcp-bridge
npm run start
```

Or use the convenience script:
```bash
./start_opnsense_bridge.sh
```

### Available Commands

Once the bridge is running, you can:

- `list-tools`: Show all available tools and their parameters
- `quit`: Exit the program
- Any other input: Send to the LLM for processing

### Example Interactions

```
> list-tools
[Shows available OPNsense tools like arp, dhcp, firewall_logs, etc.]

> Check the ARP table
[Uses OPNsense MCP to retrieve ARP information]

> Show me the firewall logs
[Uses OPNsense MCP to get firewall log data]

> Create a new folder called "network-docs"
[Uses Filesystem MCP to create directory]
```

## Architecture

The bridge works by:

1. **LLM Processing**: Takes your natural language input
2. **Tool Detection**: Identifies which MCP tools to use
3. **MCP Communication**: Sends structured requests to your OPNsense MCP server
4. **Response Formatting**: Returns results in a user-friendly format

## Troubleshooting

### If the bridge fails to start:

1. **Check Ollama**: Ensure Ollama is running and llama3.2:latest is available
   ```bash
   ollama list
   ```

2. **Check MCP Servers**: Verify the Node.js MCP servers are installed
   ```bash
   npm list -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory
   ```

3. **Check OPNsense MCP**: Ensure your OPNsense MCP server is working
   ```bash
   cd ~/vs-code/opnsense-mcp
   ./mcp_start.sh
   ```

### Common Issues

- **Node.js path**: The bridge uses `/opt/homebrew/bin/node` (macOS Homebrew)
- **MCP server paths**: Filesystem and Memory MCPs are installed globally
- **Ollama connection**: Bridge connects to `http://localhost:11434`

## Integration with Other Tools

This bridge can be used with:

- **Ollama Web UI**: For web-based interactions
- **Ollama CLI**: For command-line usage
- **Custom applications**: Via the bridge's API

## Files

- `bridge_config.json`: Main configuration file
- `start_opnsense_bridge.sh`: Convenience startup script
- `README_OPNSENSE.md`: This documentation file

## Next Steps

1. Test the bridge with basic OPNsense queries
2. Explore the available tools with `list-tools`
3. Try network monitoring and firewall management tasks
4. Consider adding more MCP servers (GitHub, Brave Search, etc.)
