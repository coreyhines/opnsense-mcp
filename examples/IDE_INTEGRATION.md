# OPNsense MCP Server - IDE Integration Guide

This document provides instructions on how to integrate the OPNsense MCP Server
with various Integrated Development Environments (IDEs) for a smooth development
experience.

## Quick Start

For the fastest way to get started:

```bash
# Copy environment template
cp examples/.env.example ~/.env

# Edit with your editor
vi ~/.env

# Run the development server (use mcp_start.sh or your IDE config; see README)
./mcp_start.sh
```

## VS Code Integration

Visual Studio Code offers excellent Python debugging capabilities. To set up:

1. Copy the VS Code configuration files:

   ```bash
   mkdir -p .vscode
   cp examples/vscode_launch.json .vscode/launch.json
   cp examples/vscode_tasks.json .vscode/tasks.json
   ```

2. Create your environment file:

   ```bash
   cp examples/.env.example ~/.env
   # Edit with your editor
   ```

3. Install the Python extension if you haven't already

4. Run or debug using the provided configurations:
   - Press F5 to start debugging
   - Press Ctrl+Shift+B to run the build task (start the server)
   - Use the Tasks menu to run other tasks

## PyCharm Integration

For PyCharm users:

1. Create your environment file:

   ```bash
   cp examples/.env.example ~/.env
   vi ~/.env
   ```

2. Open the project in PyCharm

3. Set up a Run Configuration:
   - Click on "Run" > "Edit Configurations"
   - Click the "+" button and select "Python"
   - Set the following:
     - Script path: entry you use to run the MCP server (e.g. `opnsense_mcp/server.py` via project launcher)
     - Parameters: Leave empty or per your setup
     - Python interpreter: Select your project venv
     - Environment variables: Click "..." and add the following:

       ```markdown
       PYTHONPATH=<project-root>
       DEBUG=true
       LOG_LEVEL=DEBUG
       ```

     - Check "EnvFile" and add `~/.env`
   - Click "OK" to save

4. Run or debug the configuration

## Other IDEs

For other IDEs, you can use the provided `examples/mcp.json` as a reference for
setting up your environment.

## Using the Environment Variables

Use **`~/.env`** (copy from `examples/.env.example`). See `opnsense_mcp/utils/env.py` for load order.

Typical variables:

- `OPNSENSE_FIREWALL_HOST`: Hostname or IP of your OPNsense firewall
- `OPNSENSE_API_KEY`: API key for authentication
- `OPNSENSE_API_SECRET`: API secret for authentication
- `OPNSENSE_SSL_VERIFY`: `true` or `false` (self-signed certs often use `false`)
- `DEBUG`, `LOG_LEVEL`: optional development toggles

## Development Tools

Several tools are provided to help with development:

- `create_mock_data.py`: Creates mock data for testing without a real OPNsense instance
- `test_standalone.py`: Run standalone tests for specific API endpoints
- `test_integration.py`: Run integration tests for all components

## Example MCP Server Command

You can run with credentials from `~/.env`:

```bash
uv run --env-file ~/.env python -m opnsense_mcp.server
```

Adjust module path if your launcher differs. This pattern works with IDEs that support `--env-file`.
