# OPNsense MCP Server - IDE In1. Create your environment file

   ```bash
   cp examples/.opnsense-env ~/.opnsense-env
   # Edit with vi
   vi ~/.opnsense-env
   ```tion Guide

This document provides instructions on how to integrate the OPNsense MCP Server with various Integrated Development Environments (IDEs) for a smooth development experience.

## Quick Start

For the fastest way to get started:

```bash
# Copy environment template
cp examples/.opnsense-env ~/.opnsense-env

# Edit with vi
vi ~/.opnsense-env

# Run the development server
./examples/run_dev_server.sh
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
   cp examples/.opnsense-env ~/.opnsense-env
   # Edit with vi
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
   cp examples/.opnsense-env ~/.opnsense-env
   # Edit with vi
   vi ~/.opnsense-env
   ```

2. Open the project in PyCharm

3. Set up a Run Configuration:
   - Click on "Run" > "Edit Configurations"
   - Click the "+" button and select "Python"
   - Set the following:
     - Script path: Select the `server_new.py` file
     - Parameters: Leave empty
     - Python interpreter: Select your project venv
     - Environment variables: Click "..." and add the following:

       ```
       PYTHONPATH=<project-root>
       DEBUG=true
       LOG_LEVEL=DEBUG
       ```

     - Check "EnvFile" and add `~/.opnsense-env`
   - Click "OK" to save

4. Run or debug the configuration

## Other IDEs

For other IDEs, you can use the provided `mcp_ide_config.json` as a reference for setting up your environment.

## Using the Environment Variables

The environment file (`~/.opnsense-env`) contains the following variables:

- `OPNSENSE_HOST`: Hostname or IP of your OPNsense firewall
- `OPNSENSE_API_KEY`: API key for authentication
- `OPNSENSE_API_SECRET`: API secret for authentication
- `PORT`: Port to run the MCP server on (default: 8080)
- `HOST`: Host to bind to (default: 127.0.0.1)
- `DEBUG`: Enable debug mode (true/false)
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `TEST_MODE`: Enable test mode (true/false)
- `MOCK_API`: Use mock API responses instead of real OPNsense calls (true/false)

## Development Tools

Several tools are provided to help with development:

- `create_mock_data.py`: Creates mock data for testing without a real OPNsense instance
- `run_dev_server.sh`: Sets up the environment and runs the server
- `test_standalone.py`: Run standalone tests for specific API endpoints
- `test_integration.py`: Run integration tests for all components

## Example MCP Server Command

You can run the MCP server directly using UV with:

```bash
uv run --env-file ~/.opnsense-env --with fastapi,uvicorn,pydantic,pyopnsense /Users/corey/vs-code/opnsense/mcp_server/server_new.py
```

This command can be integrated with various IDEs and task runners.
