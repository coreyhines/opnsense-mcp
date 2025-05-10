# OPNsense MCP Server Configuration Examples

This directory contains example configuration files for the OPNsense MCP Server in both JSON and YAML formats, optimized for development and IDE usage.

## Using the Configuration Files for Development

The provided `mcp.json` and `mcp.yaml` files are specifically configured for development environments, with settings that make debugging and testing easier.

### Prerequisites

- Python 3.8 or newer
- `uv` installed (`pip install uv` or from [uv's GitHub](https://github.com/astral-sh/uv))

### Installation with UV

UV is a fast Python package installer and resolver that can significantly speed up dependency installation and Python environment management.

1. Create a new virtual environment:

```bash
uv venv
```

2. Activate the virtual environment:

```bash
# On macOS/Linux
source .venv/bin/activate

# On Windows
.venv\Scripts\activate
```

3. Install dependencies:

```bash
uv pip install -r requirements.txt
```

### Running the MCP Server with UV in an IDE

These configuration files are designed to work well with IDEs like VS Code, PyCharm, or other development environments.

#### Using JSON Configuration:

```bash
# From project root directory
uv run python -m mcp_server.server_new --config ./examples/mcp.json
```

#### Using YAML Configuration:

```bash
# From project root directory
uv run python -m mcp_server.server_new --config ./examples/mcp.yaml
```

### IDE Integration

#### VS Code

1. Create a launch configuration in `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Run MCP Server",
      "type": "python",
      "request": "launch",
      "module": "mcp_server.server_new",
      "args": ["--config", "${workspaceFolder}/examples/mcp.json"],
      "justMyCode": false,
      "env": {
        "PYTHONPATH": "${workspaceFolder}"
      }
    },
    {
      "name": "Debug MCP Server",
      "type": "python",
      "request": "launch",
      "module": "mcp_server.server_new",
      "args": ["--config", "${workspaceFolder}/examples/mcp.json"],
      "justMyCode": false,
      "stopOnEntry": true,
      "env": {
        "PYTHONPATH": "${workspaceFolder}",
        "DEBUG": "true"
      }
    }
  ]
}
```

2. Press F5 to start debugging.

#### PyCharm

1. Go to Run → Edit Configurations
2. Click the '+' button to add a new configuration and select "Python"
3. Set the following:
   - Script path: Select your `server_new.py` file
   - Parameters: `--config ./examples/mcp.json`
   - Working directory: Your project root
4. Click "OK" to save the configuration
5. Use the Run or Debug button to start the server

## Development Setup

For development with an IDE (VS Code, PyCharm, etc.), follow these steps:

1. Create and activate a virtual environment:

```bash
# Create environment with UV
uv venv

# Or alternatively with standard venv
python -m venv .venv

# Activate (macOS/Linux)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate
```

2. Install development dependencies:

```bash
uv pip install -r examples/requirements-dev.txt
```

3. Generate mock data for testing:

```bash
./examples/create_mock_data.py
```

4. Customize the configuration:
   - Edit `examples/mcp.json` or `examples/mcp.yaml` with vi as needed
   - Set your OPNsense firewall connection details
   - Keep `development.mock_api: true` to use mock data without a real OPNsense instance

5. Run the server using your preferred method:

```bash
# Direct command
uv run python -m mcp_server.server_new --config ./examples/mcp.json

# Or via your IDE's run/debug configuration
```

## Development Features in the Configuration

The development configuration includes:

- **Debug Mode**: Enhanced logging and error reporting
- **Hot Reload**: Automatic server restart when code changes are detected
- **Mock API**: Use mock data instead of a real OPNsense firewall for testing
- **Extended Authentication**: Longer token expiration for convenience
- **Test Credentials**: Admin/dev users with plaintext passwords for easy development

## Tips for IDE Usage

### VS Code Extensions

- Install the "Python" extension for debugging
- Install "YAML" and "JSON" extensions for better config editing
- Install "REST Client" extension for testing API endpoints

### PyCharm Features

- Use the "HTTP Client" feature for testing API endpoints
- Set up run/debug configurations using the Python script configuration
- Enable "Resolve References" for better code navigation

### Example Debug Session

1. Set breakpoints in your code
2. Start the server in debug mode
3. Make API requests using the Swagger UI at `http://localhost:8080/docs`
4. Step through the code to understand the execution flow
```

### Configuration Options

#### Server Section
- `host`: Interface to bind the server to (default: 0.0.0.0)
- `port`: Port to listen on (default: 8080)
- `debug`: Enable debug mode (default: false)
- `workers`: Number of worker processes (default: 4)
- `ssl`: SSL/TLS configuration
  - `enabled`: Enable HTTPS (default: false)
  - `cert`: Path to SSL certificate
  - `key`: Path to SSL key

#### OPNsense Section
- `firewall_host`: Hostname or IP address of the OPNsense firewall
- `api_key`: OPNsense API key
- `api_secret`: OPNsense API secret
- `timeout`: API request timeout in seconds (default: 30)
- `max_retries`: Maximum number of API request retries (default: 3)
- `verify_ssl`: Verify SSL certificates (default: false)

#### Auth Section
- `enabled`: Enable authentication (default: true)
- `token_expire_minutes`: JWT token expiration time in minutes (default: 60)
- `secret_key`: Secret key for JWT token signing
- `users`: User credentials
  - Username as key
    - `password_hash`: Bcrypt-hashed password
    - `disabled`: Whether the user is disabled

#### Tools Section
- `enabled`: List of enabled tool modules

#### Integration Section
- `prometheus`: Prometheus metrics configuration
- `webhook`: Webhook notification configuration

#### Runtime Section
- `environment`: Deployment environment (development, testing, production)
- `package_manager`: Package manager to use (uv, pip)
- `command`: Command to start the server

## Security Notes

1. Replace the example API key and secret with your actual OPNsense API credentials
2. Generate a secure random string for `auth.secret_key` (e.g., `openssl rand -hex 32`)
3. Create secure passwords for users and hash them with bcrypt
4. Enable SSL in production environments
