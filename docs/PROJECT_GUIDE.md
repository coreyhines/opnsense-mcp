# OPNsense MCP Server - Project Guide

## Overview

This guide covers the architecture, setup, IDE integration, cleanup, and best practices for the OPNsense MCP Server. It is intended for developers, contributors, and operators.

---

## Architecture & Implementation

- The main server (`main.py`) is the only supported and recommended entry point for production and development.
- Uses a custom JWT implementation for authentication and authorization.

### Custom JWT Implementation

- Located in `opnsense_mcp/utils/jwt_helper.py`
- Supports HS256 algorithm, token expiration, and payload verification

#### Usage Example

```python
from opnsense_mcp.utils.jwt_helper import JWTError, decode_jwt as jwt, create_jwt

token = create_jwt({"sub": "username"}, secret_key="your-secret", algorithm="HS256", expire_minutes=30)

try:
    payload = jwt(token, secret_key="your-secret", algorithms=["HS256"])
    # Use payload data
except JWTError:
    # Handle invalid token
```

#### Security Notes

- Always store `SECRET_KEY` in `.env` or a secure store, never in code
- Handles signing, verification, and expiration

---

## Setup & Usage

1. Clone the repository
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:

   ```bash
   python main.py
   ```

### API Endpoints

- `/token` - Authenticate and get JWT token
- `/tools` - List available tools
- `/execute/{tool_name}` - Execute a specific tool

---

## IDE Integration

- Supports VS Code and Cursor IDE (and other Python IDEs)
- All secrets should be stored in `.env` files or `~/.opnsense-env`, not in code
- If using an IDE that does not support all dependencies, ensure your environment is activated or install missing packages

#### Example Environment Setup

```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env
```

---

## Cleanup & Best Practices

- Keep only essential launchers, tests, and scripts
- Automate cleanup of temporary/test files and artifacts
- Use VS Code tasks and scripts for automated cleanup
- Follow naming conventions for easy cleanup (e.g., tmp_, test_ prefixes)
- Always cleanup after editing (including vi/vim swap files)
- For Podman: clean up containers/volumes after testing

### Best Practices

- Use cleanup tasks/scripts after testing or editing
- Name temp/test files with tmp_or test_ for auto-cleanup
- Clean up vi/vim swap files
- For CI/CD, run cleanup after tests

---

## Troubleshooting

- **Import errors**: Ensure all dependencies are installed
- **Port conflicts**: Change the port in your config or launch arguments
- **Missing dependencies**: Install the missing package
- **Authentication fails**: Check your environment and credentials

---

## Verification

- All core functionality and tests should pass after cleanup
- Project is ready for further development

---

## Notes

- For production, always use the main server with all dependencies installed
