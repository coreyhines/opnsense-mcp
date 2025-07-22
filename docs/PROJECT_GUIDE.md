# OPNsense MCP Server - Project Guide

## Overview

This guide covers the architecture, setup, IDE integration, cleanup, and best
practices for the OPNsense MCP Server. It is intended for developers,
contributors, and operators.

---

## Architecture & Implementation

- The main server (`main.py`) is the only supported and recommended entry point
  for production and development.
- The server communicates using the MCP protocol (JSON-RPC over stdio), not HTTP
  REST endpoints.
- Uses a custom JWT implementation for authentication and authorization.

### Custom JWT Implementation

- Located in `opnsense_mcp/utils/jwt_helper.py`
- Supports HS256 algorithm, token expiration, and payload verification

### Usage Example

```python
from opnsense_mcp.utils.jwt_helper import JWTError, decode_jwt as jwt, create_jwt

token = create_jwt({"sub": "username"}, secret_key="your-secret", # pragma: allowlist secret 
                  algorithm="HS256", expire_minutes=30)

try:
    payload = jwt(token, secret_key="your-secret", algorithms=["HS256"]) # pragma: allowlist secret
    # Use payload data
except JWTError:
    # Handle invalid token
```

### Security Notes

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

---

## IDE Integration & Editing

- The server is designed for integration with Cursor IDE and other MCP-compatible
  IDEs.
- All secrets should be stored in `.env` files or `~/.opnsense-env`, not in code.
- You may use any editor or IDE you prefer; VS Code, vim, and others are all supported.
- If using an IDE that does not support all dependencies, ensure your environment
  is activated or install missing packages.

### Example Environment Setup

```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env
```

---

## Cleanup & Best Practices

- Keep only essential launchers, tests, and scripts.
- Automate cleanup of temporary/test files and artifacts.
- Name temp/test files with `tmp_` or `test_` for easy auto-cleanup.
- Always cleanup after editing (including vi/vim swap files).
- For Podman: clean up containers/volumes after testing. Podman is the preferred
  container runtime (not Docker).

### Best Practices

- Use cleanup tasks/scripts after testing or editing.
- Name temp/test files with `tmp_` or `test_` for auto-cleanup.
- Clean up vi/vim swap files.
- For CI/CD, run cleanup after tests.
- Store all secrets in `.env` or a secure store, never in code.

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
- The server communicates via MCP protocol (JSON-RPC over stdio), not HTTP REST
  endpoints
- Podman is the preferred container runtime
- You may use any editor or IDE you prefer; VS Code, vim, and others are all supported.
