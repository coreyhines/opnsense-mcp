# OPNsense MCP Server - Project Guide

## Overview

This guide covers the architecture, setup, IDE integration, cleanup, and best practices for the OPNsense MCP Server. It is intended for developers, contributors, and operators.

---

## Architecture & Implementation

- Main server uses a custom JWT implementation (see below)
- Minimal and fixed server variants existed in the past for special environments, but are no longer maintained or included
- Only the main server (`main.py`) is supported and recommended for production and development

### Server Variants

1. **Main Server**: Full-featured, uses custom JWT, passlib, and all tools
2. **Legacy/Minimal Servers**: Previously provided for special environments, but are no longer included in the repository

### Custom JWT Implementation

- Located in `jwt_helper.py`
- Eliminates dependency on `jose`/`python-jose`
- Supports HS256 algorithm, token expiration, and payload verification

#### Usage Example

```python
from mcp_server.utils.jwt_helper import JWTError, decode_jwt as jwt, create_jwt

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

- Supports VS Code, Cursor IDE, PyCharm, and others
- Provides shims for environments missing certain dependencies (e.g., `passlib_shim.py`)
- All secrets should be stored in `.env` files or `~/.opnsense-env`, not in code

### Passlib and Dependency Shimming

- The server uses `passlib` for password hashing
- In some IDEs (Cursor, VS Code), `passlib` may not be available
- Solution: A `passlib_shim.py` provides a minimal `CryptContext` for test/dev use
- For production, always install the real `passlib` package

### Launcher Options

- **VS Code/IDE**: Use the standard Python launch configuration to run `main.py`
- **Direct Execution**: Run `python main.py`
- **PyCharm**: Set up a run configuration using your venv and `~/.opnsense-env`

#### Example Environment Setup

```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env
```

---

## Cleanup & Best Practices

- Remove redundant and legacy files (e.g., _new.py, unused run_ and test_ files)
- Keep only essential launchers, tests, and check scripts
- Automate cleanup of temporary/test files and artifacts
- Use VS Code tasks and scripts for automated cleanup
- Follow naming conventions for easy cleanup (e.g., tmp_, test_ prefixes)
- Always cleanup after editing (including vi/vim swap files)
- For Podman: clean up containers/volumes after testing

### Cleanup Actions (Summary)

- All _new.py files merged or removed
- Unnecessary run_and test_ files deleted
- Only essential launchers and tests retained
- VS Code tasks updated for new structure
- Imports updated for renamed modules
- Temporary scripts and artifacts removed

### Best Practices

- Use cleanup tasks/scripts after testing or editing
- Name temp/test files with tmp_or test_ for auto-cleanup
- Clean up vi/vim swap files
- For CI/CD, run cleanup after tests

---

## Troubleshooting

- **Import errors**: Ensure all dependencies are installed, or use the passlib shim for development
- **Port conflicts**: Change the port in your config or launch arguments
- **Missing dependencies**: Install the missing package or use the shim for development
- **ModuleNotFoundError: No module named 'passlib'**: Use the provided shim or install passlib
- **Authentication fails**: The shim only supports test users (e.g., admin/password)

---

## Verification

- All core functionality and tests pass after cleanup
- Project is ready for further development

---

## Notes

- Backups of removed files are available as .bak if needed
- If you add new test or temp file types, update cleanup.py accordingly
- For production, always use the main server with all dependencies installed
