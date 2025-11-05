# GitHub Copilot Instructions for OPNsense MCP Server

## Purpose

This repository provides an MCP (Model Context Protocol) server for OPNsense firewall management. Before making any changes:
- Summarize your current goal and approach
- Identify which components will be modified
- Ensure changes align with the MCP protocol and OPNsense API patterns

## Repository Context

### What is this project?
The OPNsense MCP Server enables AI-powered network management through natural language interaction with OPNsense firewalls. It provides tools for device discovery, system monitoring, firewall management, and traffic analysis.

### Key Components
- **Main server**: `main.py` - Entry point for the MCP server (JSON-RPC over stdio)
- **Tools**: `opnsense_mcp/tools/` - Individual MCP tools for firewall operations
- **Utils**: `opnsense_mcp/utils/` - Shared utilities including JWT authentication
- **Tests**: `tests/` - Unit tests with pytest
- **Documentation**: `docs/` - User guides and API reference

## Technologies

### Core Stack
- **Python 3.12** (NOT 3.13 - compatibility issues exist)
- **MCP Protocol**: JSON-RPC over stdio (NOT HTTP REST endpoints)
- **OPNsense API**: XML-RPC interface for firewall management
- **JWT Authentication**: Custom implementation in `opnsense_mcp/utils/jwt_helper.py`

### Key Libraries
- `mcp` - Model Context Protocol server implementation
- `requests` - HTTP client for OPNsense API calls
- `pytest` - Testing framework
- `ruff` - Linting and formatting (configured in pyproject.toml)
- `pre-commit` - Git hooks for code quality

### Container Runtime
- **Podman** is the preferred container runtime (NOT Docker)

## Coding Standards

### Python Style
- Follow PEP 8 standards
- Line length: 88 characters (Black/Ruff standard)
- Use double quotes for strings
- Use type hints where appropriate
- Target version: Python 3.12

### Code Quality Tools
1. **Ruff**: Primary linter and formatter (replaces Black, isort, flake8)
   ```bash
   ruff check .
   ruff format .
   ```

2. **Pre-commit hooks**: Run automatically on commit
   ```bash
   pre-commit run --all-files
   ```

3. **Pytest**: All changes should maintain or improve test coverage
   ```bash
   pytest tests/ -v --cov=opnsense_mcp
   ```

### Naming Conventions
- Use descriptive variable names
- Prefix temporary files with `tmp_`
- Prefix test files with `test_`
- Follow existing patterns in the codebase

### Comments
- Add comments only when necessary to explain complex logic
- Match the style of existing comments in the file
- Avoid stating the obvious

## Build & Test

### Installation
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests
All changes MUST pass the full test suite:
```bash
# Run all tests with coverage
pytest tests/ -v --cov=opnsense_mcp --cov-report=xml --cov-report=html

# Run specific test file
pytest tests/test_specific.py -v
```

### Linting
Before committing, ensure code passes all linters:
```bash
# Run pre-commit checks
pre-commit run --all-files

# Or run ruff directly
ruff check .
ruff format .
```

### CI/CD Pipeline
- All PRs must pass `.github/workflows/ci.yml`
- Tests run on Python 3.12
- Coverage reports uploaded to Codecov
- Trivy security scanning for vulnerabilities

## Security & Environment

### Secrets Management
- **NEVER** hardcode secrets in source code
- Store all credentials in `~/.opnsense-env` or environment variables
- Use `.env` files for local development (ensure they're in `.gitignore`)
- Required environment variables:
  - `OPNSENSE_API_KEY`
  - `OPNSENSE_API_SECRET`
  - `OPNSENSE_FIREWALL_HOST`
  - `MCP_SECRET_KEY`

### Security Best Practices
- Always validate user inputs in MCP tools
- Use JWT tokens for authentication (see `opnsense_mcp/utils/jwt_helper.py`)
- Handle API errors gracefully
- Never log sensitive information (API keys, secrets, passwords)
- Follow secure coding practices for firewall operations

## File Organization

### Where to Make Changes

#### Adding New MCP Tools
- Create new tool in `opnsense_mcp/tools/`
- Follow existing tool patterns (e.g., `arp_tool.py`, `system_tool.py`)
- Register tool in the main server
- Add corresponding tests in `tests/`

#### Modifying Utilities
- Shared utilities go in `opnsense_mcp/utils/`
- Keep utilities focused and reusable
- Update tests when modifying utilities

#### Documentation Updates
- User-facing docs: `docs/`
- API reference: `docs/REFERENCE/FUNCTION_REFERENCE.md`
- Examples: `docs/EXAMPLES/`
- Development guides: `docs/DEVELOPMENT/`

### Files to Avoid Modifying
- DO NOT modify `.github/workflows/` unless specifically needed for CI/CD
- DO NOT change Python version requirements (must stay at 3.12)
- DO NOT modify MCP protocol implementation unless absolutely necessary

## Common Patterns

### MCP Tool Structure
```python
from mcp.server import Server
from mcp.types import Tool, TextContent

async def handle_tool_call(name: str, arguments: dict):
    """Handle MCP tool calls"""
    if name == "tool_name":
        # Validate inputs
        # Call OPNsense API
        # Return structured response
        return [TextContent(type="text", text=result)]
```

### OPNsense API Calls
- Use the existing API client patterns
- Handle authentication via API keys
- Parse XML-RPC responses properly
- Include error handling for API failures

### Testing Patterns
```python
import pytest
from unittest.mock import Mock, patch

def test_tool_function():
    """Test description"""
    # Arrange
    # Act
    # Assert
```

## Cleanup & Maintenance

### Temporary Files
- Name with `tmp_` prefix for automatic cleanup
- Store in `/tmp/` directory, not in repository
- Clean up test artifacts after running tests

### After Editing
- Clean up vi/vim swap files
- Remove unused imports
- Remove debug print statements
- Run formatters and linters

### Container Cleanup (Podman)
```bash
podman rm -f <container>
podman volume prune
```

## Common Tasks

### Adding a New Feature
1. Create feature branch
2. Add tests first (TDD approach recommended)
3. Implement the feature
4. Ensure tests pass
5. Run linters and formatters
6. Update documentation
7. Submit PR

### Fixing a Bug
1. Write a test that reproduces the bug
2. Fix the bug
3. Verify the test passes
4. Check for similar issues in codebase
5. Update documentation if needed

### Updating Dependencies
1. Update `requirements.txt` or `requirements-dev.txt`
2. Test thoroughly
3. Check for security vulnerabilities with Trivy
4. Update lock files if using pip-tools

## IDE Integration

### Supported IDEs
- **Cursor IDE**: Primary development environment for MCP integration
- **LM Studio**: AI chat interface integration
- **Continue**: AI coding assistant
- **VS Code**: Supported as IDE (not as text editor - use vi/vim for editing)

### Environment Setup
```bash
cp examples/.opnsense-env ~/.opnsense-env
vi ~/.opnsense-env  # Edit with your credentials
```

## References

- [Getting Started Guide](../docs/GETTING_STARTED.md)
- [Project Guide](../docs/DEVELOPMENT/PROJECT_GUIDE.md)
- [Function Reference](../docs/REFERENCE/FUNCTION_REFERENCE.md)
- [Contributing Guidelines](../docs/DEVELOPMENT/CONTRIBUTING.md)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)

## Questions?

If you're unsure about:
- **Architecture**: Check `docs/DEVELOPMENT/PROJECT_GUIDE.md`
- **API usage**: See `docs/REFERENCE/FUNCTION_REFERENCE.md`
- **Examples**: Look at `docs/EXAMPLES/`
- **Testing**: Review existing tests in `tests/`
- **MCP patterns**: Examine existing tools in `opnsense_mcp/tools/`
