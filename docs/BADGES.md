# Badges for README.md

Add these badges to the top of your README.md for better visibility:

```markdown
# OPNsense MCP Server

[![CI](https://github.com/coreyhines/opnsense-mcp/workflows/CI/badge.svg)](https://github.com/coreyhines/opnsense-mcp/actions)
[![codecov](https://codecov.io/gh/coreyhines/opnsense-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/coreyhines/opnsense-mcp)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **AI-Powered Network Management for OPNsense Firewalls**
```

## Badge Explanations

- **CI Badge**: Shows the current build status
- **Codecov Badge**: Shows test coverage percentage
- **Python Version**: Indicates supported Python version
- **Ruff Badge**: Shows code formatting/linting tool
- **Bandit Badge**: Indicates security scanning
- **License Badge**: Shows project license

## Setup Instructions

1. **Codecov Setup** (if not already configured):
   - Go to https://codecov.io/gh/coreyhines/opnsense-mcp
   - Add the repository
   - Get the upload token
   - Add `CODECOV_TOKEN` to repository secrets

2. **Badge URLs** are automatically generated from GitHub Actions

3. **Customize** the badges as needed for your repository
