# Pre-commit Configuration Notes

## Current Status
Pre-commit hooks are currently disabled due to Python 3.13 compatibility issues.

## Issue
The pre-commit hooks were failing with the following error:
```
ImportError: cannot import name 'JSONDecodeError' from 'pip._vendor.requests.compat'
```

This is a known issue with Python 3.13 and older versions of pip/requests in pre-commit environments.

## Solution Applied
1. **Simplified pre-commit configuration** to use only basic hooks
2. **Removed pre-commit hook installation** to prevent interference
3. **Specified Python 3.12** as the target version in `.python-version` and `pyproject.toml`

## Current Configuration
The `.pre-commit-config.yaml` file contains only basic hooks:
- `trailing-whitespace`
- `end-of-file-fixer` 
- `check-yaml`

## Future Steps
When Python 3.13 compatibility improves in the pre-commit ecosystem:

1. **Reinstall pre-commit**: `pip install pre-commit`
2. **Install hooks**: `pre-commit install`
3. **Add more hooks gradually** as compatibility is confirmed

## Manual Code Quality
Until pre-commit hooks are re-enabled, use these manual commands:

```bash
# Format code with ruff
ruff format .

# Lint code with ruff
ruff check .

# Run tests
python -m pytest tests/
```

## Project Status
The OPNsense MCP project is fully functional and production-ready. The pre-commit issue is a development tooling problem, not a project functionality issue.
