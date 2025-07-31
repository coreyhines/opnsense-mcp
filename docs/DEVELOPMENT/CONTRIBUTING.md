# Contributing to OPNsense MCP Server

> **How to contribute to AI-powered OPNsense network management**

Thank you for your interest in contributing to the OPNsense MCP Server! This guide will help you get started with development, testing, and contributing to the project.

## 🚀 Getting Started

### **Prerequisites**

- **Python 3.8+** installed
- **OPNsense firewall** for testing (or access to one)
- **Git** for version control
- **Basic understanding** of MCP (Model Context Protocol)

### **Development Setup**

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/opnsense-mcp.git
   cd opnsense-mcp
   ```

2. **Install UV**
   ```bash
   # Install UV (fast Python package installer)
   # UV is significantly faster than pip and provides better dependency resolution
   pip install uv
   ```

3. **Create Virtual Environment and Install Dependencies**
   ```bash
   # Create virtual environment
   uv venv
   
   # Activate virtual environment
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   uv pip install -r requirements.txt
   uv pip install -r requirements-dev.txt
   ```

4. **Configure Environment**
   ```bash
   cp examples/.opnsense-env ~/.opnsense-env
   vi ~/.opnsense-env  # Add your OPNsense credentials
   ```

## 🛠️ Development Workflow

### **Code Style and Standards**

We follow these coding standards:

- **Python**: PEP 8 style guide
- **Type Hints**: Use type annotations for all functions
- **Docstrings**: Google-style docstrings for all public functions
- **Testing**: Unit tests for all new functionality
- **Linting**: Use `ruff` for linting and formatting

### **Running Tests**

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_arp.py

# Run with coverage
uv run pytest --cov=opnsense_mcp

# Run linting
uv run ruff check .
uv run ruff format .
```

### **Adding New Tools**

1. **Create Tool Module**
   ```python
   # opnsense_mcp/tools/your_tool.py
   from typing import Any, Dict
   from opnsense_mcp.utils.api import OPNsenseClient
   
   async def your_tool_name(client: OPNsenseClient, **kwargs) -> Dict[str, Any]:
       """
       Brief description of what this tool does.
       
       Args:
           client: OPNsense API client
           **kwargs: Tool-specific parameters
           
       Returns:
           Dict containing tool results
       """
       # Your tool implementation here
       pass
   ```

2. **Add to Server**
   ```python
   # opnsense_mcp/server.py
   from opnsense_mcp.tools.your_tool import your_tool_name
   
   # Add to tools list
   tools = [
       # ... existing tools
       your_tool_name,
   ]
   ```

3. **Write Tests**
   ```python
   # tests/test_your_tool.py
   import pytest
   from opnsense_mcp.tools.your_tool import your_tool_name
   
   @pytest.mark.asyncio
   async def test_your_tool_name():
       # Test implementation
       pass
   ```

4. **Update Documentation**
   - Add to [Function Reference](../REFERENCE/FUNCTION_REFERENCE.md)
   - Add examples to [Basic Examples](../EXAMPLES/BASIC_EXAMPLES.md) if appropriate
   - Update this contributing guide if needed

### **Testing Guidelines**

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test with real OPNsense API
- **Mock Tests**: Use mock data for CI/CD pipelines
- **Edge Cases**: Test error conditions and boundary cases

### **Error Handling**

All tools should include proper error handling:

```python
async def your_tool_name(client: OPNsenseClient, **kwargs) -> Dict[str, Any]:
    try:
        # Tool implementation
        result = await client.some_api_call()
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

## 📝 Documentation

### **Documentation Standards**

- **Clear and Concise**: Write for users, not developers
- **Examples**: Include practical examples for all tools
- **Progressive Disclosure**: Start simple, add complexity gradually
- **Cross-References**: Link related documentation sections

### **Documentation Structure**

```
docs/
├── GETTING_STARTED.md          # Setup and integration
├── REFERENCE/
│   └── FUNCTION_REFERENCE.md   # Complete API reference
├── EXAMPLES/
│   ├── BASIC_EXAMPLES.md       # Simple use cases
│   └── COMPLEX_EXAMPLES.md     # Advanced scenarios
└── DEVELOPMENT/
    ├── PROJECT_GUIDE.md        # Development setup
    └── CONTRIBUTING.md         # This file
```

### **Updating Documentation**

When adding new features:

1. **Update Function Reference**: Add complete tool documentation
2. **Add Examples**: Include in appropriate examples file
3. **Update README**: If it's a major feature
4. **Check Links**: Ensure all cross-references work

## 🔧 Development Tools

### **IDE Setup**

**VS Code Configuration**
```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./.venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.formatting.provider": "ruff"
}
```

**Pre-commit Hooks**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
```

### **Debugging**

**Enable Debug Mode**
```bash
export DEBUG=1
uv run python main.py
```

**Logging Configuration**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🚨 Common Issues

### **Import Errors**
- Ensure virtual environment is activated (`source .venv/bin/activate`)
- Check `PYTHONPATH` includes project root
- Verify all dependencies are installed (`uv pip install -r requirements.txt`)

### **Authentication Issues**
- Check `~/.opnsense-env` file exists and is readable
- Verify API credentials are correct
- Test connectivity to OPNsense firewall

### **Test Failures**
- Run tests with `-v` flag for verbose output
- Check mock data is up to date
- Verify test environment is properly configured

## 📋 Pull Request Process

### **Before Submitting**

1. **Run Tests**: Ensure all tests pass (`uv run pytest`)
2. **Check Linting**: Run `uv run ruff check .` and `uv run ruff format .`
3. **Update Documentation**: Add/update relevant documentation
4. **Test Integration**: Test with real OPNsense firewall if possible

### **Pull Request Template**

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Test addition/update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Documentation
- [ ] Function reference updated
- [ ] Examples updated (if applicable)
- [ ] README updated (if applicable)

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation is clear and complete
```

### **Review Process**

1. **Automated Checks**: CI/CD pipeline runs tests and linting
2. **Code Review**: At least one maintainer reviews the PR
3. **Testing**: PR is tested against real OPNsense firewall
4. **Documentation**: Documentation is reviewed for clarity
5. **Merge**: PR is merged after approval

## 🎯 Areas for Contribution

### **High Priority**
- **New Tools**: Additional OPNsense API integrations
- **Error Handling**: Improved error messages and recovery
- **Testing**: More comprehensive test coverage
- **Documentation**: Better examples and tutorials

### **Medium Priority**
- **Performance**: Optimize API calls and data processing
- **Security**: Additional security features and validation
- **Integration**: Support for more MCP clients
- **Monitoring**: Enhanced system monitoring capabilities

### **Low Priority**
- **UI Improvements**: Better output formatting
- **Configuration**: Additional configuration options
- **Logging**: Enhanced logging and debugging features

## 🤝 Community Guidelines

### **Code of Conduct**
- Be respectful and inclusive
- Help others learn and grow
- Provide constructive feedback
- Follow project conventions

### **Communication**
- **Issues**: Use GitHub issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Chat**: Join our community chat for real-time help

### **Getting Help**
- Check existing documentation first
- Search existing issues and discussions
- Ask specific questions with context
- Provide error messages and logs when reporting issues

## 📚 Resources

### **Learning Materials**
- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
- [OPNsense API Documentation](https://docs.opnsense.org/development/api.html)
- [Python Async/Await Guide](https://docs.python.org/3/library/asyncio.html)

### **Development Tools**
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Pytest Documentation](https://docs.pytest.org/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

## 🏆 Recognition

Contributors are recognized in several ways:

- **Contributors List**: Added to project contributors
- **Release Notes**: Mentioned in release announcements
- **Documentation**: Credit in relevant documentation sections
- **Community**: Recognition in community discussions

Thank you for contributing to making OPNsense network management more accessible and powerful! 
