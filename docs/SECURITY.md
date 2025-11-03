# Security Guide

This document outlines the security considerations and best practices for the OPNsense MCP Server.

## Table of Contents

- [SSH Security](#ssh-security)
- [API Security](#api-security)
- [Environment Variables](#environment-variables)
- [Network Security](#network-security)
- [Dependency Security](#dependency-security)
- [Reporting Security Issues](#reporting-security-issues)

## SSH Security

### Host Key Verification

The OPNsense MCP Server uses SSH for certain operations like packet capture. By default, **strict host key verification** is enabled for security.

#### Recommended Setup (Secure)

Add your OPNsense firewall's host key to your known_hosts file:

```bash
# Add the host key to known_hosts
ssh-keyscan -H your.opnsense.host >> ~/.ssh/known_hosts

# Or connect manually first to accept the key
ssh root@your.opnsense.host
```

#### Development/Testing Setup (Less Secure)

For development or initial setup in a trusted network, you can disable strict host key checking:

```bash
# In your ~/.opnsense-env file
OPNSENSE_SSH_ACCEPT_UNKNOWN_HOSTS=true
```

**⚠️ WARNING**: This setting makes your connection vulnerable to man-in-the-middle attacks. Only use this:
- In trusted, isolated networks
- During initial setup
- For development/testing purposes

**Never use this in production environments.**

### SSH Key Authentication

Always use SSH key authentication instead of passwords:

```bash
# Generate SSH key if you don't have one
ssh-keygen -t ed25519 -C "opnsense-mcp"

# Copy public key to OPNsense
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@your.opnsense.host

# Configure in ~/.opnsense-env
OPNSENSE_SSH_KEY=~/.ssh/id_ed25519
```

### SSH Configuration

Your `~/.ssh/config` can include OPNsense-specific settings:

```ssh-config
Host opnsense
    HostName your.opnsense.host
    User root
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts
```

## API Security

### API Credentials

API credentials should **never** be hardcoded. Always use environment variables:

```bash
# ~/.opnsense-env
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here
OPNSENSE_FIREWALL_HOST=your.opnsense.host
```

### File Permissions

Protect your environment file:

```bash
chmod 600 ~/.opnsense-env
```

### API Key Generation

Generate API keys with minimal required permissions:

1. Log into OPNsense web interface
2. Go to System → Access → Users
3. Edit your user or create a dedicated API user
4. Generate an API key with only the permissions needed

### SSL/TLS Verification

By default, SSL verification is disabled for self-signed certificates. In production:

```bash
# Enable SSL verification (requires valid certificate)
OPNSENSE_SSL_VERIFY=true
```

## Environment Variables

### Required Variables

```bash
OPNSENSE_API_KEY=<your-api-key>
OPNSENSE_API_SECRET=<your-api-secret>
OPNSENSE_FIREWALL_HOST=<firewall-hostname-or-ip>
```

### Optional Security Variables

```bash
# MCP secret key for JWT tokens (generate a strong random key)
MCP_SECRET_KEY=<strong-random-secret>

# SSH configuration
OPNSENSE_SSH_HOST=<ssh-hostname>
OPNSENSE_SSH_USER=root
OPNSENSE_SSH_KEY=~/.ssh/id_ed25519

# Security settings
OPNSENSE_SSL_VERIFY=false  # Set to true in production with valid cert
OPNSENSE_SSH_ACCEPT_UNKNOWN_HOSTS=false  # Never set to true in production
```

### Generating Strong Secrets

```bash
# Generate a strong MCP secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Network Security

### Firewall Rules

Ensure your OPNsense firewall allows connections from the MCP server:

- **API Access**: HTTPS (port 443)
- **SSH Access**: SSH (port 22)

Consider restricting access to specific IP addresses.

### Local Development

When developing locally, consider:

- Using a separate VLAN for management traffic
- Restricting API access to management networks
- Using VPN for remote access

## Dependency Security

### Regular Updates

Keep dependencies up to date:

```bash
# Check for outdated packages
pip list --outdated

# Update dependencies
pip install -U -r requirements.txt
```

### Security Scanning

Run security scans regularly:

```bash
# Install security tools
pip install bandit safety

# Run bandit security scanner
bandit -r opnsense_mcp/

# Check for known vulnerabilities
safety check
```

### Pre-commit Hooks

Use pre-commit hooks to catch security issues early:

```bash
# Install pre-commit
pip install pre-commit

# Set up hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Best Practices

### 1. Principle of Least Privilege

- Create dedicated API users with minimal required permissions
- Use separate SSH keys for different purposes
- Limit network access to required ports only

### 2. Secrets Management

- Never commit secrets to version control
- Use environment variables or secret management tools
- Rotate API keys and secrets regularly

### 3. Logging and Monitoring

- Enable logging for security events
- Monitor failed authentication attempts
- Review API access logs regularly

### 4. Input Validation

The MCP server validates all inputs, but when extending:

- Always validate user inputs
- Sanitize data before use in shell commands
- Use parameterized queries for database operations

### 5. Error Handling

- Don't expose sensitive information in error messages
- Log detailed errors securely, show generic messages to users
- Handle exceptions gracefully

## Security Checklist

Before deploying to production:

- [ ] API credentials stored securely in environment variables
- [ ] Strong MCP_SECRET_KEY generated and configured
- [ ] SSH host keys added to known_hosts
- [ ] SSH key authentication configured (no passwords)
- [ ] File permissions set correctly (600 for .opnsense-env)
- [ ] SSL verification enabled (if using valid certificates)
- [ ] Firewall rules configured to restrict access
- [ ] Dependencies updated and scanned for vulnerabilities
- [ ] Pre-commit hooks installed and passing
- [ ] Logging and monitoring configured
- [ ] `OPNSENSE_SSH_ACCEPT_UNKNOWN_HOSTS` set to `false` or not set

## Reporting Security Issues

If you discover a security vulnerability in the OPNsense MCP Server:

1. **Do NOT** open a public GitHub issue
2. Email the maintainers directly with details
3. Allow time for a fix to be developed and released
4. Coordinate disclosure timing

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

## Additional Resources

- [OPNsense Security Documentation](https://docs.opnsense.org/)
- [Paramiko Security Best Practices](https://www.paramiko.org/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)

## Security Updates

This document is regularly updated. Last update: November 2024

For the latest security recommendations, check the repository documentation.
