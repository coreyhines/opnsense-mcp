# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that exposes OPNsense firewall management capabilities to AI assistants. It provides tools for querying ARP/NDP tables, DHCP leases, firewall logs, LLDP neighbors, interface lists, firewall rules, and system status.

## Environment Variables

All connection credentials come from environment variables, typically loaded from `~/.env` (see `opnsense_mcp/utils/env.py`):

```
OPNSENSE_FIREWALL_HOST   # Hostname/IP of the OPNsense firewall
OPNSENSE_API_KEY         # OPNsense API key
OPNSENSE_API_SECRET      # OPNsense API secret
```

## Commands

```bash
# Run all tests
uv run pytest tests/

# Run a single test file
uv run pytest tests/test_arp.py

# Run a single test
uv run pytest tests/test_arp.py::test_function_name

# Lint and format
uv run ruff check .
uv run ruff format .

# Benchmark all tools against a live firewall
python benchmark_performance.py
python benchmark_performance.py --output results.json --verbose
```

## Architecture

```
opnsense_mcp/
├── server.py           # MCP server entry point; exports get_opnsense_client()
├── tools/              # One file per MCP tool exposed to the AI
│   ├── arp.py          # ARPTool
│   ├── dhcp.py         # DHCPTool
│   ├── fw_rules.py     # FwRulesTool
│   ├── get_logs.py     # GetLogsTool
│   ├── interface_list.py # InterfaceListTool
│   ├── lldp.py         # LLDPTool
│   └── system.py       # SystemTool
└── utils/
    └── api_optimized.py  # OptimizedOPNsenseClient — direct HTTP with pre-computed auth headers
```

**Request flow**: MCP client → `server.py` → Tool class → `OptimizedOPNsenseClient` → OPNsense REST API (`https://<host>/api/...`)

**Client design**: `OptimizedOPNsenseClient` uses `requests` (not pyopnsense) with Basic auth headers pre-computed at init time, `verify=False` for self-signed certs, and aggressive timeouts (2–3 seconds). Sync HTTP calls are run in a thread executor so tool `execute()` methods can be async.

**Tool pattern**: Each tool takes a client instance and implements `async execute(args: dict) -> dict`.

## Git Commits and Pushes

`cat` is aliased to `bat` (a syntax-highlighting pager) in this shell. This means `$(cat <<'EOF'...EOF)` heredocs used for commit messages get wrapped in ANSI color escape sequences, which are stored literally in the commit message.

Always use `\cat` (backslash bypasses the alias) when constructing commit messages:

```bash
git commit -m "$(\cat <<'EOF'
your message here

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

Never use bare `cat` in a commit message heredoc.

## OPNsense MCP Output

When displaying results from OPNsense MCP tools, summarize the data in a human-readable format (tables, bullet points, or prose). Do not show raw JSON unless the user explicitly asks for it.

## Code Standards

- Python 3.12+, typing annotations and docstrings on all functions/classes
- Use `uv` for dependency management
- Ruff for linting and formatting (f-strings preferred except where they cause TRY401 issues)
- pytest (not unittest) for all tests; place tests in `./tests/` with `__init__.py`
- Do not break existing functionality during cleanup or formatting passes
