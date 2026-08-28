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

## MCP-first live operations

For homelab changes (DHCP, DNS, firewall), **use MCP tools** against the deployed server — not `uv run python` with `get_opnsense_client()` in this repo. See `.cursor/rules/mcp-first.mdc`. Fallback only when MCP is errored or no tool exists; say why.

**Testing MCP:** agent sessions using MCP tools (primary), `python benchmark_performance.py` (live smoke), `uv run pytest tests/` (unit). Workspace Python bypasses the MCP protocol path.

## Code Standards

- Python 3.12+, typing annotations and docstrings on all functions/classes
- Use `uv` for dependency management
- Ruff for linting and formatting (f-strings preferred except where they cause TRY401 issues)
- pytest (not unittest) for all tests; place tests in `./tests/` with `__init__.py`
- Do not break existing functionality during cleanup or formatting passes

## Failure modes this project has already paid for

Each of these shipped a defect. They are listed because intending to avoid them
did not work; the checks did.

**A safety claim needs a falsification test, not a happy-path test.**
`set_interface_address` documented "parsed by ipaddress, so injection fails to
parse". Nobody tested the claim, and it was false for IPv6 scope ids
(`fe80::1%$(reboot)` parses). Its read-back was a substring match, so
`198.51.100.1` was satisfied by `198.51.100.10`. When a docstring says a thing
is safe, write the test that tries to break it in that exact way.

**Assert on structured fields, not on message wording.** Four assertions here
tested phrasing and passed or failed for the wrong reason (`"enable"` is not a
substring of `"enabling"`). Assert `result["status"]`, `result["applied"]`, the
absence of a key — not that an error message contains a chosen phrase.

**Cleanup must be gated on the step it undoes.** A `finally` that deleted a
device regardless of whether the unassign succeeded left an orphaned,
lock-protected interface on the live firewall. Teardown checks the previous
step's result before proceeding.

**Never chain a gate with `;`.** `ruff check . ; git commit && git push` pushes
a lint failure, because the pipeline reports the last command. Use `&&`
throughout. This pushed broken commits three times in one session.

**Replace a sweep with a test.** Two grep-based reference sweeps missed
`README.md` at the repository root. `tests/test_review_wave4.py` now walks every
markdown file and fails on a tool name the registry does not know. When
removing or renaming something, the deliverable is the test, not the grep.

**Read the error body before concluding an API cannot do something.**
`del_item` returning 500 was declared undoable; the body said "Interface
locked, unset lock first before removal". The fix was three commands.

**Probe scripts run against the live firewall and deserve the same care as
tools.** Every orphan left on the firewall this session came from a throwaway
script, not from a tool. A probe named `test_*` at the repository root is worse:
pytest collects it, so a routine test run opens live connections. Keep probes
out of the collection path.

**Three of these are enforced now, not remembered.**
`.claude/hooks/bash_guard.py` runs as a `PreToolUse` hook on every Bash call. It
refuses the `;`-chained publish and the bare-cat heredoc, and warns on workspace
Python calling `get_opnsense_client()`. `tests/test_bash_guard.py` holds the
falsification cases, including the one where the guard blocked its own commit
for quoting a pattern it forbids. Everything else on this list is still read
rather than run.
