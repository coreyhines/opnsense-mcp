# Diagnostics MCP features — execution session (2026-06-28)

## Approval

| Field | Value |
|-------|-------|
| Schedule | `docs/research/diagnostics-features-buckets.md` |
| Approval | User replied `approve` |
| Scope executed | Wave 1 (`8a`, `7a`, `9a`), Wave 2 (`8b`, `7b`, `9b`), Wave 3 (`8c`, `7c`), Wave 4 (`8e`), Wave 5 (`W`), Wave 6 (`M`) |
| Commit policy | No commits unless explicitly requested |

## Attribution

| Bucket | Owner | Planned backend | Resolved backend | Cost pool | Exec | Branch | Commit | Tests | Status |
|--------|-------|-----------------|------------------|-----------|------|--------|--------|-------|--------|
| 8a | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_firewall_log_normalize.py` | success |
| 7a | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_pf_diagnostics_client.py` | success |
| 9a | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_interface_health.py` | success |
| 8b | Claude CLI | claude-cli | claude-cli | claude_subscription | external | `feat/diagnostics-mcp` | — | `test_get_logs_analysis.py`, `test_get_logs_filters.py` | success |
| 7b | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_pf_diagnostics_normalize.py` | success |
| 9b | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_interface_health_tool.py` | success |
| 8c | Claude CLI | claude-cli | claude-cli | claude_subscription | external | `feat/diagnostics-mcp` | — | `test_get_logs_rule_correlation.py`, `test_get_logs_cache.py` | success |
| 7c | Claude CLI | claude-cli | claude-cli | claude_subscription | external | `feat/diagnostics-mcp` | — | `test_pf_diagnostics_tools.py` | success |
| 8e | Cursor coordinator | ollama-local | inline fallback | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_additional_tools.py::test_get_logs_tool_success_and_client_exception` + log tests | success |
| W | Cursor coordinator | cursor-auto | inline | cursor_included | inline | `feat/diagnostics-mcp` | — | `test_fastmcp_server.py` | success |
| M | Cursor coordinator | cursor-auto | inline | cursor_included | inline | `feat/diagnostics-mcp` | — | `tests/` + FastMCP smoke | success |

Inline fallback reason: the current Ollama farmer is configured to commit automatically. The user has not explicitly requested commits in this pass, so Ollama-planned buckets were implemented in the integration branch without commits. Claude-planned bucket `8b` ran on Claude CLI / Sonnet as scheduled.

## Delivered

| Bucket | Files |
|--------|-------|
| 8a | `opnsense_mcp/utils/firewall_log_normalize.py`, `tests/test_firewall_log_normalize.py` |
| 7a | `opnsense_mcp/utils/api.py`, `tests/test_pf_diagnostics_client.py` |
| 9a | `opnsense_mcp/utils/interface_health.py`, `tests/test_interface_health.py` |
| 8b | `opnsense_mcp/tools/firewall_logs.py`, `tests/test_get_logs_analysis.py`, `tests/test_get_logs_filters.py` |
| 7b | `opnsense_mcp/utils/pf_diagnostics.py`, `tests/test_pf_diagnostics_normalize.py` |
| 9b | `opnsense_mcp/tools/interface_health.py`, `tests/test_interface_health_tool.py` |
| 8c | `opnsense_mcp/tools/firewall_logs.py`, `tests/test_get_logs_rule_correlation.py`, `tests/test_get_logs_cache.py` |
| 7c | `opnsense_mcp/tools/pf_diagnostics.py`, `tests/test_pf_diagnostics_tools.py` |
| 8e | `opnsense_mcp/tools/get_logs.py` |
| W | `opnsense_mcp/server.py`, `opnsense_mcp/fastmcp_server.py`, `opnsense_mcp/tools/__init__.py`, `tests/test_fastmcp_server.py`, `docs/REFERENCE/FUNCTION_REFERENCE.md` |
| M | Local FastMCP smoke only |

## Verification

| Check | Result |
|-------|--------|
| Ruff | `uv run ruff check ...` passed |
| Format | `uv run ruff format ...` applied; targeted files clean |
| Pytest (Wave 1) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio pytest tests/test_firewall_log_normalize.py tests/test_pf_diagnostics_client.py tests/test_interface_health.py -q` → 14 passed |
| Pytest (Wave 1+2) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio pytest tests/test_firewall_log_normalize.py tests/test_get_logs_analysis.py tests/test_get_logs_filters.py tests/test_interface_health.py tests/test_interface_health_tool.py tests/test_pf_diagnostics_client.py tests/test_pf_diagnostics_normalize.py -q` → 53 passed |
| Pytest (Wave 1+2+3) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio pytest tests/test_firewall_log_normalize.py tests/test_get_logs_analysis.py tests/test_get_logs_filters.py tests/test_get_logs_rule_correlation.py tests/test_get_logs_cache.py tests/test_interface_health.py tests/test_interface_health_tool.py tests/test_pf_diagnostics_client.py tests/test_pf_diagnostics_normalize.py tests/test_pf_diagnostics_tools.py -q` → 108 passed |
| Pytest (8e shim) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio pytest tests/test_get_logs_analysis.py tests/test_get_logs_filters.py tests/test_get_logs_rule_correlation.py tests/test_get_logs_cache.py tests/test_additional_tools.py::test_get_logs_tool_success_and_client_exception -q` → 55 passed |
| Pytest (wiring) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio pytest tests/test_fastmcp_server.py tests/test_additional_tools.py::test_get_logs_tool_success_and_client_exception tests/test_pf_diagnostics_tools.py tests/test_interface_health_tool.py tests/test_get_logs_cache.py tests/test_get_logs_rule_correlation.py -q` → 64 passed |
| Pytest (full) | `env -u VIRTUAL_ENV uv run --with pytest --with pytest-asyncio --with bandit pytest tests/ -q` → 629 passed |
| FastMCP smoke | Local `fastmcp.client.Client(build_mcp_server())` exposed `55` tools and returned `status=success` for `get_logs`, `pf_states`, `pf_statistics`, and `interface_health` |

Pytest note: `.venv` did not have pytest installed, and bare `uv run pytest` resolved to a global Homebrew pytest without project dependencies. The successful gate used transient pytest dependencies via `uv run --with`.

## Next wave

Implementation complete. Remaining release steps:

- Review diff and decide whether to commit/push.
- Deploy/restart the configured MCP server before expecting the already-connected Cursor MCP tool list to show the three new tools.

