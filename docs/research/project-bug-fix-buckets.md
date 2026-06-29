# Project bug fix buckets — 2026-06-28

Approved by: User ("run the fix buckets")  
Source: `docs/research/project-bug-scrub-session-2026-06-28.md`  
Branch: `feat/project-bug-fixes`

## Execution schedule

| Bucket | Theme | Owner | Backend | Status |
|--------|-------|-------|---------|--------|
| F1 | Honest mutation status / apply | Cursor | inline | done |
| F2 | Firewall rule update/delete | Cursor | inline | done |
| F3 | Shaper guardrails | Cursor | inline | done |
| F4 | Silent read-tool failures | Cursor | inline | done |
| F5 | MCP stdio shaper parity | Cursor | inline | done |
| F6 | DHCP/DNS edge cases | Cursor | inline | done |
| F7 | CI/deploy hygiene | Cursor | inline | done |
| F8 | Input validation envelopes | Cursor | inline | done |

F5 implemented via a `shaper_tools` registry threaded into `handle_message` as one
keyword-only param (instead of 25 positional args): registry-driven `tools/list`
entries and a generic `tools/call` dispatch. The stdio server (`server.py`,
launched by `mcp_start.sh`) now exposes the same 25 traffic-shaper tools as
`fastmcp_server.py`. Existing direct callers/tests are unaffected (param defaults
to `None`).
