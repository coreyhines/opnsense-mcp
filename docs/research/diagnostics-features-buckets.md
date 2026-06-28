# Diagnostics MCP features — bucket plan (#7 + #8 + #9)

Generated: 2026-06-28  
Specs: GitLab [#7](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/7), [#8](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/8), [#9](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/9) (v2 in issue comments)  
Phase 0: [diagnostics-features-phase0-session-2026-06-28.md](diagnostics-features-phase0-session-2026-06-28.md)  
Integration branch: `feat/diagnostics-mcp`  
Coordination skill: Parallel Buckets v0.1.0

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (2026-06-28) |
| Approved waves | all |
| Notes | Execute with Claude CLI spend-down preference; no commits unless explicitly requested |

## Phase 0 outcomes (done — coordinator)

| Item | Status |
|------|--------|
| Live log shape + analysis bug | ✅ |
| Interface list inventory | ✅ |
| `query_states` row payload | ✅ |
| `pf_states` meta (current/limit) | ✅ |
| `pf_statistics` payload | ⚠️ empty `[]` — fallback in 7b |
| Fixtures under `tests/fixtures/phase0-diagnostics/` | ✅ |

## Bucket sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 12 |
| Parallel wave 1 | 8a ∥ 7a ∥ 9a |
| Claude buckets | 3 (`8b`, `8c`, `7c`) |
| Ollama-local buckets | 5 |
| Cursor buckets | 4 (1 spike done, 3 inline) |
| Estimated phases | 5 waves + merge |

## Session status

| Field | Value |
|-------|-------|
| **Level** | YELLOW |
| **Updated** | 2026-06-28 |
| **Claude session %** | unavailable (429) |
| **Cursor total %** | ~54% |
| **Note** | Use Claude CLI for substantive behavior/tool buckets until actual session limit is near; reroute only when Claude CLI is blocked or >=95% |

## Routing preference

This project intentionally spends Claude Code capacity on buckets where Sonnet can improve implementation quality. Claude usage API failures or 80%+ warning bands are **not** reasons to avoid Claude by default; they are signals to probe `claude -p` and keep farming until the session is effectively exhausted. Reroute Claude-planned buckets only when the CLI itself is blocked, the session is at/above the hard limit, or the user explicitly chooses to conserve quota.

## Spec delta from Phase 0

- **#7:** Implement state **listing** via `POST /api/diagnostics/firewall/query_states` (not `pf_states` rows). Keep `GET pf_states` for table pressure only.
- **#7:** `pf_statistics` may return `[]` — health from `current`/`limit` when counters absent.
- **#8:** Target `firewall_logs.py`; dedupe `get_logs.py` in bucket 8e.
- **#9:** No extra statistics API on fw.freeblizz.com; `interface_list` output is primary source.

## Bucket registry

| Wave | ID | Title | Profile | Anthropic | Owner | Backend | Model | Exec | Files (own) | Depends | Issue |
|------|-----|-------|---------|-----------|-------|---------|-------|------|-------------|---------|-------|
| 0 | P0 | Phase 0 fixtures + report | `spike` | none | Cursor | inline | auto | inline | `tests/fixtures/phase0-diagnostics/*`, `docs/research/diagnostics-features-phase0-session-2026-06-28.md` | — | all |
| 1 | 8a | Log normalize helpers + tests | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/utils/firewall_log_normalize.py`, `tests/test_firewall_log_normalize.py`, fixture copy from phase0 | P0 | #8 |
| 1 | 7a | PF client methods + query_states tests | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/utils/api.py` (client methods only), `tests/test_pf_diagnostics_client.py`, fixtures | P0 | #7 |
| 1 | 9a | Interface health utils + tests | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/utils/interface_health.py`, `tests/test_interface_health.py`, fixtures | P0 | #9 |
| 2 | 8b | Fix analysis, filters, cache in firewall_logs | `pure_logic` | sonnet | Claude | claude-cli | sonnet | — | `opnsense_mcp/tools/firewall_logs.py`, `tests/test_get_logs_analysis.py`, `tests/test_get_logs_filters.py` | 8a | #8 |
| 2 | 7b | PF normalize/filter/summarize | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/utils/pf_diagnostics.py`, `tests/test_pf_diagnostics_normalize.py` | 7a | #7 |
| 2 | 9b | interface_health tool | `read_tools` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/tools/interface_health.py`, `tests/test_interface_health_tool.py` | 9a | #9 |
| 3 | 8c | Rule correlation + summary_only | `read_tools` | sonnet | Claude | claude-cli | sonnet | — | `opnsense_mcp/tools/firewall_logs.py`, `tests/test_get_logs_rule_correlation.py`, `tests/test_get_logs_cache.py` | 8b | #8 |
| 3 | 7c | pf_states + pf_statistics tools | `read_tools` | sonnet | Claude | claude-cli | sonnet | — | `opnsense_mcp/tools/pf_diagnostics.py`, `tests/test_pf_diagnostics_tools.py` | 7b | #7 |
| 4 | 8e | Consolidate get_logs.py shim | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | — | `opnsense_mcp/tools/get_logs.py`, `opnsense_mcp/tools/__init__.py` | 8c | #8 |
| 5 | W | MCP wiring + docs (52→55 tools) | `mcp_wiring` | none | Cursor | cursor-auto | auto | inline | `opnsense_mcp/server.py`, `opnsense_mcp/fastmcp_server.py`, `tests/test_fastmcp_server.py`, `docs/REFERENCE/FUNCTION_REFERENCE.md` | 7c, 8e, 9b | all |
| 6 | M | Integration pytest + live MCP smoke | `integration_merge` | none | Cursor | cursor-auto | auto | inline | — | W | all |

### Bucket notes

**8a — Do NOT:** touch `firewall_logs.py` yet; only pure normalize module.

**7a — Do NOT:** implement tools; add `query_states`, `get_pf_state_table_meta`, `get_pf_statistics` client methods. Document `query_states` as primary list endpoint in docstrings.

**7b — Do NOT:** call MCP; map `src_addr`→`src`, handle empty statistics + meta fallback for `usage_percent`.

**8b — Do NOT:** enable rule correlation (`include_rules` stays false default until 8c).

**W — Do NOT:** change tool bodies; register `pf_states`, `pf_statistics`, `interface_health`; extend `get_logs` params; assert tool count **55**.

**M — Live smoke:** `get_logs limit=20`, `pf_states limit=10`, `pf_statistics`, `interface_health warnings_only=true`.

## Merge order

```text
P0 (done)
→ (8a ∥ 7a ∥ 9a)
→ (8b ∥ 7b ∥ 9b)
→ (8c ∥ 7c)
→ 8e
→ W
→ M
```

## File ownership map

| File | Bucket |
|------|--------|
| `opnsense_mcp/utils/firewall_log_normalize.py` | 8a |
| `opnsense_mcp/tools/firewall_logs.py` | 8b, 8c |
| `opnsense_mcp/utils/pf_diagnostics.py` | 7b |
| `opnsense_mcp/tools/pf_diagnostics.py` | 7c |
| `opnsense_mcp/utils/interface_health.py` | 9a |
| `opnsense_mcp/tools/interface_health.py` | 9b |
| `opnsense_mcp/utils/api.py` (PF methods) | 7a |
| `opnsense_mcp/fastmcp_server.py`, `server.py` | W only |

## Out of scope

- GeoIP / SIEM / mutation of PF or interfaces
- Rate/delta interface metrics (future tool)
- SSH fallback
- Pi-hole or non-OPNsense correlation

## Open questions (resolve before or during execute)

- [ ] `pf_statistics` empty on live — confirm acceptable fallback in 7b or expand API key ACL
- [ ] Post v2 comment on GitLab #7 documenting `query_states` endpoint change

## Session reports

| Date | Chat posted | File |
|------|-------------|------|
| 2026-06-28 | yes | `diagnostics-features-phase0-session-2026-06-28.md` |
| 2026-06-28 | yes | `diagnostics-features-session-2026-06-28.md` |

## Execution status

| Bucket | Status | Owner | Backend | Tests | Commit |
|--------|--------|-------|---------|-------|--------|
| P0 | done | Cursor | inline | live probes | — |
| 8a | done | Cursor (coordinator) | inline fallback | `test_firewall_log_normalize.py` | — |
| 7a | done | Cursor (coordinator) | inline fallback | `test_pf_diagnostics_client.py` | — |
| 9a | done | Cursor (coordinator) | inline fallback | `test_interface_health.py` | — |
| 8b | done | Claude CLI / Sonnet | claude-cli | `test_get_logs_analysis.py`, `test_get_logs_filters.py` | — |
| 7b | done | Cursor (coordinator) | inline fallback | `test_pf_diagnostics_normalize.py` | — |
| 9b | done | Cursor (coordinator) | inline fallback | `test_interface_health_tool.py` | — |
| 8c | done | Claude CLI / Sonnet | claude-cli | `test_get_logs_rule_correlation.py`, `test_get_logs_cache.py` | — |
| 7c | done | Claude CLI / Sonnet | claude-cli | `test_pf_diagnostics_tools.py` | — |
| 8e | done | Cursor (coordinator) | inline fallback | `test_additional_tools.py::test_get_logs_tool_success_and_client_exception` + log tests | — |
| W | done | Cursor (coordinator) | inline | `test_fastmcp_server.py` | — |
| M | done | Cursor (coordinator) | inline | `tests/` full suite + local FastMCP smoke | — |

Note: Wave 1 was executed inline after approval to avoid the current farmer's automatic commit behavior. Claude-planned buckets remain on Claude CLI for Wave 2/3 spend-down.

Wave 2 note: `8b` was executed through Claude CLI / Sonnet as planned. `7b` and `9b` were executed inline to keep the tree uncommitted while the current non-Claude farmer path auto-commits.

Wave 3 note: `8c` and `7c` both executed through Claude CLI / Sonnet in parallel, with no commits.

Wave 4 note: `8e` executed inline to replace the duplicate legacy `get_logs.py` implementation with a compatibility shim around canonical `firewall_logs.py`.

Wave 5/M note: wiring and integration smoke executed inline. Local FastMCP smoke exposed 55 tools and returned success for `get_logs`, `pf_states`, `pf_statistics`, and `interface_health`.
