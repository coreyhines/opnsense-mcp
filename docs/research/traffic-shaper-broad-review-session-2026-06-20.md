# Session report — traffic shaper broad read-path review

**Date:** 2026-06-20  
**Branch:** `feat/traffic-shaper-spec` (includes uncommitted P2 fixes)  
**Mode:** Read-only (BR1–BR5)  
**Plan:** [traffic-shaper-broad-review-buckets.md](traffic-shaper-broad-review-buckets.md)

## Summary table

| Bucket | Owner | Status | Top finding |
|--------|-------|--------|-------------|
| BR1 | Ollama-local | done | Read path solid; `search_*` capped at 50 rows |
| BR2 | Ollama-workstation | done | Audit + drift detection strong; stats lack util/drop hints |
| BR3 | Ollama-local | done | Normalize/serialize contract stable; heavy pytest coverage |
| BR4 | Cursor | done | All 26 tools registered; MCP missing `remove_orphans` wire |
| BR5 | Cursor | done | Read path homelab-ready; one P1 wiring gap |

## Cross-bucket findings (prioritized)

### P1 — wire before redeploy

1. **MCP `restore_shaper_snapshot` omits `remove_orphans`** (BR4) — tool class supports opt-in orphan cleanup (P2b); FastMCP wrapper only passes `snapshot_id` + `apply`. Agents using MCP cannot enable orphan removal.

### P2 — quality / spec gaps

2. **`SEARCH_BODY` rowCount=50** (BR1) — all list/search/audit paths share this cap. Fine for homelab fixtures; large configs truncate silently.

3. **Statistics interpretation incomplete vs spec** (BR2) — `interpret_statistics` covers scheduler drift + zero-pkts rules; spec also mentions drops, util vs cap, ECN runtime signals. Not implemented in interpret layer.

4. **`set_shaper_settings` POSTs `{}`** (BR1) — write stub on global settings; read path unaffected but audit/explain never surface global toggle changes via this tool.

5. **FUNCTION_REFERENCE stale vs P2** (BR4) — no mention of `remove_orphans`, `rate_policy`, or preset rounding policy.

### P3 — nits

6. **`explain_shaper_config(include_audit=False)`** returns `success` even when drift exists (BR2) — intentional; document that audit should stay on for ops triage.

7. **In-memory baseline store** (BR2) — same session-scoped model as snapshots; acceptable for v1 SSE workers.

8. **Mock fixture has 2 rules** (BR1 tests) — audit `IPV6_MISSING` path less exercised in unit tests than production 4-rule preset.

## Bucket detail

### BR1 — Read tools + settings

**Good:**
- Shared helpers (`search_shaper_*`, `fetch_shaper_settings_raw`, `settings_from_ts`) used consistently.
- `GetShaperPipeTool` uses `get_pipe/{uuid}` then search fallback; list tools filter client-side.
- `ShaperStatisticsTool` wires interpret + baseline store cleanly.
- `GetShaperSettingsTool` unwraps nested `ts` tree correctly.

**Gaps:** pagination cap; get queue/rule mirror pipe pattern (OK).

### BR2 — Audit + interpret

**Good:**
- `SCHEDULER_DRIFT` → critical in both `interpret_statistics` and `run_audit`.
- Audit checklist matches spec themes: FQ-CoDel, IPv6 dual-stack, ISP/line bandwidth, ECN, LAN shaping, queue/pipe attachment, rule targets queue not pipe.
- `explain_shaper_config` narrative is user-safe (descriptions/bandwidth only, no credentials).
- Tests: drift critical, baseline delta, audit ISP params, explain with/without audit.

**Gaps:** no drop/util interpretation; explain without audit skips statistics fetch entirely.

### BR3 — Normalize + serialize contract

**Good:**
- `parse_boolish`, `selected_enum`, normalize pipe/queue/rule handle search rows + settings/get enums.
- `test_shaper_serialize.py` (38 tests) + `test_shaper_normalize.py` (74 tests) guard round-trip.
- Write path depends on same contract — no breaking drift observed.

### BR4 — MCP register + docs

**Good:**
- `test_shaper_mcp_register.py` — all 10 read + 16 write tool names present in FastMCP `list_tools`.
- `FUNCTION_REFERENCE.md` shaper section lists read/write tables and agent workflows.

**Gaps:**
- `restore_shaper_snapshot` MCP signature missing `remove_orphans: bool = False`.
- Docs not updated for P2 preset/restore structured fields.

### BR5 — Synthesis

**Verdict:** Read/audit/explain path is **homelab-ready**. Scheduler drift detection matches Phase 0 spike findings. Before live MCP redeploy, fix the **`remove_orphans` wiring gap** (small bucket). Optional follow-up: stats util/drop hints + search pagination.

## Integration health

| Check | Result |
|-------|--------|
| `tests/test_shaper_read_tools.py` | 17 passed |
| `tests/test_shaper_interpret.py` | 36 passed |
| `tests/test_shaper_audit_rules.py` | 23 passed |
| `tests/test_shaper_mcp_register.py` | 3 passed |
| Live MCP read smoke | not run (read-only pass) |

## Suggested fix buckets (implementation, not done)

| ID | Title | Files |
|----|-------|-------|
| BR-fix-a | Wire `remove_orphans` in FastMCP + docs | `fastmcp_server.py`, `FUNCTION_REFERENCE.md` |
| BR-fix-b | Statistics util/drop hints | `shaper_interpret.py`, tests |
| BR-fix-c | Search pagination or rowCount param | `shaper_settings.py`, list tools |

## Approval record

| Field | Value |
|-------|-------|
| Schedule | approved all BR1–BR5 (2026-06-20) |
| Execution | read-only, no code changes |
