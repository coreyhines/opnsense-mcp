# Traffic shaper fix pass — read-only review buckets

Generated: 2026-06-20  
Scope: **uncommitted fix-pass changes** on `feat/traffic-shaper-spec` (post `eb46194`)  
Mode: **READ ONLY** — no edits, no commits, no live MCP mutations  
Prior review: [traffic-shaper-review-session-2026-06-20.md](traffic-shaper-review-session-2026-06-20.md) (Wave 2 write path baseline)  
Coordination skill: Parallel Buckets v0.1.0 + model catalog  
Catalog: `.cursor/parallel-buckets/model-catalog.json` (scanned 2026-06-20)

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (AskQuestion, 2026-06-20) |
| Approved waves | all (FR1–FR5) |
| Notes | Model catalog configured; review executed read-only |

## Review sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 5 |
| Parallel wave 1 | FR1 ∥ FR2 ∥ FR3 ∥ FR4 |
| Ollama-local | 1 |
| Ollama-workstation | 1 |
| Ollama-cloud | 1 |
| Claude | 1 |
| Cursor | 1 |
| Estimated phases | 2 (parallel review → synthesis) |

## Diff scope (~547 LOC touched)

| Area | Files | Fix bucket ref |
|------|-------|----------------|
| Restore + envelope | `shaper_snapshot.py`, `shaper_mutation.py`, `shaper_snapshot_store.py` | F2 |
| Preset completion | `shaper_presets.py` | F3 |
| Mock write fidelity | `mock_api.py` | F4 |
| Test expansion | `tests/test_shaper_write_tools.py` | F4 |

## Bucket registry (schedule)

**Probe run:** 2026-06-20 with model catalog scan (pre-`models.choices` apply)

| Wave | ID | Title | Profile | Probe owner | **Assigned owner** | Model | Files (read) | Depends | Status |
|------|-----|-------|---------|-------------|-------------------|-------|--------------|---------|--------|
| 1 | **FR1** | Restore path + mutation envelope | `pure_logic` | Ollama-local | **Claude Code** | opus | `shaper_snapshot.py`, `shaper_mutation.py`, `shaper_snapshot_store.py` | — | **done** |
| 1 | **FR2** | `bufferbloat_wan` preset | `read_tools` | Ollama-local | **Ollama-cloud** | kimi-k2.7-code:cloud | `shaper_presets.py` | — | **done** |
| 1 | **FR3** | Mock API payload fidelity | `mock_fixtures` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `mock_api.py` | — | **done** |
| 1 | **FR4** | Write-path test assertions | `mock_fixtures` | Ollama-local | **Ollama-workstation** | qwen3:32b | `tests/test_shaper_write_tools.py` | — | **done** |
| 2 | **FR5** | Synthesis + severity rollup | `integration_merge` | Cursor auto | **Cursor** | auto | prior findings only | FR1–FR4 | **done** |

**Assigned owner** spreads backends to exercise catalog + routing paths (same pattern as fix-pass farm schedule). Probes document primary *fit*; overrides are intentional for this exercise.

### Review focus (per bucket)

| ID | Check for |
|----|-----------|
| FR1 | Restore uses get+normalize+merge (not raw search rows); pre-restore snapshot; `finish_mutation` WARNING when apply pending; deepcopy on snapshot read |
| FR2 | Four dual-stack rules; pipe/queue idempotency; ECN/FQ-CoDel params; sub-tool error propagation; 85% rate math |
| FR3 | Rule add/set honors POST payload; enum field extraction; pipe/queue gaps vs rules |
| FR4 | Error-path tests; preset four-rule assertion; restore pending_apply envelope; delete confirm flows |
| FR5 | P0/P1 rollup, regression vs first review, commit readiness |

## Merge order (synthesis)

```text
(FR1 ∥ FR2 ∥ FR3 ∥ FR4) → FR5
```

## File ownership map

| File | Review bucket |
|------|---------------|
| `opnsense_mcp/tools/shaper_snapshot.py` | FR1 |
| `opnsense_mcp/utils/shaper_mutation.py` | FR1 |
| `opnsense_mcp/utils/shaper_snapshot_store.py` | FR1 |
| `opnsense_mcp/tools/shaper_presets.py` | FR2 |
| `opnsense_mcp/utils/mock_api.py` | FR3 |
| `tests/test_shaper_write_tools.py` | FR4 |

## Do NOT (all buckets)

- Edit source or tests
- Commit or merge branches
- Run live MCP shaper mutations
- Re-run fix implementation

## Out of scope

- Already-committed Wave 2 tools in `eb46194` (covered in first review unless regression)
- `fastmcp_server.py` wiring (unchanged this diff)
- parallel-buckets product repo
- Live firewall verify

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 | [traffic-shaper-fix-review-session-2026-06-20.md](traffic-shaper-fix-review-session-2026-06-20.md) |
