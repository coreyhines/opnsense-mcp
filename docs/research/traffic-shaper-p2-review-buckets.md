# Traffic shaper — P2 read-only review buckets (post-P1)

Generated: 2026-06-20  
Baseline commit: `1e10be9` (`fix(shaper): fix-pass restore/preset hardening and P1 review fixes`)  
Branch: `feat/traffic-shaper-spec`  
Mode: **READ ONLY** — no edits, no commits, no live MCP mutations  
Prior passes: [traffic-shaper-fix-review-buckets.md](traffic-shaper-fix-review-buckets.md) (FR1–FR5), [traffic-shaper-p1-fix-buckets.md](traffic-shaper-p1-fix-buckets.md) (P1a–P1e)  
Coordination skill: Parallel Buckets v0.1.0  
Models: `parallel-buckets.local.yaml` → `models.choices` (configured 2026-06-20)

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (AskQuestion, 2026-06-20) |
| Approved waves | all (RR1–RR6) |
| Notes | Fix pass (P2) deferred until separate approval |

## Resource notes (probe 2026-06-20)

| Resource | Status | Schedule impact |
|----------|--------|-----------------|
| Claude Code | 429 / session ~86% | **Avoid** for write_crud; use Ollama-cloud or Cursor |
| Ollama cloud | week **91.3%** | Prefer local/workstation; cloud for one bucket max |
| Ollama local | OK | RR2, RR4 |
| Ollama workstation | OK, max 1 parallel farm | RR3 → RR5 sequential |
| Cursor | ~10% usage | RR6 synthesis |

## Review sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 6 |
| Parallel wave 1 | RR1 ∥ RR2 ∥ RR4 |
| Ollama-local | 2 |
| Ollama-workstation | 2 (sequential) |
| Ollama-cloud | 1 |
| Cursor | 1 |
| Estimated phases | 3 |

## Scope

Validate P1 fixes landed; re-audit deferred P2/P3 items; regression-check write CRUD tools unchanged since `eb46194`; catalog live-deploy readiness.

**In diff since P1:** mostly unchanged — review is **whole-tree** on current HEAD, focused on areas FR/P1 touched plus write CRUD regression.

## Bucket registry (schedule)

**Probe run:** 2026-06-20 (`recommend_bucket_owner.py` + limits)

| Wave | ID | Title | Profile | Probe owner | **Assigned owner** | Model | Files (read) | Depends | Status |
|------|-----|-------|---------|-------------|-------------------|-------|--------------|---------|--------|
| 1 | **RR1** | Restore + snapshot store | `write_crud` | Ollama-cloud | **Ollama-cloud** | kimi-k2.7-code:cloud | `shaper_snapshot.py`, `shaper_snapshot_store.py`, `shaper_mutation.py` | — | **done** |
| 1 | **RR2** | Preset + rate policy | `read_tools` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `shaper_presets.py` | — | **done** |
| 1 | **RR4** | Mock + write helpers | `mock_fixtures` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `mock_api.py`, `shaper_write_helpers.py` | — | **done** |
| 2 | **RR3** | Write CRUD regression | `read_tools` | Ollama-local | **Ollama-workstation** | qwen3:32b | `shaper_pipes.py`, `shaper_queues.py`, `shaper_rules.py` | RR1 | **done** |
| 3 | **RR5** | Test + doc coverage audit | `mock_fixtures` | Ollama-local | **Ollama-workstation** | qwen3:32b | `tests/test_shaper*.py`, `FUNCTION_REFERENCE.md` (shaper section) | RR3 | **done** |
| 4 | **RR6** | Synthesis + deploy readiness | `integration_merge` | Cursor | **Cursor** | auto | prior findings only | RR1–RR5 | **done** |

### Review focus (per bucket)

| ID | Verify P1 fixed | Hunt for P2/P3 |
|----|-----------------|----------------|
| RR1 | `shaper_api_result_ok` on every restore step; `resource_updates` vs settings; partial error envelope | `build_restore_plan` unused; orphan objects after restore; auto-rollback hint on failure; in-memory store limits |
| RR2 | UUID guards after pipe/queue ensure | Nested snapshots per sub-tool; `int(rate*0.85)` floor; `_ensure_pipe` set path returns stale row; partial preset `actions` on failure |
| RR3 | Delete confirm tokens; idempotent set WARNING; LAN guardrails; apply/reconfigure envelope | Regressions vs first review R1; inconsistent validation across pipe/queue/rule |
| RR4 | Pipe/queue mock payload parity with rules | Enum extraction gaps; delete/toggle mock paths; token TTL edge cases |
| RR5 | P1 tests present (API fail restore, WARNING reconfigure, mock pipe desc) | Restore field round-trip; preset partial failure; `build_restore_plan` vs restore tool drift; missing delete/toggle tests |
| RR6 | P0/P1 closed? | P2 fix bucket priorities; live MCP smoke checklist; commit/push readiness |

## Merge order

```text
(RR1 ∥ RR2 ∥ RR4) → RR3 → RR5 → RR6
```

## File ownership map

| File | Review bucket |
|------|---------------|
| `opnsense_mcp/tools/shaper_snapshot.py` | RR1 |
| `opnsense_mcp/utils/shaper_snapshot_store.py` | RR1 |
| `opnsense_mcp/utils/shaper_mutation.py` | RR1 |
| `opnsense_mcp/tools/shaper_presets.py` | RR2 |
| `opnsense_mcp/utils/mock_api.py` | RR4 |
| `opnsense_mcp/utils/shaper_write_helpers.py` | RR4 |
| `opnsense_mcp/tools/shaper_pipes.py` | RR3 |
| `opnsense_mcp/tools/shaper_queues.py` | RR3 |
| `opnsense_mcp/tools/shaper_rules.py` | RR3 |
| `tests/test_shaper*.py` | RR5 |

## Do NOT (all buckets)

- Edit source or tests
- Commit or push
- Run live MCP shaper mutations
- Implement P2 fixes (separate schedule)

## Out of scope

- parallel-buckets product repo changes
- Phase 1 read-path-only modules unless regression suspected
- Cross-MCP (CloudVision/Coroot) correlation

## Session reports

| Date | Link |
|------|------|
| _(pending)_ | [traffic-shaper-p2-review-session-2026-06-20.md](traffic-shaper-p2-review-session-2026-06-20.md) |
