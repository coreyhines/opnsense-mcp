# Session report — traffic shaper P2 review (Parallel Buckets)

**Date:** 2026-06-20  
**Branch:** `feat/traffic-shaper-spec` @ `1e10be9`  
**Mode:** Read-only review (RR1–RR6)  
**Skill:** Parallel Buckets v0.1.0  
**Bucket plan:** [traffic-shaper-p2-review-buckets.md](traffic-shaper-p2-review-buckets.md)  
**Prior:** P1 complete ([traffic-shaper-p1-fix-buckets.md](traffic-shaper-p1-fix-buckets.md)); FR pass ([traffic-shaper-fix-review-session-2026-06-20.md](traffic-shaper-fix-review-session-2026-06-20.md))

## Summary table

| Bucket | Owner | Model | Status | Top finding |
|--------|-------|-------|--------|-------------|
| RR1 | Ollama-cloud | kimi-k2.7-code:cloud | done | P1 API checks landed; `build_restore_plan` still unused; no orphan handling |
| RR2 | Ollama-local | qwen3.6:35b-a3b-mxfp8 | done | UUID guards landed; nested snapshots + rate floor remain |
| RR3 | Ollama-workstation | qwen3:32b | done | Write CRUD solid; LAN warn rules-only; each mutation still snapshots |
| RR4 | Ollama-local | qwen3.6:35b-a3b-mxfp8 | done | Pipe/queue mock payload parity **fixed** in P1; codel_ecn not in mock rows |
| RR5 | Ollama-workstation | qwen3:32b | done | 275 tests pass; gaps: preset partial, restore fidelity, plan executor |
| RR6 | Cursor | auto | done | **Ready for P2 fix pass**; live MCP smoke still not run |

## P1 regression check

| P1 item | Status |
|---------|--------|
| Restore API status checks | **Verified** — `_require_ok` + `shaper_api_result_ok` on set_pipe/queue/rule/settings |
| Mock pipe/queue payload | **Verified** — `_payload_scalar` on add/set |
| Preset UUID guards | **Verified** — raises before queues/rules if pipe/queue UUID missing |
| WARNING on reconfigure fail | **Verified** — test `test_add_shaper_pipe_warning_when_reconfigure_fails` |
| Restore fail on API error | **Verified** — test `test_restore_shaper_snapshot_fails_on_api_error` |

## Cross-bucket findings (prioritized)

### P2 — fix before live deploy (scheduled)

1. **Restore executor duplicates `build_restore_plan`** (RR1) — inline loops in `shaper_snapshot.py`; store helper emits raw `flat_data` not serialize path. Refactor bucket P2a.
2. **No orphan cleanup on restore** (RR1) — objects created after snapshot remain. User approved **opt-in** `remove_orphans=False` default → P2b.
3. **Preset nested snapshots** (RR2, RR3) — preset calls sub-tools with default snapshot capture (~10 store entries per run). P2c.
4. **Rate floor policy** (RR2) — `int(dl_rate * 0.85)` truncates (e.g. 33.3 → 28). Document or `round()`. P2d.
5. **`_ensure_pipe` / `_ensure_queue` set path returns stale search row** (RR2) — UUID OK via fallback search; bandwidth in returned dict may be stale. P2e.

### P3 — quality / nits

6. **Mock omits CoDel ECN fields on pipe rows** (RR4) — preset sets `codel_ecn_enable`; mock search rows don't persist ECN on add (scheduler only). Low impact on unit tests; live API differs.
7. **Restore error hints** (RR1) — partial failure returns `pre_restore_snapshot_id` but summary doesn't suggest restore command.
8. **LAN shaping guard** (RR3) — `warn_lan_interface` on rules only, not pipes/queues.
9. **Settings step in `results` but not `restored` count** (RR1) — intentional after P1; document in tool description.

### Test gaps (P2f)

| Missing test | Priority |
|--------------|----------|
| Preset partial failure (`partial: True`, `actions` list) | high |
| Restore bandwidth/description round-trip after mutate+restore | medium |
| `build_restore_plan` steps executed same as restore tool | medium |
| Opt-in orphan deletion (mock) | medium (after P2b) |
| Queue/rule mock greenfield idempotency by description | low |

## Bucket detail

### RR1 — Restore + snapshot store

**Good:** Serialize restore path; pre-restore snapshot; fail-fast with `partial_results`; `resource_updates` excludes settings-only step from count.

**Remaining:** `build_restore_plan()` unused by tool; no orphan deletion; no auto-hint to restore from `pre_restore_snapshot_id` on failure.

### RR2 — Preset

**Good:** Four rules, queue targets, FQ-CoDel + ECN params, UUID guards with search fallback, partial error envelope with `actions`.

**Remaining:** Single parent snapshot only at preset level — sub-tools still capture independently when called outside preset. Rate truncation.

### RR3 — Write CRUD regression

**Good:** Delete confirm tokens; idempotent set → WARNING; validation helpers; consistent `finish_mutation` envelope across pipe/queue/rule.

**No regressions** vs first review R1 relative to P1 baseline.

### RR4 — Mock + helpers

**Good:** P1 pipe/queue payload parity matches rules pattern.

**Gap:** Mock pipe `add_pipe` row lacks codel_* fields; not blocking pytest.

### RR5 — Tests

**Good:** 275 shaper tests pass (2026-06-20).

**Gaps:** Listed above; no `test_shaper_write_tools` coverage for preset mid-flight failure.

### RR6 — Synthesis

**Verdict:** P1 objectives met. Proceed to **P2 fix pass** per [traffic-shaper-p2-fix-buckets.md](traffic-shaper-p2-fix-buckets.md).

**Not done:** Live MCP write smoke (defer to P2h after fixes).

## Integration health

| Check | Result |
|-------|--------|
| `uv run pytest tests/test_shaper*.py` | 275 passed |
| Model catalog | configured, valid |
| Live MCP | not run |

## Approval record

| Field | Value |
|-------|-------|
| Review schedule | approved (RR1–RR6, 2026-06-20) |
| Fix schedule | pending separate approval |
| Orphan delete | user: opt-in only (default False) |

## Recommended fix order

```text
(P2a ∥ P2e) → P2d → P2c → P2b → P2f → P2g → P2h
```
