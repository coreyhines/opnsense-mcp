# Session report — traffic shaper fix-pass review (Parallel Buckets)

**Date:** 2026-06-20  
**Branch:** `feat/traffic-shaper-spec` (uncommitted fix delta on `eb46194`)  
**Mode:** Read-only review (no code changes)  
**Skill:** Parallel Buckets v0.1.0 + model catalog setup  
**Bucket plan:** [traffic-shaper-fix-review-buckets.md](traffic-shaper-fix-review-buckets.md)  
**Prior review:** [traffic-shaper-review-session-2026-06-20.md](traffic-shaper-review-session-2026-06-20.md)

## Model catalog (setup)

| Step | Result |
|------|--------|
| Scan | `.cursor/parallel-buckets/model-catalog.json` — local, cloud, morpheus OK |
| User choices | Saved to `parallel-buckets.local.yaml` → `models.choices` |
| Validation | No issues |

**Configured models:** local `qwen3.6:35b-a3b-mxfp8` (standard + fast), cloud `kimi-k2.7-code:cloud`, workstation `qwen3:32b`, Cursor `auto`.

## Summary table

| Bucket | Owner | Model | Status | Top finding |
|--------|-------|-------|--------|-------------|
| FR1 | Claude Code | opus | done | Restore serialize path fixed; still no API error checks / orphan handling |
| FR2 | Ollama-cloud | kimi-k2.7-code:cloud | done | Preset now matches spec (4 rules, queues, ECN); missing UUID guards |
| FR3 | Ollama-local | qwen3.6:35b-a3b-mxfp8 | done | Rule mock honors payload; pipe/queue mock still generic |
| FR4 | Ollama-workstation | qwen3:32b | done | Tests expanded; still no WARNING/partial-restore coverage |
| FR5 | Cursor | auto | done | Fix pass clears first-review P0s; P1 mock fidelity + restore hardening remain |

## Portfolio utilization (exercise)

| Resource | Bucket | Notes |
|----------|--------|-------|
| Claude Code | FR1 | Opus-tier restore/mutation review |
| Ollama-cloud | FR2 | kimi-k2.7-code:cloud preset review |
| Ollama-local | FR3 | mock_api review (user mapped fast=standard) |
| Ollama-workstation | FR4 | test coverage review |
| Cursor | FR5 | synthesis |

## Regression vs first review (P0 status)

| First-review P0 | Fix-pass status |
|-----------------|-----------------|
| Preset incomplete | **Resolved** — `PRESET_RULES` ×4, queues, FQ-CoDel + ECN, sub-tool `_require_tool_success` |
| Restore untrusted | **Mostly resolved** — get+normalize+merge, `settings_get` replay, pre-restore snapshot, deepcopy read |
| Queue/rule hardening | **Resolved in `eb46194`** — not re-reviewed this pass (out of diff scope) |

## Cross-bucket findings (prioritized)

### P1 — before live MCP deploy

1. **Restore ignores per-step API failures** (FR1) — loops append results without checking `status` / error keys; partial success returns `success`.
2. **Mock pipe/queue mutations still generic** (FR3) — only rules use POST payload; `add_pipe`/`set_pipe`/`add_queue` keep placeholder descriptions/bandwidth; greenfield preset idempotency relies on fixture rows.
3. **Preset missing empty-UUID guard** (FR2) — if pipe add fails to yield UUID, queues/rules proceed with empty `pipe_uuid` / `target_uuid`.

### P2 — quality / maintainability

4. **Nested snapshots in preset** (FR2) — each sub-tool calls `capture_pre_mutation_snapshot`; one preset run creates many store entries (unchanged from first review).
5. **`build_restore_plan` unused** (FR1) — restore tool duplicates logic inline; plan helper still emits raw `flat_data` shape.
6. **Restore cannot remove orphans** (FR1) — replay sets known UUIDs only; objects created after snapshot remain.
7. **Rate truncation** (FR2) — `int(rate * 0.85)` floors Mbps; document or round explicitly.
8. **Test gaps** (FR4) — no test for `finish_mutation` → `WARNING` when reconfigure fails; no restore field-level fidelity; no mock pipe payload tests.

### P3 — nits

9. **`_ensure_pipe` set path** returns stale `existing` row (FR2) — UUID OK via search fallback.
10. **`restored` count includes settings step** (FR1) — metric mixes resource types.

## Bucket detail

### FR1 — Restore + mutation envelope (Claude / opus)

**Fixed since first review:** `get_pipe`/`get_queue`/`get_rule` + normalize + merge; `settings_get` POST; `pre_restore_snapshot_id`; `get_snapshot()` deepcopy; `finish_mutation` elevates to `WARNING` when `apply=True` and `pending_changes`.

**Remaining:**

- No validation of `set_*` / `set_settings` responses before counting success.
- On exception, returns error with `partial_results` but does not auto-offer restore from `pre_restore_id`.
- Snapshot store still in-memory only (documented).

### FR2 — `bufferbloat_wan` preset (Ollama-cloud / kimi-k2.7-code:cloud)

**Fixed since first review:** Four dual-stack rules; download/upload queues; FQ-CoDel + `codel_ecn_enable`; 85% rate math; try/except with partial `actions`; `_require_tool_success` on sub-tools.

**Remaining:**

- No upfront assert that `dl_uuid`, `ul_uuid`, `dl_q_uuid`, `ul_q_uuid` are non-empty before downstream steps.
- Rules correctly target **queues** (not pipes) — fixes first-review critical #7.
- `_require_tool_success` allows `WARNING`+`idempotent` — correct for set idempotency.

### FR3 — Mock API (Ollama-local)

**Improved:** `_payload_scalar`, rule add/set honor serialized payload; `_make_request` passes JSON to shaper mock.

**Gap:** `_handle_pipe_action` / `_handle_queue_action` ignore payload (still `"New pipe"` / `"Updated pipe …"`). Preset tests pass because fixture already has named pipes/queues; add-path idempotency by description would fail on fresh mock state.

### FR4 — Tests (Ollama-workstation / qwen3:32b)

**Added:** no-client queue, invalid pipe/target, delete confirm queue/rule, preset four-rule presence, restore `pending_apply` envelope.

**Still missing:** reconfigure-failure WARNING, preset partial failure, restore value round-trip, pipe mock fidelity.

### FR5 — Synthesis (Cursor / auto)

**Verdict:** Fix pass is **commit-worthy** for the Wave 2 hardening delta with noted P1 follow-ups. Recommend commit message scope: F2–F4 fix pass + model catalog overlay.

**Suggested next buckets (implementation, not review):**

- Mock pipe/queue payload parity (small bucket)
- Restore API status checks + optional rollback hint (small bucket)
- Test bucket for WARNING + restore fidelity

## Integration health

| Check | Result |
|-------|--------|
| `uv run pytest tests/test_shaper*.py` | 271 passed (per fix pass) |
| Model catalog | configured, validated |
| Live MCP write smoke | not run (read-only pass) |

## Approval record

| Field | Value |
|-------|-------|
| Schedule | approved_all (2026-06-20) |
| Model setup | AskQuestion completed |
