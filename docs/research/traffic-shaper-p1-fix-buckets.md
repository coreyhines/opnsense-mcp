# Traffic shaper — P1 fix buckets (post fix-review)

Generated: 2026-06-20  
Source: [traffic-shaper-fix-review-session-2026-06-20.md](traffic-shaper-fix-review-session-2026-06-20.md)  
Integration branch: `feat/traffic-shaper-spec`  
Coordination skill: Parallel Buckets v0.1.0  
Models: `parallel-buckets.local.yaml` → `models.choices` (configured 2026-06-20)

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (AskQuestion, 2026-06-20) |
| Approved waves | all (commit + P1a–P1e) |
| Notes | Executed coordinator-side; 275 shaper tests pass |

## P1 scope (from fix-review)

| # | Finding | Bucket |
|---|---------|--------|
| 1 | Restore ignores per-step API failures | P1a |
| 2 | Mock pipe/queue ignore POST payload | P1b |
| 3 | Preset proceeds with empty pipe/queue UUIDs | P1c |
| — | Tests for above + WARNING envelope | P1d |
| — | Full shaper pytest gate | P1e |

**Out of scope (P2 defer):** nested preset snapshots, orphan deletion on restore, `build_restore_plan` refactor, rate rounding policy.

## Fix bucket schedule (for approval)

**Probe run:** 2026-06-20 with configured `models.choices`

| Wave | ID | Title | Profile | Probe owner | **Assigned owner** | Model | Files (own) | Depends | Farm |
|------|-----|-------|---------|-------------|-------------------|-------|-------------|---------|------|
| 0 | **commit** | Baseline commit (fix pass + review docs) | — | Human | **Human** | — | uncommitted delta | — | git | **done** |
| 1 | **P1a** | Restore API status checks | `write_crud` | Ollama-cloud | **Claude Code** | opus | `shaper_snapshot.py` | commit | `claude -p` | **done** |
| 1 | **P1b** | Mock pipe/queue payload fidelity | `mock_fixtures` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `mock_api.py` | commit | worktree ∥ P1a | **done** |
| 2 | **P1c** | Preset UUID guards | `write_crud` | Ollama-cloud | **Ollama-cloud** | kimi-k2.7-code:cloud | `shaper_presets.py` | P1b | `farm_ollama_bucket.sh` | **done** |
| 3 | **P1d** | P1 test coverage | `mock_fixtures` | Ollama-local | **Ollama-workstation** | qwen3:32b | `tests/test_shaper_write_tools.py`, `test_shaper_write_helpers.py` | P1c | morpheus farm | **done** |
| 4 | **P1e** | Integration verify | `integration_merge` | Cursor auto | **Cursor** | auto | pytest shaper suite | P1d | coordinator | **done** (275 pass) |

**Assigned owner** spreads backends (Claude / local / cloud / workstation / Cursor). Probe column shows `recommend_bucket_owner.py` primary fit at bucketize time.

### Per-bucket deliverables

| ID | Do | Do NOT |
|----|-----|--------|
| P1a | After each `set_*` / settings POST, validate API `status`; fail fast with `partial_results` + `pre_restore_snapshot_id`; distinguish resource vs settings in counts | Orphan deletion, refactor `build_restore_plan` |
| P1b | Mirror rule handler: `_payload_scalar` for pipe/queue add/set (description, bandwidth, scheduler, pipe link, weight) | Change live API client |
| P1c | After pipe/queue ensure, assert non-empty UUIDs before queues/rules; clear error message | Nested snapshot refactor (P2) |
| P1d | Tests: mock greenfield pipe add description; restore fails on bad API status; preset abort on missing UUID; optional `finish_mutation` WARNING | Live MCP |
| P1e | `uv run pytest tests/test_shaper*.py`; ruff; update bucket statuses | Implement new features |

## Merge order

```text
commit → (P1a ∥ P1b) → P1c → P1d → P1e
```

## File ownership map

| File | Bucket |
|------|--------|
| `opnsense_mcp/tools/shaper_snapshot.py` | P1a |
| `opnsense_mcp/utils/mock_api.py` | P1b |
| `opnsense_mcp/tools/shaper_presets.py` | P1c |
| `tests/test_shaper_write_tools.py` | P1d |

## Uncommitted baseline (wave 0)

| File | Notes |
|------|-------|
| `shaper_presets.py`, `shaper_snapshot.py`, `shaper_mutation.py`, `shaper_snapshot_store.py` | F2–F3 fix pass |
| `mock_api.py`, `test_shaper_write_tools.py` | F4 |
| `traffic-shaper-fix-*`, `parallel-buckets.local.yaml`, `.cursor/parallel-buckets/*` | review + model catalog |

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 fix-review | [traffic-shaper-fix-review-session-2026-06-20.md](traffic-shaper-fix-review-session-2026-06-20.md) |
