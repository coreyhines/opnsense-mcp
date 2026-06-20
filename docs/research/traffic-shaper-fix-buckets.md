# Traffic shaper — fix pass buckets (post-review)

Generated: 2026-06-20  
Source review: [traffic-shaper-review-session-2026-06-20.md](traffic-shaper-review-session-2026-06-20.md)  
Integration branch: `feat/traffic-shaper-spec`  
Coordination skill: Parallel Buckets v0.1.0  
Cloud model default: **`kimi-k2.7-code:cloud`** (not `kimi-k2.6:cloud`; no `kimi-k2.7` tag on Ollama Cloud)

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (AskQuestion, 2026-06-20) |
| Approved waves | 0–5 (full schedule) |
| Notes | Execute in merge order; cloud Kimi = **`kimi-k2.7-code:cloud`** |

## Fix bucket schedule (for approval)

**Probe run:** 2026-06-20 with `OLLAMA_FARM_CLOUD_MODEL=kimi-k2.7-code:cloud`

| Wave | ID | Title | Profile | Probe owner | **Assigned owner** | Model | Files (own) | Depends | Farm |
|------|-----|-------|---------|-------------|-------------------|-------|-------------|---------|------|
| 0 | **commit** | Baseline commit (Wave 2 + review + wiring) | — | Human | **Human** | — | all uncommitted | — | git | **done** (`eb46194`) |
| 1 | **F1a** | Queue write hardening | `write_crud` | Claude Opus | **Ollama-cloud** | `kimi-k2.7-code:cloud` | `shaper_queues.py` | review | `farm_ollama_bucket.sh` | **done** (coordinator) |
| 1 | **F1b** | Rule write hardening | `write_crud` | Claude Opus | **Ollama-local** | `qwen3.6:35b-a3b-mxfp8` | `shaper_rules.py` | review | worktree ∥ F1a | **done** (coordinator) |
| 2 | **F2** | Restore serialize + envelope | `serialize` | Claude Opus | **Claude Code** | `opus` | `shaper_snapshot.py`, `shaper_mutation.py`, `shaper_snapshot_store.py` | F1 | `claude -p` | **done** (uncommitted) |
| 3 | **F3** | Complete `bufferbloat_wan` preset | `write_crud` | Claude Opus | **Ollama-workstation** | `qwen3:32b` | `shaper_presets.py` | F2 | morpheus farm | **done** (uncommitted) |
| 4 | **F4** | Expand write-path tests | `mock_fixtures` | Ollama-local | **Ollama-local** | `gemma4:12b-mlx` | `tests/test_shaper_write_tools.py`, `mock_api.py` | F3 | local farm | **done** (uncommitted) |
| 5 | **F5** | Integration verify | `integration_merge` | Cursor auto | **Cursor** | auto | pytest full shaper suite | F4 | coordinator | **done** (271 shaper tests pass) |

**Assigned owner** column intentionally spreads backends to **exercise all paths** (cloud / local / workstation / Claude / Cursor). Probe column shows `recommend_bucket_owner.py` primary fit; overrides documented here for the exercise.

### Ollama Cloud Kimi scan (2026-06-20)

| Tag on Ollama Cloud API | Notes |
|-------------------------|-------|
| `kimi-k2.5` | older |
| `kimi-k2.6` | **deprecated for new work** — do not default |
| `kimi-k2.7-code` | **Kimi 2.7** — use as **`kimi-k2.7-code:cloud`** |
| `kimi-k2.7` | **does not exist** (Hermes 404) |

## Merge order

```text
commit → (F1a ∥ F1b) → F2 → F3 → F4 → F5
```

## P0 mapping (from review)

| Finding | Bucket |
|---------|--------|
| Queue/rule hardening | F1a, F1b |
| Restore path | F2 |
| Preset incomplete | F3 |
| Test gaps | F4 |

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 review | [traffic-shaper-review-session-2026-06-20.md](traffic-shaper-review-session-2026-06-20.md) |
