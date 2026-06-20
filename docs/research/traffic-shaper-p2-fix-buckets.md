# Traffic shaper — P2 fix buckets (post P2 review)

Generated: 2026-06-20  
Baseline: `1e10be9` + **P2 review findings** (execute review first, or approve both schedules)  
Branch: `feat/traffic-shaper-spec`  
Coordination skill: Parallel Buckets v0.1.0  
Review plan: [traffic-shaper-p2-review-buckets.md](traffic-shaper-p2-review-buckets.md)

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (AskQuestion, 2026-06-20) |
| Approved waves | all (P2a–P2h) |
| Notes | Orphan delete opt-in default False; executed coordinator-side |

## P2 scope (from FR/P1 defer + expected RR findings)

| # | Item | Bucket | Risk |
|---|------|--------|------|
| 1 | Restore uses inline loops; `build_restore_plan` unused | P2a | low |
| 2 | Restore cannot remove post-snapshot orphans | P2b | **medium** — needs opt-in + confirm |
| 3 | Preset creates nested per-sub-tool snapshots | P2c | low |
| 4 | Rate `int(mbit * 0.85)` floors Mbps | P2d | low |
| 5 | `_ensure_pipe` set path returns stale search row | P2e | low |
| 6 | Test gaps (restore fidelity, preset partial, plan executor) | P2f | low |
| 7 | Full shaper pytest + ruff gate | P2g | — |
| 8 | Live MCP write smoke (MCP-first) | P2h | **medium** — homelab only |

## Fix bucket schedule (for approval)

**Probe run:** 2026-06-20

| Wave | ID | Title | Profile | Probe owner | **Assigned owner** | Model | Files (own) | Depends | Farm |
|------|-----|-------|---------|-------------|-------------------|-------|-------------|---------|------|
| 0 | **commit** | Baseline if review-only edits land first | — | Human | **Human** | — | docs only | RR6 | git | **done** |
| 1 | **P2a** | Restore executor via `build_restore_plan` | `write_crud` | Ollama-cloud | **Cursor** | auto | `shaper_snapshot.py`, `shaper_mutation.py`, `shaper_snapshot_store.py` | commit | coordinator | **done** |
| 1 | **P2e** | Preset `_ensure_*` return fresh rows | `read_tools` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `shaper_presets.py` | commit | worktree ∥ P2a | **done** |
| 2 | **P2d** | Rate rounding policy + summary text | `pure_logic` | Ollama-local | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `shaper_presets.py`, `shaper_write_helpers.py` | P2e | sequential | **done** |
| 2 | **P2c** | Preset single parent snapshot | `write_crud` | Ollama-cloud | **Ollama-workstation** | qwen3:32b | `shaper_presets.py`, `shaper_mutation.py`, write tools | P2e | morpheus farm | **done** |
| 3 | **P2b** | Opt-in orphan cleanup on restore | `write_crud` | Ollama-cloud | **Ollama-cloud** | kimi-k2.7-code:cloud | `shaper_snapshot.py`, `shaper_mutation.py` | P2a | farm | **done** |
| 4 | **P2f** | P2 test coverage | `mock_fixtures` | Ollama-local | **Ollama-workstation** | qwen3:32b | `tests/test_shaper_write_tools.py`, `test_shaper_write_helpers.py` | P2a–P2d | morpheus | **done** |
| 5 | **P2g** | Integration verify | `integration_merge` | Cursor | **Cursor** | auto | pytest shaper suite | P2f | coordinator | **done** (280 pass) |
| 6 | **P2h** | Live MCP smoke | `live_mcp` | Cursor | **Cursor** | auto | MCP tools only | P2g | MCP-first | **blocked** — shaper write tools not on deployed MCP |

**Owner overrides:** P2a → Cursor because Claude 429 and cloud week at 91%; keeps cloud budget for P2b (risky restore behavior).

### Per-bucket deliverables

| ID | Do | Do NOT |
|----|-----|--------|
| P2a | Extract shared restore step runner from plan steps; keep get+normalize+merge; preserve P1 API checks | Change snapshot capture format |
| P2b | Add `remove_orphans: bool = False`; when true, delete pipes/queues/rules whose UUID ∉ snapshot (rules last); require explicit param in schema | Default-on orphan deletion |
| P2c | One `capture_pre_mutation_snapshot` at preset start; sub-tools use `apply=False` without new snapshots | Break sub-tool standalone behavior |
| P2d | Use `round()` or document floor in structured output + summary; add helper if shared | Change preset semantics without test |
| P2e | After set, re-fetch or merge structured pipe/queue from tool response | Large preset refactor |
| P2f | Tests: plan executor parity; restore bandwidth round-trip; preset partial failure; optional orphan opt-in mock test | Live firewall |
| P2g | `uv run pytest tests/test_shaper*.py`; ruff on touched files | New features |
| P2h | MCP: list pipes → dry preset or read-only restore path; document results in session report | Destructive prod changes without user OK |

## Merge order

```text
commit → (P2a ∥ P2e) → P2d → P2c → P2b → P2f → P2g → P2h
```

## File ownership map

| File | Bucket |
|------|--------|
| `opnsense_mcp/tools/shaper_snapshot.py` | P2a, P2b |
| `opnsense_mcp/utils/shaper_snapshot_store.py` | P2a |
| `opnsense_mcp/tools/shaper_presets.py` | P2e, P2d, P2c |
| `opnsense_mcp/utils/shaper_mutation.py` | P2c |
| `opnsense_mcp/utils/shaper_write_helpers.py` | P2d, P2b |
| `tests/test_shaper_write_tools.py` | P2f |
| `tests/test_shaper_snapshot_store.py` | P2f |

## Out of scope (P3 / later)

- Disk-persisted snapshot store
- Cross-session rollback across MCP workers
- Bulk import/export presets
- VPN-interface edge cases (spec v1 defer)

## Open questions (resolve before approval)

- [x] **P2b:** Approve opt-in orphan deletion — **yes, default `False`** (user 2026-06-20)
- [ ] **P2h:** Live smoke on production firewall vs mock-only until redeploy?
- [x] Run P2 review before P2 fix wave 1 — **done** (see session report)

## Session reports

| Date | Link |
|------|------|
| _(pending review)_ | `traffic-shaper-p2-review-session-2026-06-20.md` |
| _(pending fix)_ | `traffic-shaper-p2-fix-session-2026-06-20.md` |
