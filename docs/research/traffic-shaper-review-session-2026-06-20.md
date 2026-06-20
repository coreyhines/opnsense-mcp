# Session report — traffic shaper code review (Parallel Buckets)

**Date:** 2026-06-20  
**Branch:** `feat/traffic-shaper-spec`  
**Mode:** Read-only review (no code changes)  
**Skill:** Parallel Buckets v0.1.0 (generic) + opnsense-mcp local overlay  
**Bucket plan:** [traffic-shaper-review-buckets.md](traffic-shaper-review-buckets.md)

## Summary table

| Bucket | Owner | Model | Status | Top finding |
|--------|-------|-------|--------|-------------|
| R1 | Ollama-local | qwen3.6:35b | done | Pipes are reference quality; queues/rules lack client guards + try/except parity |
| R2 | Ollama-local | qwen3.6:35b | done | Restore posts raw search rows, never replays `settings_get`; envelope differs from writes |
| R3 | Ollama-local | qwen3.6:35b | done | `bufferbloat_wan` preset incomplete vs spec (no queues, no dual-stack, sub-tool errors ignored) |
| R4 | Cursor | auto | done | MCP registration complete (16 write tools); schemas better than some tool classes; docstrings oversell preset |
| R5 | Cursor | auto | done | Register tests pass; write tests are happy-path only — gaps match R1–R3 |

## Portfolio utilization

| Resource | Used | Quota / probe | Notes |
|----------|------|---------------|-------|
| Ollama-local | R1, R2, R3 (parallel agents) | local OK | Review-only prompts |
| Morpheus | probed at bucketize | ready | Not used for review (no farm) |
| Cursor | R4, R5, synthesis | ~10% total | Coordinator merge |
| Claude | — | session 86% | Not needed for read-only review |

## Cross-bucket themes (prioritized)

### P0 — fix before live write deploy

1. **`bufferbloat_wan` preset incomplete** (R3) — missing queues, IPv6/upload rules, ECN; sub-tool failures silently ignored.
2. **Restore path untrusted** (R2) — raw search rows vs serialize path; `settings_get` captured but not restored.
3. **Queue/rule write hardening** (R1) — null client → `AttributeError`; missing try/except vs pipes.

### P1 — agent UX / correctness

4. **Reconfigure failure still `success`** (R1/R2) — `finish_mutation` when `applied: false`.
5. **Nested snapshots in preset** (R3) — one preset run pollutes snapshot store.
6. **Set-tool MCP schemas vs tool input_schema** (R1/R4) — FastMCP exposes full set fields; tool classes under-document queues/rules.

### P2 — tests and docs

7. **Expand `test_shaper_write_tools.py`** — error paths, queue/rule set/delete, preset rule counts, restore field-level assertions.
8. **Align FUNCTION_REFERENCE** with actual preset behavior until preset is completed.

## Bucket detail

### R1 — Write CRUD (Ollama-local)

- **Strengths:** Pipe tools are the quality bar; delete confirm tokens; idempotent set; snapshot/apply pattern.
- **High:** Queue/rule missing client checks and exception wrappers; no referential validation on add; bandwidth metric ignored in validation.
- **Medium:** Inconsistent delete confirm envelope; UUID extraction differs pipe vs queue/rule.

### R2 — Mutation + snapshot (Ollama-local)

- **Strengths:** Clean pure helpers; deepcopy capture; restore ordering pipes→queues→rules.
- **Critical:** Restore payload shape ≠ write path; settings not restored; can't undo add/delete.
- **High:** Restore envelope ≠ `finish_mutation`; no pre-restore snapshot; mutable `get_snapshot` reference.

### R3 — Presets + settings + service (Ollama-local)

- **Strengths:** Outer `apply=false` chaining correct; `shaper_service.py` error handling solid.
- **Critical:** Preset vs spec mismatch; ignored sub-tool statuses; no top-level try/except.
- **High:** Broken rule idempotency check; rules target pipes not queues.

### R4 — MCP wiring (Cursor)

- **Strengths:** All 16 write tools registered; `set_shaper_queue`/`set_shaper_rule` FastMCP signatures expose updatable fields.
- **Issues:** `set_shaper_settings` MCP docstring implies configurable globals but tool is stub; `apply_shaper_preset` docstring claims dual-stack before preset delivers it.
- **Note:** `return str(result)` consistent with existing server pattern — agents must parse dict string or structured fields in summary.

### R5 — Tests + docs (Cursor)

- **`test_shaper_mcp_register.py`:** Read + write tool sets enumerated; import smoke passes.
- **`test_shaper_write_tools.py`:** 10 happy-path tests; restore test shallow (`restored >= 1`); preset test only checks bandwidth math.
- **Gap:** No test for queue/rule error envelopes, preset partial failure, or restore serialization fidelity.

## Integration health

| Check | Result |
|-------|--------|
| Bucketize + owner routing | OK — `recommend_bucket_owner.py` matched profiles |
| Parallel review wave | OK — R1∥R2∥R3 concurrent |
| Read-only constraint | OK — no files modified |
| Next action | Address P0 list before live MCP write smoke |

## Next buckets (if fixing)

| ID | Title | Profile | Suggested owner |
|----|-------|---------|-----------------|
| F1 | Harden queue/rule writes to pipe parity | `write_crud` | Claude Opus or Ollama-workstation |
| F2 | Fix restore serialization + settings replay | `serialize` | Claude Opus |
| F3 | Complete bufferbloat_wan preset | `write_crud` | Claude Opus |
| F4 | Expand write-path tests | `mock_fixtures` | Ollama-local |
