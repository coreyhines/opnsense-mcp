# Traffic shaper write path — code review buckets (read-only)

Generated: 2026-06-20  
Scope: uncommitted Wave 2 changes on `feat/traffic-shaper-spec`  
Mode: **READ ONLY** — no edits, no commits  
Coordination skill: [`.cursor/skills/parallel-buckets/SKILL.md`](../../.cursor/skills/parallel-buckets/SKILL.md)  
Overlay: [`parallel-buckets.local.yaml`](../../parallel-buckets.local.yaml)

## Review sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 5 |
| Parallel wave 1 | R1 ∥ R2 ∥ R3 |
| Ollama-local buckets | 3 |
| Cursor buckets | 2 |
| Claude buckets | 0 |
| Estimated phases | 2 (parallel review → coordinator synthesis) |

## Bucket registry

| ID | Title | Profile | Owner | Model | Files (read) | Depends on | Output |
|----|-------|---------|-------|-------|--------------|------------|--------|
| R1 | Write CRUD tools review | `read_tools` | Ollama-local | qwen3.6:35b | `shaper_pipes/queues/rules.py` | — | findings |
| R2 | Mutation + snapshot review | `pure_logic` | Ollama-local | qwen3.6:35b | `shaper_mutation.py`, `shaper_snapshot*.py`, `shaper_snapshot.py` | — | findings |
| R3 | Presets + settings + service | `read_tools` | Ollama-local | qwen3.6:35b | `shaper_presets.py`, `shaper_settings.py`, `shaper_service.py` | — | findings |
| R4 | MCP wiring review | `mcp_wiring` | Cursor | auto | `fastmcp_server.py` (shaper block) | R1–R3 | findings |
| R5 | Tests + docs integration | `integration_merge` | Cursor | auto | `tests/test_shaper_*`, `FUNCTION_REFERENCE.md` | R1–R4 | session report |

**Do NOT:** edit code, run live MCP mutations, or merge branches during review buckets.

## Merge order (synthesis)

```text
(R1 ∥ R2 ∥ R3) → R4 → R5
```

## File ownership map

| File / directory | Review bucket |
|------------------|---------------|
| `opnsense_mcp/tools/shaper_pipes.py` | R1 |
| `opnsense_mcp/tools/shaper_queues.py` | R1 |
| `opnsense_mcp/tools/shaper_rules.py` | R1 |
| `opnsense_mcp/utils/shaper_mutation.py` | R2 |
| `opnsense_mcp/utils/shaper_snapshot_store.py` | R2 |
| `opnsense_mcp/tools/shaper_snapshot.py` | R2 |
| `opnsense_mcp/tools/shaper_presets.py` | R3 |
| `opnsense_mcp/tools/shaper_settings.py` | R3 |
| `opnsense_mcp/tools/shaper_service.py` | R3 |
| `opnsense_mcp/fastmcp_server.py` | R4 |
| `tests/test_shaper_write_tools.py` | R5 |
| `tests/test_shaper_mcp_register.py` | R5 |

## Out of scope

- Phase 1 read-path code (already merged)
- Live firewall MCP verify
- Parallel-buckets product repo itself

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 | [traffic-shaper-review-session-2026-06-20.md](traffic-shaper-review-session-2026-06-20.md) |
