# Traffic shaper — broad read-path + audit review buckets

Generated: 2026-06-20  
Baseline commit: `1e10be9`  
Branch: `feat/traffic-shaper-spec`  
Mode: **READ ONLY**  
Purpose: Second-pass review of **read/audit/explain** tools and MCP registration — not covered deeply in FR/P1 passes (write-path focused).

Coordination skill: Parallel Buckets v0.1.0

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (2026-06-20) |
| Approved waves | all (BR1–BR5) |
| Notes | Executed read-only coordinator review |

## Review sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 5 |
| Parallel wave 1 | BR1 ∥ BR2 ∥ BR3 |
| Estimated phases | 2 |

## Bucket registry

| Wave | ID | Title | Profile | **Assigned owner** | Model | Files (read) | Depends | Status |
|------|-----|-------|---------|-------------------|-------|--------------|---------|--------|
| 1 | **BR1** | Read tools + settings | `read_tools` | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `shaper_settings.py`, `shaper_service.py`, read helpers in `shaper_pipes/queues/rules.py` | — | **done** |
| 1 | **BR2** | Audit + interpret | `pure_logic` | **Ollama-workstation** | qwen3:32b | `shaper_audit.py`, `shaper_interpret.py`, `shaper_audit_rules.py` | — | **done** |
| 1 | **BR3** | Normalize + serialize contract | `serialize` | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | `shaper_normalize.py`, `shaper_serialize.py`, `shaper_types.py` | — | **done** |
| 2 | **BR4** | MCP register + docs | `mcp_wiring` | **Cursor** | auto | `fastmcp_server.py`, `FUNCTION_REFERENCE.md`, `test_shaper_mcp_register.py` | BR1–BR3 | **done** |
| 3 | **BR5** | Synthesis | `integration_merge` | **Cursor** | auto | findings | BR4 | **done** |

### Review focus

| ID | Check for |
|----|-----------|
| BR1 | List/get/search consistency; statistics tool interpretation hooks; settings unwrap |
| BR2 | Scheduler drift detection (config vs stats); checklist completeness; explain output safety |
| BR3 | Enum round-trip stability for write path; breaking field renames |
| BR4 | All spec tools registered; naming parity with MCP descriptions |
| BR5 | Cross-bucket severity; doc gaps; test holes in read path |

## Merge order

```text
(BR1 ∥ BR2 ∥ BR3) → BR4 → BR5
```

## Do NOT

- Edit code or tests
- Live MCP mutations

## Out of scope

- Write-path restore/preset (see [traffic-shaper-p2-review-buckets.md](traffic-shaper-p2-review-buckets.md))
- parallel-buckets product repo

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 | [traffic-shaper-broad-review-session-2026-06-20.md](traffic-shaper-broad-review-session-2026-06-20.md) |
