# Sub-agent dry run — fix buckets

Generated: 2026-06-20  
Source: [subagent-dry-run-session-2026-06-20.md](subagent-dry-run-session-2026-06-20.md)  
Integration branch: `feat/subagent-dry-run-fixes`

## Approval status

| Field | Value |
|-------|-------|
| Status | **approved** |
| Approved by | User (bucketize the fixes and execute) |
| Approved waves | all |

## Bucket registry

| Wave | ID | Title | Profile | Owner | Model | Exec | Files (own) | Depends |
|------|-----|-------|---------|-------|-------|------|-------------|---------|
| 1 | FX0 | Contract scheduler + audit vocab | `contract` | Cursor | auto | **inline** | `shaper_types.py`, `test_shaper_types.py` | — |
| 1 | FX1 | Normalize selected_enum + int parse | `pure_logic` | Cursor | auto | **inline** | `shaper_normalize.py`, `test_shaper_normalize.py` | — |
| 1 | FX2 | Interpret flowset drops + queue threshold | `pure_logic` | Cursor | auto | **inline** | `shaper_interpret.py`, `test_shaper_interpret.py` | — |
| 2 | FXM | Combined pytest gate | `integration_merge` | Cursor | auto | **inline** | — | FX0, FX1, FX2 |

**Note:** Wave 1 buckets are file-disjoint but **serialized inline** (coordinator) — faster than 3× write sub-agents for small, well-scoped fixes.

## Merge order

```text
(FX0 → FX1 → FX2) → FXM
```

## Fix mapping (dry-run findings)

| Finding | Bucket |
|---------|--------|
| `is_valid_scheduler("")` vs `PIPE_SCHEDULERS` | FX0 |
| Audit/interpret status vocabularies | FX0 |
| `selected_enum` string `"0"` truthy | FX1 |
| Required int parse inconsistency | FX1 |
| Dict `flowset` drops skipped | FX2 |
| `[QUEUE_FLOWS_ACTIVE]` at flows ≥ 1 | FX2 |
| Test gaps | FX0, FX1, FX2 |
