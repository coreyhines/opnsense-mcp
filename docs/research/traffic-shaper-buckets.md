# Traffic shaper — parallel bucket coordination

Coordination skill: [`.cursor/skills/parallel-buckets/SKILL.md`](../../.cursor/skills/parallel-buckets/SKILL.md)  
Local overlay: [`parallel-buckets.local.yaml`](../../parallel-buckets.local.yaml)  
Session report: [`traffic-shaper-session-2026-06-20.md`](traffic-shaper-session-2026-06-20.md)

Integration branch: **`feat/traffic-shaper-spec`** (merge buckets here, then optional `feat/traffic-shaper` for final PR).

---

## Phase 1 — Read path (complete)

| Bucket | Profile | Owner | Model | Branch | Status | Depends on |
|--------|---------|-------|-------|--------|--------|------------|
| 0 Contract | `contract` | Claude | Sonnet | `feat/shaper-bucket-0-contract` | **merged** | — |
| 1a Normalize | `pure_logic` | Claude | Sonnet | `feat/shaper-bucket-1a-normalize` | **merged** | 0 |
| 2a Interpret | `pure_logic` | Claude | Sonnet | `feat/shaper-bucket-2a-interpret` | **merged** | 0 |
| 2b Audit | `pure_logic` | Cursor | auto | `feat/shaper-bucket-2b-audit` | **merged** | 0, 2a |
| 3c Mock/fixtures | `mock_fixtures` | Cursor | auto | `feat/shaper-bucket-3c-mock` | **merged** | 0 |
| 1b Serialize | `serialize` | Claude | Opus | `feat/shaper-bucket-1b-serialize` | **merged** | 0, 1a |
| 3a Read tools | `read_tools` | Cursor | auto | `feat/shaper-bucket-3a-read-tools` | **merged** | 0, 1a, 2a, 2b, 3c |
| 3b MCP register | `mcp_wiring` | Cursor | auto | `feat/shaper-bucket-3b-mcp-register` | **merged** | 3a |

**Phase 1 merge order:** 0 → (1a ∥ 2a ∥ 3c) → 2b → 3a → 3b → 1b

---

## Phase 2 — Write path

**Capacity snapshot (re-bucketized 2026-06-20):**

| Resource | Status | Routing impact |
|----------|--------|----------------|
| **Ollama-workstation** (NEW) | OK @ `morpheus.freeblizz.com:11434`, `qwen3:32b`, idle | **Primary for Wave 2 write_crud** — one farm at a time |
| Claude Code | Session **86%** (Opus ≥80% blocked) | Skip Claude for 4d–5a |
| Ollama local (Mac) | OK; Wave 1 done | **No new 35B/122B farms** — Mac coordinator only |
| Ollama cloud | Week **91%** | Avoid |
| Cursor Pro+ | Total **9%** | 4i, 4j, 5b only |

**Wave 1 experiment:** [traffic-shaper-parallel-experiment-2026-06-20.md](traffic-shaper-parallel-experiment-2026-06-20.md) — parallel Mac farms failed; coordinator pytest gate required on 3/3 buckets.

| ID | Title | Profile | Owner | Model | Host | Depends on | Status |
|----|-------|---------|-------|-------|------|------------|--------|
| 4a | Snapshot store | `pure_logic` | Ollama-local | qwen3.6:35b | Mac | Phase 1 | **merged** `a5a7baa` |
| 4b | Write helpers | `pure_logic` | Ollama-local | qwen3.6:35b | Mac | Phase 1 | **merged** `274e776` |
| 4c | Mock write API | `mock_fixtures` | Ollama-local | qwen3.6:35b | Mac | Phase 1 | **merged** `b5b6464` |
| 4d | Pipe write tools | `write_crud` | Cursor (coordinator) | auto | Cursor | 4a–4c | **done** (Wave 2 pivot) |
| 4e | Queue write tools | `write_crud` | Cursor (coordinator) | auto | Cursor | 4a–4c | **done** |
| 4f | Rule write tools | `write_crud` | Cursor (coordinator) | auto | Cursor | 4a–4c | **done** |
| 4g | Settings + apply | `write_crud` | Cursor (coordinator) | auto | Cursor | 4a–4c | **done** |
| 4h | Restore snapshot tool | `write_crud` | Cursor (coordinator) | auto | Cursor | 4a, 4d–4g | **done** |
| 4i | MCP write register | `mcp_wiring` | Cursor | auto | Cursor | 4d–4h | **done** |
| 4j | Live write smoke | `live_mcp` | Cursor | auto | Cursor | 4i | **mock verified** — live MCP after redeploy |

**Phase 2 merge order (revised — serial workstation, not parallel Mac):**

```text
Wave 1 (done): (4a ∥ 4b ∥ 4c) on Mac — with gates

Wave 2 (executed 2026-06-20 — coordinator pivot):
  4d → 4e → 4f → 4g → 4h   [Cursor coordinator — workstation farms skipped for speed]
  → 4i → 4j                 [Cursor — 264 shaper tests pass; 52 MCP tools]

Coordinator gate after EACH bucket: ruff + pytest + commit if agent didn't
```

**Routing rationale:**

| Bucket | Why this owner |
|--------|----------------|
| 4d–4h | `write_crud` profile; Claude session 86%; cloud week 91%; workstation idle with tools-capable `qwen3:32b`; frees Mac for merge/MCP |
| 4i, 4j | MCP wiring + live verify — Cursor only per skill |
| Mac Ollama-local | Wave 1 only — experiment showed parallel 35B contention + indent gate load on coordinator |

**Execution constraints (from experiment):**

- Workstation: **max 1 parallel farm** (`max_parallel_farms: 1`)
- Every Ollama farm: `coordinator_gate_required: true` (indent/tests/commit)
- Worktree bootstrap: `uv pip install pytest pytest-asyncio`
- Backend flag: `OLLAMA_BACKEND=workstation` / `--backend workstation`

**Wiring owner:** bucket **4i** only touches `fastmcp_server.py` for write tools.

### File ownership map (Phase 2)

| File | Bucket | Notes |
|------|--------|-------|
| `utils/shaper_snapshot_store.py` | 4a | Session-scoped snapshot map; no API I/O |
| `utils/shaper_write_helpers.py` | 4b | Confirm tokens, idempotency, apply envelope |
| `utils/mock_api.py` | 4c | Add write endpoint mocks only |
| `tools/shaper_pipes.py` | 4d | Add write tool classes; keep read tools |
| `tools/shaper_queues.py` | 4e | Add write tool classes |
| `tools/shaper_rules.py` | 4f | Add write tool classes |
| `tools/shaper_settings.py` | 4g | Add `SetShaperSettingsTool`; keep fetch helpers |
| `tools/shaper_service.py` | 4g | Add `ApplyShaperTool`; keep statistics |
| `utils/shaper_mutation.py` | 4d–4h | Shared snapshot/apply helpers for write tools |
| `tools/shaper_snapshot.py` | 4h | `RestoreShaperSnapshotTool` |
| `fastmcp_server.py` | 4i | Register write MCP tools (52 tools total) |
| `tools/shaper_presets.py` | 5a | `ApplyShaperPresetTool` |

### Out of scope (Phase 2)

- Persisting snapshots to disk (document session limitation only)
- Live homelab mutations without explicit user confirm (bucket 4j — mock verified; live after redeploy)

---

## Phase 3 — Presets & docs

| ID | Title | Profile | Owner | Model | Host | Depends on | Status |
|----|-------|---------|-------|-------|------|------------|--------|
| 5a | Preset bufferbloat_wan | `write_crud` | Cursor (coordinator) | auto | Cursor | Phase 2 | **done** |
| 5b | Docs + register preset | `mcp_wiring` | Cursor | auto | Cursor | 5a, 4i | **done** |

**Phase 3 merge order:** 5a (workstation) → 5b (Cursor)

---

## Pending execution plan

**Status:** Full chain complete on `feat/traffic-shaper-spec` (uncommitted). Workstation farms were skipped after Wave 1 experiment; Cursor coordinator implemented 4d–5b directly.

| Remaining | Action |
|-----------|--------|
| Deploy | Redeploy opnsense-mcp container so live MCP exposes 16 write tools |
| Live 4j | Run `apply=false` write smoke via MCP after redeploy |
| Commit | User-requested commit on integration branch |

**Mac role during Wave 2:** coordinator only (merge, pytest gate, tracker) — no new Ollama farms on Mac GPU.

---

## Bucket sizing summary

| Metric | Phase 1 | Phase 2 (remaining) | Phase 3 |
|--------|---------|---------------------|---------|
| Total buckets | 8 merged | 7 done | 2 done |
| Ollama-workstation | — | 0 (pivot) | 0 (pivot) |
| Ollama-local (Mac) | 4 (Phase 1) | 0 new | 0 |
| Cursor | 4 | 2 | 1 |
| Claude | 4 | 0 | 0 |

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 | [traffic-shaper-session-2026-06-20.md](traffic-shaper-session-2026-06-20.md) |
