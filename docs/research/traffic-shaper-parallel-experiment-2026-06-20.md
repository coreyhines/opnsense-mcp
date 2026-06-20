# Parallel bucket experiment — traffic shaper Phase 2

**Date:** 2026-06-20  
**Coordinator:** Cursor (Auto)  
**Goal:** Validate multi-agent bucket farming (Ollama-local + Cursor coordinator) for a real feature spec.  
**Audience:** blog/thread material if the workflow proves useful.

**Related:** [traffic-shaper-buckets.md](traffic-shaper-buckets.md) · [traffic-shaper-spec.md](traffic-shaper-spec.md) · [parallel-buckets SKILL](../../.cursor/skills/parallel-buckets/SKILL.md)

---

## Executive summary (Wave 1)

| Result | Detail |
|--------|--------|
| **Wave 1 status** | **Complete** — buckets 4a, 4b, 4c merged |
| **Integration tests added** | 29 passing (10 + 8 + 7 + 4 mock) |
| **Ollama success rate** | 3/3 modules after coordinator gate (100% needed human test fix) |
| **Ollama git commits** | **0** — agents wrote files but never committed |
| **Time Wave 1** | ~45 min wall clock (incl. coordinator gates + retries) |
| **Verdict (draft)** | **Promising with gates** — local GPU is viable for pure-logic buckets; not fire-and-forget |

---

## Setup

| Item | Value |
|------|-------|
| Repo | `opnsense-mcp` |
| Integration branch | `feat/traffic-shaper-spec` @ `b5b6464` (after Wave 1) |
| Phase 1 baseline | 8 buckets, 231 shaper tests |
| Phase 2 Wave 1 | 4a snapshot store, 4b write helpers, 4c mock write API |

### Resource probes at farm time

| Resource | Reading | Routing decision |
|----------|---------|------------------|
| Claude Code usage API | HTTP **429** | Skip Claude farms |
| Ollama local | OK — qwen3.6:35b, gemma4:12b, qwen3.5:122b | Primary for Phase 2 |
| Ollama cloud | Week **91%**, session **43%** | Avoid cloud Opus |
| Cursor Pro+ | Total **8%**, API **11%** | Reserve for MCP wiring (4i+) |

---

## Architecture (what we actually ran)

```text
Spec → bucketize → tmp_bucket_*_prompt.md
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    worktree 4a      worktree 4b      worktree 4c
    Ollama 35b       Ollama 35b       Ollama 35b (gemma failed)
         │               │               │
         └───────────────┴───────────────┘
                         │
              Cursor coordinator gate
              (ruff, pytest, indent fix)
                         │
                         ▼
              merge → feat/traffic-shaper-spec
```

**Farmer:** `~/code/parallel-buckets/scripts/farm_ollama_bucket.py` (via `PARALLEL_BUCKETS_HOME`)  
**Agent loop:** Ollama `/api/chat` + tools: `run_shell`, `read_file`, `write_file` (max 45 rounds)

---

## Experiment design

### Hypothesis

1. Bucketize spec into disjoint file-ownership slices.
2. Farm pure-logic buckets to local Ollama in git worktrees.
3. Cursor coordinator merges after pytest/ruff gate.
4. Claude when quota available; local 122B for write_crud later.

### What we learned immediately

| Attempt | Result | Lesson |
|---------|--------|--------|
| Launch 4a∥4b∥4c without `nohup` | Shell exit killed PIDs | Use `nohup … &` or persistent shell |
| Parallel 3× qwen3.6:35b on one GPU | 4b/4c logs = 1 line, no files | **Serialize 35B farms** on single GPU |
| `gemma4:12b-mlx` for 4c | Process exit **~8s**, zero files | **Verify tool-calling** before assigning fast model |
| Ollama farmer logs | Only first line unless foreground | Add structured logging per tool round |
| Worktree `uv run pytest` | Missing `pytest-asyncio` | Gate script: `uv pip install pytest pytest-asyncio` or share main `.venv` |
| Ollama output | **100% test files had IndentationError** | Coordinator gate is mandatory, not optional |

---

## Bucket 4a — Snapshot store

| Field | Value |
|-------|-------|
| Model | `qwen3.6:35b-a3b-mxfp8` |
| Branch | `feat/shaper-bucket-4a-snapshot-store` |
| Commit | `a5a7baa` |
| Tests | 10 passed |
| Farm time to first file | ~6 min |
| Agent commit? | No |

**Ollama delivered:** `shaper_snapshot_store.py` — capture/get/list/build_restore_plan/clear; deepcopy; session-scoped dict.

**Coordinator fixed:** IndentationError in module + 445-line test file → 10 focused tests.

**Quality:** Good architecture match to spec; coordinator mostly formatting.

---

## Bucket 4b — Write helpers

| Field | Value |
|-------|-------|
| Model | `qwen3.6:35b-a3b-mxfp8` |
| Branch | `feat/shaper-bucket-4b-write-helpers` |
| Commit | `274e776` |
| Tests | 8 passed |
| Farm time to first file | ~3 min |
| Agent commit? | No |

**Ollama delivered:** `shaper_write_helpers.py` (368 LOC) — delete confirm tokens, idempotency, bandwidth validation, mutation envelope, serialize delegates. **Module passed ruff on first read.**

**Coordinator fixed:** Test file IndentationError only → 8 tests.

**Quality:** Best bucket — production-shaped code, spec-aligned.

---

## Bucket 4c — Mock write API

| Field | Value |
|-------|-------|
| Model | `qwen3.6:35b-a3b-mxfp8` (retry; gemma4 failed) |
| Branch | `feat/shaper-bucket-4c-mock-write` |
| Commit | `b5b6464` |
| Tests | 7 new + 4 existing mock = 11 in bucket |
| Farm time to first file | ~2.5 min (qwen retry) |
| Agent commit? | No |

**Ollama delivered:** +252 LOC in `mock_api.py` — mutable deep copy, add/set/del/toggle pipes/queues/rules, settings/set, reconfigure.

**Coordinator fixed:** 383-line test file indent → 7 tests; `uv pip install pytest-asyncio` in worktree venv.

**Quality:** Strong mock layer; enables write-tool buckets without live firewall.

---

## Metrics (Wave 1)

| Metric | Value |
|--------|--------|
| Buckets merged | 3 / 3 |
| LOC added (approx) | 281 + 442 + 341 = **1064** |
| Ollama farms launched | 6+ (retries, parallel failures) |
| Successful module generations | 3 / 3 |
| Tests needing coordinator rewrite | 3 / 3 |
| Git commits from Ollama agent | **0 / 3** |
| Coordinator gate time | ~15 min total |
| Combined Wave 1 pytest | **29 passed** |

---

## Failure modes catalog (for blog)

1. **Silent farm death** — log shows only `Farming via …`; process gone. Cause: GPU contention or crash before first tool call.
2. **Indentation roulette** — qwen3.6 consistently mixes 4/5 space indents in test files (and sometimes modules).
3. **No commit discipline** — prompt says commit; agent writes files and stops or hangs.
4. **Worktree venv drift** — fresh worktree `.venv` lacks dev deps; pytest asyncio fails misleadingly.
5. **Wrong model for tools** — gemma4:12b exited instantly; skill says use tools-capable models only.
6. **Parallel 35B on M5 Max** — one wins, others starve.

---

## Recommended workflow (revised after experiment)

```bash
# 1. Bucketize + prompts (Cursor coordinator)
# 2. ONE Ollama farm at a time for 35B models
nohup uv run python .cursor/skills/.../farm_ollama_bucket.py \
  --prompt-file tmp_bucket_4d_prompt.md \
  --backend local --model qwen3.6:35b-a3b-mxfp8 \
  --worktree ../opnsense-mcp-bucket-4d \
  >> /tmp/ollama-bucket-4d.log 2>&1 &

# 3. Coordinator gate (required)
cd ../opnsense-mcp-bucket-4d
uv pip install pytest pytest-asyncio
uv run ruff check <owned files>
uv run pytest <owned tests> -q

# 4. Commit if agent didn't
git add … && git commit -m "feat(shaper): … (bucket 4d)"

# 5. Merge to integration + combined pytest
cd ../opnsense-mcp && git merge feat/shaper-bucket-4d-…
uv run pytest tests/test_shaper_*.py -q
```

---

## Blog / thread angles (draft copy)

**Hook:** “I split a firewall MCP feature into token buckets and fed them to local Ollama on an M5 Max while Cursor played tech lead.”

**Bullet flex:**

- Phase 1 (read path): 8 buckets, Claude + Cursor, **231 tests**
- Phase 2 Wave 1: 3 Ollama farms, **1064 LOC**, merged in one afternoon
- Cost: sunk GPU + Cursor sub — **no Claude quota burned** (API was 429)
- Catch: **every Ollama bucket needed a pytest gate** before merge

**Honest caveat:** Not fully autonomous — coordinator fixed tests 3/3 times. Still faster than one monolithic agent session for file-conflict-free parallel spec work.

**Stack:** Cursor · Ollama local · git worktrees · custom `farm_ollama_bucket.py` agent loop · MCP-first homelab repo

---

## Wave 2 queue (next)

| Bucket | Owner | Model | Depends | Notes |
|--------|-------|-------|---------|-------|
| 4d Pipe write | Ollama-local | qwen3.5:122b | Wave 1 | Serialize + mock ready |
| 4e Queue write | Ollama-local | qwen3.5:122b | Wave 1 | Can run after 4d serially |
| 4f Rule write | Ollama-local | qwen3.5:122b | Wave 1 | Same |
| 4g Settings/apply | Ollama-local | qwen3.5:122b | Wave 1 | |
| 4h Restore tool | Ollama-local | qwen3.5:122b | 4d–4g | |
| 4i MCP register | Cursor auto | — | 4d–4h | |
| 4j Live smoke | Cursor auto | — | 4i | |

**Recommendation:** Farm 4d next (single 122B job), not 4d∥4e∥4f unless using smaller model or multiple GPUs.

---

## Skill improvements to file (backlog)

- [ ] Farmer: log each tool round to `/tmp/ollama-bucket-{id}.log`
- [ ] Farmer: enforce `uv run pytest` + exit non-zero before allowing “done”
- [ ] Farmer: auto `git commit` in final tool round
- [ ] `farm_ollama_bucket.sh`: serialize mode flag
- [ ] Worktree bootstrap: `uv pip install pytest pytest-asyncio` in script
- [ ] Document gemma4 tool-calling failure in resource-portfolio.md

---

## Session log (append-only)

| UTC | Event |
|-----|-------|
| 16:38 | Wave 1 parallel launch (4a∥4b∥4c) — partial failure |
| 16:42 | 4a farm single-threaded |
| 16:44–16:45 | Ollama writes 4a files |
| 16:49 | 4a merged — 10 tests |
| 16:48–17:01 | 4b farm ~3 min to files |
| 17:01 | 4b merged — 8 tests |
| 17:02 | gemma4 4c farm instant fail |
| 17:02–17:05 | 4c retry qwen3.6 — mock_api +252 LOC |
| 17:06 | 4c merged — 29 total Wave 1 tests |
| — | **Wave 1 complete** |
