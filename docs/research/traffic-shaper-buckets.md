# Traffic shaper — parallel bucket coordination

Coordination skill: [`.cursor/skills/parallel-bucket-coordination/SKILL.md`](../../.cursor/skills/parallel-bucket-coordination/SKILL.md)  
Session report: [`traffic-shaper-session-2026-06-20.md`](traffic-shaper-session-2026-06-20.md)

Integration branch: **`feat/traffic-shaper-spec`** (merge buckets here, then optional `feat/traffic-shaper` for final PR).

| Bucket | Owner | Branch | Worktree | Status | Depends on |
|--------|-------|--------|----------|--------|------------|
| 0 Contract | Claude | `feat/shaper-bucket-0-contract` | `../opnsense-mcp-bucket-0` | **merged** | — |
| 1a Normalize | Claude | `feat/shaper-bucket-1a-normalize` | `../opnsense-mcp-bucket-1a` | **merged** | 0 |
| 2a Interpret | Claude | `feat/shaper-bucket-2a-interpret` | `../opnsense-mcp-bucket-2a` | **merged** | 0 |
| 2b Audit | Cursor | `feat/shaper-bucket-2b-audit` | (main repo) | **merged** | 0, 2a |
| 3c Mock/fixtures | Cursor | `feat/shaper-bucket-3c-mock` | (main repo) | **merged** | 0 |
| 1b Serialize | Claude | `feat/shaper-bucket-1b-serialize` | `../opnsense-mcp-bucket-1b` | **merged** | 0, 1a |
| 3a Read tools | Cursor | `feat/shaper-bucket-3a-read-tools` | (main repo) | **merged** | 0, 1a, 2a, 2b, 3c |
| 3b MCP register | Cursor | `feat/shaper-bucket-3b-mcp-register` | (main repo) | **merged** | 3a |

**Merge order:** 0 → (1a ∥ 2a ∥ 3c) → 2b → 3a → 3b → 1b (Phase 2 prep) → **Phase 1 complete**.

**Rules:** One agent per branch; only **3b** touches `fastmcp_server.py` in Phase 1.

**Next:** Phase 2 write buckets (CRUD, snapshot, presets) — not yet bucketized.
