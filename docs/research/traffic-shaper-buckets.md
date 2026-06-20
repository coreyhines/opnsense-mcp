# Traffic shaper — parallel bucket coordination

Integration branch: **`feat/traffic-shaper-spec`** (merge buckets here, then optional `feat/traffic-shaper` for final PR).

| Bucket | Owner | Branch | Worktree | Status | Depends on |
|--------|-------|--------|----------|--------|------------|
| 0 Contract | Claude | `feat/shaper-bucket-0-contract` | `../opnsense-mcp-bucket-0` | **merged** | — |
| 1a Normalize | Claude | `feat/shaper-bucket-1a-normalize` | `../opnsense-mcp-bucket-1a` | **Claude running** | 0 |
| 2a Interpret | Claude | `feat/shaper-bucket-2a-interpret` | `../opnsense-mcp-bucket-2a` | **Claude running** | 0 |
| 2b Audit | Cursor | `feat/shaper-bucket-2b-audit` | (main repo) | queued | 0, 2a |
| 3c Mock/fixtures | Cursor | `feat/shaper-bucket-3c-mock` | (main repo) | **in progress** | 0 |
| 1b Serialize | — | — | — | queued | 0, 1a |
| 3a Read tools | — | — | — | queued | 0, 1a, 2a, 2b, 3c |
| 3b MCP register | — | — | — | queued | 3a |

**Merge order:** 0 → (1a ∥ 2a ∥ 3c) → 2b → 1a+2a → 3a → 3b → Phase 2 write buckets.

**Rules:** One agent per branch; only **3b** touches `fastmcp_server.py` in Phase 1.
