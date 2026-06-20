# Traffic shaper — P2h live smoke + post-deploy review buckets

Generated: 2026-06-20  
Baseline commit: `3c47e55`  
Deployed image: `hub.freeblizz.com/opnsense-mcp:1.0.0-dev.3c47e55` on **strongpod**  
Branch: `feat/traffic-shaper-spec`  
Mode: **READ ONLY** (live MCP + container smoke; no firewall mutations)  
Purpose: Validate redeploy + live shaper path; prioritize follow-up fixes.

Coordination skill: Parallel Buckets v0.1.0

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (2026-06-20 — redeploy + smoke + review) |
| Approved waves | all (LS1–LS5) |
| Notes | Executed after strongpod redeploy |

## Review sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 5 |
| Parallel wave 1 | LS1 ∥ LS2 ∥ LS3 ∥ LS4 |
| Estimated phases | 2 |

## Bucket registry

| Wave | ID | Title | Profile | **Assigned owner** | Model | Focus | Depends | Status |
|------|-----|-------|---------|-------------------|-------|-------|---------|--------|
| 1 | **LS1** | Deploy + transport | `live_mcp` | **Cursor** | auto | Image tag, container recreate, MCP endpoint, Cursor reconnect | — | **done** |
| 1 | **LS2** | Core MCP read smoke | `read_tools` | **Ollama-local** | qwen3.6:35b-a3b-mxfp8 | POST_DEPLOY checklist failures (dhcp, fw_rules) | — | **done** |
| 1 | **LS3** | Shaper read live | `live_mcp` | **Ollama-workstation** | qwen3:32b | list/stats/audit/explain on live firewall | LS1 | **done** |
| 1 | **LS4** | Shaper write registration | `mcp_wiring` | **Cursor** | auto | 52 tools, restore `remove_orphans`, preset write path (code review only) | LS1 | **done** |
| 2 | **LS5** | Synthesis + fix backlog | `integration_merge` | **Cursor** | auto | Cross-bucket severity, deploy runbook gap | LS1–LS4 | **done** |

## Merge order

```text
(LS1 ∥ LS2 ∥ LS3 ∥ LS4) → LS5
```

## Do NOT

- Mutate live firewall shaper config in review buckets
- Merge to main without user PR request

## Out of scope

- CloudVision / Pi-hole MCP
- parallel-buckets product repo changes

## Session reports

| Date | Link |
|------|------|
| 2026-06-20 | [traffic-shaper-p2h-smoke-review-session-2026-06-20.md](traffic-shaper-p2h-smoke-review-session-2026-06-20.md) |
