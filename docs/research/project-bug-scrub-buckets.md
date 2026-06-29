# Project bug scrub - bucket plan

Generated: 2026-06-28
Scope: full repository bug scrub after `feat/diagnostics-mcp` merged to `main`
Integration branch: `review/project-bug-scrub`
Coordination skill: Parallel Buckets

## Approval status

| Field | Value |
|-------|-------|
| Status | **`approved`** |
| Approved by | User (2026-06-28) |
| Approved waves | all |
| Notes | Read-only bug scrub. Do not edit product code or commit fixes. Mixed backend schedule follows fit-first guidance: Cursor for review/MCP-context buckets, Claude for nuanced semantic review, Ollama for broad code scans/frontier review. |

**Coordinator:** post the schedule table in chat with `Approval status: pending`. **Do not execute** until status is `approved` or `approved_wave_N`.

## Bucket sizing summary

| Metric | Value |
|--------|-------|
| Total buckets | 8 |
| Parallel wave 1 | R0, R1, R2, R3, R4, R5, R6 |
| Claude buckets | 2 |
| Ollama-local buckets | 2 |
| Ollama-workstation buckets | 0 |
| Ollama-cloud buckets | 1 |
| Cursor buckets | 3 |
| Cursor sub-agent buckets | 2 |
| Cursor inline buckets | 1 |
| Estimated phases | 2 waves: parallel read-only review, then synthesis |

## Session status

| Field | Value |
|-------|-------|
| **Level** | YELLOW |
| **Updated** | 2026-06-28 21:40 local |
| **Claude session %** | unavailable: usage API returned 401/429 during probes |
| **Cursor total %** | 57.9% total, 66.0% auto composer, 14.0% API |
| **Note** | Coordinator dry-run routes implementation-shaped `pure_logic`/`read_tools` buckets to Ollama-local, but the skill's read-only review path allows Cursor readonly sub-agents. This schedule mixes backends by fit and documents each override below. Claude usage probe was unavailable/limited; Claude CLI should be smoke-tested before execution. |

## Bucket registry (schedule)

| Wave | ID | Title | Profile | Anthropic | Owner | Backend | Model | Exec | Files (own) | Depends on | Fits one session? |
|------|-----|-------|---------|-----------|-------|---------|-------|------|-------------|------------|-------------------|
| 1 | R0 | CI, deploy, packaging, and repo hygiene review | `pure_logic` | sonnet | Claude | claude-cli | sonnet | - | `.gitlab-ci.yml`, `.dockerignore`, `Dockerfile`, `deploy/**`, `pyproject.toml`, `requirements*.txt`, `uv.lock`, `.pre-commit-config.yaml`, `.gitleaks.toml`, `.gitguardian.yaml`, `README.md`, root scripts | - | yes |
| 1 | R1 | MCP server, registration, auth, and runtime bootstrap review | `read_tools` | none | Cursor | cursor-auto | auto | subagent | `main.py`, `mcp_start.sh`, `opnsense-mcp-start`, `start_opnsense_bridge.sh`, `opnsense_mcp/server.py`, `opnsense_mcp/fastmcp_server.py`, `opnsense_mcp/tools/__init__.py`, `opnsense_mcp/utils/auth.py`, `opnsense_mcp/utils/env.py`, `opnsense_mcp/utils/jwt_helper.py`, `opnsense_mcp/utils/logging.py`, `opnsense_mcp/utils/passlib_shim.py`, `opnsense_mcp/utils/errors.py`, `opnsense_mcp/utils/compat.py`, matching server/runtime tests | - | yes |
| 1 | R2 | OPNsense API client, mock API, SSH, and shared protocol helpers review | `pure_logic` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | - | `opnsense_mcp/utils/api.py`, `opnsense_mcp/utils/mock_api.py`, `opnsense_mcp/utils/form_helper.py`, `opnsense_mcp/utils/ssh_client.py`, `opnsense_mcp/utils/paramiko_ssh.py`, `opnsense_mcp/utils/oui_lookup.py`, `benchmark_performance.py`, `test_api_performance.py`, `update_oui_db.py`, matching client/helper tests | - | yes |
| 1 | R3 | DHCP, DNS, reservations, leases, and subnet DNS review | `read_tools` | sonnet | Claude | claude-cli | sonnet | - | `opnsense_mcp/tools/dhcp*.py`, `opnsense_mcp/tools/*dhcp*.py`, `opnsense_mcp/tools/dns.py`, `opnsense_mcp/tools/mkdns.py`, `opnsense_mcp/tools/rmdns.py`, `opnsense_mcp/tools/flush_dns.py`, `opnsense_mcp/utils/dhcp*.py`, `opnsense_mcp/utils/dhcp_providers/**`, matching DHCP/DNS tests | - | yes |
| 1 | R4 | Firewall, aliases, packet capture, gateway, interface inventory, LLDP, ARP, and system tools review | `read_tools` | none | Ollama-local | ollama-local | qwen3.6:35b-a3b-mxfp8 | - | `opnsense_mcp/tools/aliases.py`, `arp.py`, `firewall.py`, `fw_rules.py`, `gateway_status.py`, `interface.py`, `interface_list.py`, `lldp.py`, `mkfw_rule.py`, `optimized_block.py`, `packet_capture.py`, `rmfw_rule.py`, `set_fw_rule.py`, `ssh_fw_rule.py`, `system.py`, `toggle_fw_rule.py`, matching firewall/network tests | - | yes |
| 1 | R5 | Traffic shaper read/write/audit/snapshot suite review | `read_tools` | none | Ollama-cloud | ollama-cloud | kimi-k2.7-code:cloud | - | `opnsense_mcp/tools/shaper_*.py`, `opnsense_mcp/utils/shaper_*.py`, `tests/test_shaper_*.py`, traffic-shaper docs/research notes | - | yes |
| 1 | R6 | Diagnostics, logs, PF state/statistics, interface health, and flent review | `read_tools` | none | Cursor | cursor-auto | auto | subagent | `opnsense_mcp/tools/firewall_logs.py`, `get_logs.py`, `pf_diagnostics.py`, `interface_health.py`, `opnsense_mcp/utils/firewall_log_normalize.py`, `pf_diagnostics.py`, `interface_health.py`, `flent_summary.py`, diagnostics/flent fixtures and tests | - | yes |
| 2 | RS | Synthesize findings into prioritized bug scrub report | `integration_merge` | none | Cursor | cursor-auto | auto | inline | `docs/research/project-bug-scrub-session-2026-06-28.md` | R0, R1, R2, R3, R4, R5, R6 | yes |

## Merge order

```text
(R0 || R1 || R2 || R3 || R4 || R5 || R6) -> RS
```

## File ownership map

| File / directory | Bucket | Notes |
|------------------|--------|-------|
| CI, container, deploy, requirements, root docs/scripts | R0 | Infra and repo hygiene only |
| MCP server bootstrap and shared runtime helpers | R1 | Registration, auth, env, logging |
| API client, mock API, SSH, helper utilities | R2 | Shared transport/protocol risks |
| DHCP/DNS/IPAM tool and provider surface | R3 | Reservation/override semantics, leases, subnet DNS |
| Firewall/network inventory/read-write tools | R4 | Firewall rule mutation, packet capture, gateway/system reads |
| Traffic shaper tool and utility suite | R5 | Read/write shaper, audit, presets, snapshots |
| Diagnostics/log/PF/interface health/flent surface | R6 | Recently merged diagnostics and observability tools |
| Bug scrub session report | RS | Synthesis only |

## Routing rationale

| Bucket | Planned owner | Rationale |
|--------|---------------|-----------|
| R0 | Claude / Sonnet | CI and deploy failures benefit from Anthropic review; not worth Cursor, more nuanced than a pure local scan. |
| R1 | Cursor readonly subagent | Skill default for read-only review plus local MCP/server-registration context. Cursor is used readonly, not inline implementation. |
| R2 | Ollama-local | Broad pure Python helper/client scan; matches `pure_logic` primary fit and uses local sunk capacity. |
| R3 | Claude / Sonnet | DHCP/DNS reservation semantics and homelab source-of-truth rules are nuanced; use Sonnet review. |
| R4 | Ollama-local | Broad read-tool scan with mostly local invariants and tests; matches `read_tools` primary fit. |
| R5 | Ollama-cloud | Large shaper subsystem review uses frontier/cloud quota and avoids overloading Cursor/local-only schedule. |
| R6 | Cursor readonly subagent | Recently merged diagnostics/MCP surface; skill default review path plus synthesis-friendly findings. |
| RS | Cursor inline | Coordinator synthesis/report only. |

## Review instructions for R0-R6

Each review bucket is read-only and should return findings in code-review style:

- Prioritize correctness bugs, silent failures, data loss risks, security regressions, broken MCP behavior, live-infra hazards, and missing tests.
- Include exact file and symbol references for each finding.
- Separate confirmed bugs from speculative improvements.
- Do not make code changes.
- Do not call live OPNsense/Pi-hole/CloudVision mutation tools.
- Do not duplicate another bucket's file scope except when noting cross-bucket dependencies.

## Out of scope

- Implementing fixes.
- Refactoring style-only issues.
- Opening or editing GitLab issues during the review pass.
- Live homelab mutations or direct API/SSH fallbacks.
- Deleting or reverting existing branches/worktrees.

## Open questions

- [ ] If the review finds live-infra MCP tool bugs, should RS open GitLab issues immediately or only list issue drafts in the report?
- [ ] Should low-risk documentation nits be excluded entirely from RS, or kept in a final "cleanup" section?

## Session reports

| Date | Chat posted | File |
|------|-------------|------|
| 2026-06-28 | yes | `docs/research/project-bug-scrub-session-2026-06-28.md` |

## Execution status

| Bucket | Status | Owner | Planned backend | Resolved backend | Tests | Notes |
|--------|--------|-------|-----------------|------------------|-------|-------|
| R0 | done | Claude | claude-cli | claude-cli | review only | CI/deploy findings in session report |
| R1 | done | Cursor | cursor-auto | cursor-auto | review only | readonly subagent `4393d359-fed3-4ca9-8bae-9f0a5564135b` |
| R2 | done | Ollama-local | ollama-local | ollama-cloud | review only | local run hung >10m; rerouted to cloud |
| R3 | done | Claude | claude-cli | claude-cli | review only | DHCP/DNS findings in session report |
| R4 | done | Ollama-local | ollama-local | ollama-cloud | review only | local run hung >10m; rerouted to cloud |
| R5 | done | Ollama-cloud | ollama-cloud | ollama-cloud | `307 passed` shaper tests reported by reviewer | shaper findings in session report |
| R6 | done | Cursor | cursor-auto | cursor-auto | review only | readonly subagent `43210bd1-9c98-42b6-aa9b-d0add093210e` |
| RS | done | Cursor | cursor-auto | cursor-auto | synthesis only | session report written |
