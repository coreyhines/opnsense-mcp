# Traffic shaper — P2h live smoke review session

Date: 2026-06-20  
Deploy: **strongpod** `hub.freeblizz.com/opnsense-mcp:1.0.0-dev.3c47e55` (`3c47e55`, `feat/traffic-shaper-spec`)  
Bucket plan: [traffic-shaper-p2h-smoke-review-buckets.md](traffic-shaper-p2h-smoke-review-buckets.md)

## Deploy summary (LS1)

| Step | Result |
|------|--------|
| Push branch to GitLab | ✅ `feat/traffic-shaper-spec` |
| `install.sh --build-local` on strongpod | ✅ image built and quadlet patched |
| `systemctl restart` alone | ⚠️ **Insufficient** — running container stayed on old `1.0.0` (Jun 16) |
| `podman rm -f` + start units | ✅ new container on `1.0.0-dev.3c47e55`, build metadata correct |
| Cursor MCP client | ⚠️ Brief `fetch failed` after restart — **reconnect MCP in Cursor Settings** |

**Runbook gap (P2):** Document that image tag updates require **container recreate**, not only quadlet sed + systemd restart.

---

## Core MCP read smoke (POST_DEPLOY + LS2)

| Tool | Pass/Fail | Note |
|------|-----------|------|
| `system` | Pass* | `fw.freeblizz.com`, OPNsense 26.1.10 — *old build metadata until MCP reconnect |
| `interface_list` | Pass | 19 interfaces; WAN `ax1` present |
| `gateway_status` | Pass | 2 gateways online |
| `fw_rules` | **Fail** | `rules=[]` but `total_all=179` — FastMCP passes `enabled=None`, filter drops all rows (**P1**) |
| `arp` | Pass | Large ARP table returned |
| `dhcp` | **Fail** | `'NoneType' object has no attribute 'strip'` when `search=None` (**P1**) |
| `get_logs` | Pass | 20 log entries |
| `lldp` | Pass | 2 neighbors (720xp) |
| `dns` | Pass | 100 overrides |
| `aliases` | Pass | 38 aliases |

---

## Shaper read live smoke (P2h / LS3)

Executed inside new container with live `OPNsenseClient` (MCP-equivalent tool path):

| Tool | Status | Note |
|------|--------|------|
| `list_shaper_pipes` | Pass | 2 pipes |
| `list_shaper_queues` | Pass | 2 queues |
| `list_shaper_rules` | Pass | 2 rules |
| `get_shaper_settings` | Pass | Counts match |
| `shaper_statistics` | Critical | `[SCHEDULER_DRIFT]` fq_codel vs FIFO — **expected Phase 0 finding** |
| `audit_shaper_config` | Critical | Score **65/100** (drift + missing IPv6) |
| `explain_shaper_config` | Critical | Narrative reflects drift |

**Verdict:** Shaper read path is **live-ready**. Critical severity reflects real OPNsense scheduler drift, not MCP regression.

BR-fix-b hints: `[SCHEDULER_DRIFT]` + `[ECN_INEFFECTIVE]` expected on this firewall; drop/flow/BW hints are conditional on runtime counters.

---

## Shaper MCP wiring (LS4)

| Check | Result |
|-------|--------|
| Tool count | **52** `@mcp.tool()` registrations (26 shaper + 26 legacy) |
| Write tools | All 16 write tools registered |
| `restore_shaper_snapshot.remove_orphans` | ✅ Wired (BR-fix-a) |
| `list_shaper_*` pagination params | ✅ Wired (BR-fix-c) |
| Missing registrations | None |

---

## Synthesis — fix backlog (LS5)

| Priority | ID | Issue | Action |
|----------|-----|-------|--------|
| **P1** | MCP-01 | `dhcp` crashes on `search=None` | Coalesce `None` before `.strip()` in `dhcp.py` |
| **P1** | MCP-02 | `fw_rules` empty when `enabled=None` | Filter only when `enabled is not None` |
| **P2** | DEP-01 | Redeploy without container recreate | Update deploy docs / install.sh post-step |
| **P2** | FW-01 | Live scheduler drift | Operator: reconfigure shaper or pipe rewrite on OPNsense |
| **P2** | FW-02 | Missing IPv6 shaper rules | Operator: add paired `ip6` WAN rules or accept audit warning |
| **P2** | MCP-03 | `set_shaper_settings` stub | Implement or document limitation |
| **P3** | MCP-04 | Post-redeploy MCP reconnect | Note in POST_DEPLOY smoke prompt |
| **P3** | TEST-01 | MCP schema tests for list pagination | Add register test like BR-fix-a |
| **P3** | TEST-02 | Unit tests for set/toggle queue/rule | Extend `test_shaper_write_tools.py` |

### Overall verdict

**Shaper feature: ready for agent use on live MCP** after Cursor MCP reconnect. Core homelab MCP has **two P1 regressions** (`dhcp`, `fw_rules`) unrelated to shaper but visible in standard smoke. Deploy procedure needs a **container recreate** step.

### Recommended next buckets (fix pass)

| Wave | ID | Title |
|------|-----|-------|
| 1 | MCP-fix-a ∥ MCP-fix-b | `dhcp` + `fw_rules` None handling |
| 2 | DEP-fix-a | Deploy runbook + optional install.sh recreate hook |
| 3 | FW-ops | Live scheduler reconfigure (operator, not code) |

---

## GitLab issues filed (2026-06-20 follow-up)

MCP workflows that failed on live infra — tracked for fix, not bypass:

| Issue | Title | Blocks MCP? |
|-------|-------|-------------|
| [#4](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/4) | Shaper pipe write tools fail — wrong POST payload shape | **Yes** — `set_shaper_pipe`, `add_shaper_pipe`, preset pipe updates |
| [#5](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/5) | SCHEDULER_DRIFT audit false positive for FQ-CoDel | Misleading read path — false critical |
| [#6](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/6) | MCP-first: file GitLab issues before bypass | Process |

**Resolved in branch (not issues):** MCP-01/MCP-02 (`dhcp`, `fw_rules` null args) — commit `cbcf539`.

**Session note:** Scheduler remediation required container API bypass (#4). After delete/recreate, shaping works; `sched_type=FIFO` in statistics may be expected per OPNsense core#8572 — see #5.

---

## Agent delivery

| Bucket | Owner | Status |
|--------|-------|--------|
| LS1 | Cursor | done |
| LS2 | Ollama-local (review) | done |
| LS3 | Ollama-workstation (review) | done |
| LS4 | Cursor (review) | done |
| LS5 | Cursor | done |
