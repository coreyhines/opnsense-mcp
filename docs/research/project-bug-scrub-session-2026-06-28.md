# Project bug scrub session - 2026-06-28

Approved by: User  
Tracker: `docs/research/project-bug-scrub-buckets.md`  
Scope: full-repo read-only bug scrub after diagnostics merge  
Execution mode: mixed backend review wave plus Cursor inline synthesis

## Session summary

| Bucket | Owner | Planned backend | Resolved backend | Cost pool | Exec | Sub-agent ID | Branch | Commit | Tests | Status |
|--------|-------|-----------------|------------------|-----------|------|--------------|--------|--------|-------|--------|
| R0 | Claude | claude-cli | claude-cli | claude_subscription | - | - | - | - | review only | done |
| R1 | Cursor | cursor-auto | cursor-auto | cursor_included | subagent readonly | `4393d359-fed3-4ca9-8bae-9f0a5564135b` | - | - | review only | done |
| R2 | Ollama-local | ollama-local | ollama-cloud | ollama_cloud | - | - | - | - | review only | done |
| R3 | Claude | claude-cli | claude-cli | claude_subscription | - | - | - | - | review only | done |
| R4 | Ollama-local | ollama-local | ollama-cloud | ollama_cloud | - | - | - | - | review only | done |
| R5 | Ollama-cloud | ollama-cloud | ollama-cloud | ollama_cloud | - | - | - | - | `ruff` shaper files; `307 passed` shaper tests | done |
| R6 | Cursor | cursor-auto | cursor-auto | cursor_included | subagent readonly | `43210bd1-9c98-42b6-aa9b-d0add093210e` | - | - | review only | done |
| RS | Cursor | cursor-auto | cursor-auto | cursor_included | inline | - | - | - | synthesis only | done |

## Integration health

| Check | Result |
|-------|--------|
| Combined tests | Not run; read-only review pass. R5 ran targeted shaper checks: `ruff` passed and `307 passed` with cloud farmer-provided dev deps. |
| Unmerged bucket branches | none created |
| Claude at farm | usage probe unavailable/429; CLI completed R0 and R3 |
| Ollama at farm | local `qwen3.6:35b-a3b-mxfp8` hung for R2/R4 with no progress after >10m; rerouted to cloud. Cloud `kimi-k2.7-code:cloud` completed R2/R4/R5. |
| Cursor at farm | ~58% total usage before wave; used two readonly subagents plus inline synthesis |
| Portfolio notes | Mixed backend execution used Claude, Cursor, Ollama Cloud, and attempted Ollama-local. |

## Reroutes

| Bucket | Planned | Resolved | Reason |
|--------|---------|----------|--------|
| R2 | ollama-local | ollama-cloud | Local Ollama farmer hung with no output beyond startup after >10 minutes; no working-tree edits. |
| R4 | ollama-local | ollama-cloud | Local Ollama farmer hung with no output beyond startup after >10 minutes; no working-tree edits. |

## Highest-priority findings

### P0/P1

1. **Firewall delete reports failure after successfully deleting and applying.**  
   `opnsense_mcp/tools/rmfw_rule.py` checks `result.get("success")`, but `delete_firewall_rule` returns `{"result": "success"}`. The tool can mutate the firewall, apply the change, then return an error. This is the most dangerous finding because it creates retry risk after a successful live mutation.

2. **Log fetch failures are reported as successful empty results.**  
   `opnsense_mcp/tools/firewall_logs.py` and `opnsense_mcp/utils/api.py` swallow API/transport failures and return `status: "success"` with `logs: []`. This can produce false negatives during incident triage.

3. **`dhcp_lease_delete` reports deletion success when providers return unsupported/error dicts.**  
   `opnsense_mcp/tools/dhcp_lease_delete.py` appends `"status": "deleted"` without inspecting provider responses. Dnsmasq/Kea can return `{"status": "error"}` without raising, and the tool still reports deleted leases.

4. **Traffic shaper apply paths treat failed reconfigure responses as applied.**  
   `opnsense_mcp/tools/shaper_service.py` and `opnsense_mcp/utils/shaper_write_helpers.py` do not require `status == "ok"` for `service/reconfigure`. A response like `{"status": "failed"}` can still be interpreted as applied.

5. **Traffic shaper bandwidth guardrails can be wrong or non-blocking.**  
   `opnsense_mcp/tools/shaper_pipes.py` validates raw `bandwidth` without metric conversion and still mutates after guardrail errors. A `1 Gbit` pipe is validated as `1 Mbit`; unsafe changes can proceed.

6. **Stdio MCP server is missing the traffic-shaper tool surface.**  
   `opnsense_mcp/server.py` and `mcp_start.sh` expose a different tool set than `opnsense_mcp/fastmcp_server.py`; the shaper tools are FastMCP/HTTP only. Stdio clients cannot call tools that HTTP clients can.

### P2

7. **`set_fw_rule` / `update_firewall_rule` update payload shape is likely wrong.**  
   `opnsense_mcp/tools/set_fw_rule.py` builds nested `source`/`destination` dicts and passes bools, while add-rule code flattens and normalizes fields. Rule edits may be rejected, ignored, or partially applied.

8. **`ssh_fw_rule` advertises a bypass path that likely cannot work on real OPNsense.**  
   `opnsense_mcp/tools/ssh_fw_rule.py` builds `opnsense-shell firewall rule add` / reload commands, which the reviewer reports are not valid OPNsense CLI commands, and drops several rule fields.

9. **`packet_capture` fetch and stop semantics are unsafe/broken.**  
   `start_capture` writes tcpdump to stdout while `fetch_pcap` tries to retrieve `/tmp/mcp_capture.pcap`. `stop_capture` uses broad `pkill -f 'tcpdump -i'`, which can kill unrelated captures.

10. **Interface discovery is misleading in several paths.**  
    `OPNsenseClient.get_interfaces()` derives interfaces from ARP/NDP neighbor tables instead of the interface-names endpoint. `InterfaceListTool` can fall back to example data with success. Packet capture has site-specific interface mappings.

11. **`firewall.py` list and interface resolution paths are broken or divergent.**  
    `FirewallRule` expects `id` while API rows use `uuid`; `_resolve_interface_name` expects a dict but clients return a list.

12. **DNS override search truncates at 100 rows.**  
    `OPNsenseClient.search_host_overrides()` hardcodes `rowCount: 100`, affecting DNS listings, conflict checks, and delete lookups in larger environments.

13. **DHCP dynamic-to-static promotion may use the wrong lease MAC field.**  
    `find_ipv4_conflicts()` reads `hwaddr`; other lease code uses `mac`. If live dnsmasq lease rows use `mac`, promotion is incorrectly blocked.

14. **`apply_shaper_preset` can report success while leaving existing resources disabled.**  
    Existing pipe/queue/rule updates omit `enabled`, so a disabled preset object remains disabled.

15. **Snapshot restore cannot recreate deleted shaper resources.**  
    `apply_snapshot_restore()` replays via `set_*` endpoints only; if UUIDs were deleted after snapshot capture, restore is incomplete.

16. **`PfStatesTool` and `InterfaceHealthTool` can raise uncaught `ValueError` on invalid numeric params.**  
    `src_port`, `dst_port`, and `max_results` use bare `int()` without structured error envelopes.

17. **`get_logs` deployed MCP response bypasses the compatibility shim.**  
    Servers wire `FirewallLogsTool` directly while registry maps `get_logs` to `GetLogsTool`; legacy `summary` shape may differ from live MCP.

18. **`get_interfaces` / mock / output schema drift is broad.**  
    LLDP model field names are unused/mismatched; mock firewall log search uses `src_ip`/`dst_ip` while real code filters `src`/`dst`.

### P3 / cleanup

19. GitLab coverage regex never matches pytest-cov term output, so GitLab coverage tracking is silently broken.
20. `requirements.txt` is not in sync with `pyproject.toml` for `pydantic-settings`.
21. ~~`deploy/install.sh` uses the `opensense-mcp` typo in default repository URLs.~~ Fixed: GitLab project renamed to `opnsense-mcp`; installer URLs updated.
22. `gitleaks` scans `main` history instead of feature-branch deltas.
23. Several deployment and scanner images are floating tags or otherwise inconsistent.
24. `MCP_SECRET_KEY` has a default but is not enforced by the runtime.
25. `create_access_token()` custom expiry is overwritten by `create_jwt()` default expiry.
26. `opnsense-mcp-start` references a non-existent `mcp_server` module.
27. `mcp_start.sh` defaults `DEBUG=1`.
28. `system.py` diagnostics can run local subprocess mutations from an MCP tool.

## Suggested fix buckets

| Bucket | Theme | Candidate files |
|--------|-------|-----------------|
| F1 | Honest mutation status and apply handling | `rmfw_rule.py`, `dhcp_lease_delete.py`, `shaper_service.py`, `shaper_write_helpers.py` |
| F2 | Firewall rule update/delete correctness | `set_fw_rule.py`, `utils/api.py`, `ssh_fw_rule.py`, firewall tests |
| F3 | Shaper guardrails and restore safety | `shaper_pipes.py`, `shaper_presets.py`, `shaper_mutation.py`, shaper tests |
| F4 | Silent failure removal for read tools | `firewall_logs.py`, `utils/api.py`, `interface_list.py`, `arp.py` |
| F5 | MCP tool parity and runtime hygiene | `server.py`, `fastmcp_server.py`, startup scripts, runtime tests |
| F6 | DHCP/DNS edge cases | `dhcp_lease_delete.py`, `dhcp_host.py`, `utils/api.py`, DNS/DHCP tests |
| F7 | CI/deploy hygiene | `.gitlab-ci.yml`, `requirements.txt`, `deploy/install.sh`, deploy tests |
| F8 | Input validation envelopes | `pf_diagnostics.py`, `interface_health.py`, `packet_capture.py`, validation tests |

## Raw output locations

| Bucket | Output |
|--------|--------|
| R0 | `/tmp/project-bug-scrub-R0.log` |
| R2 | `/tmp/project-bug-scrub-R2.log` |
| R3 | `/tmp/project-bug-scrub-R3.log` |
| R4 | `/tmp/project-bug-scrub-R4.log` |
| R5 | `/tmp/project-bug-scrub-R5.log` |
| R1 | Cursor subagent `4393d359-fed3-4ca9-8bae-9f0a5564135b` |
| R6 | Cursor subagent `43210bd1-9c98-42b6-aa9b-d0add093210e` |
