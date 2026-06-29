# Diagnostics features — Phase 0 session (2026-06-28)

GitLab issues: [#7](https://gitlab.freeblizz.com/coreyhines/opnsense-mcp/-/work_items/7) PF states/stats, [#8](https://gitlab.freeblizz.com/coreyhines/opnsense-mcp/-/work_items/8) log analysis, [#9](https://gitlab.freeblizz.com/coreyhines/opnsense-mcp/-/work_items/9) interface health.

## Verdict

**Phase 0 passed** — proceed to bucketize. One spec correction required for #7; one open risk for `pf_statistics`.

## Methods

| Feature | Probe | Path |
|---------|-------|------|
| #8 logs | MCP `get_logs` | Live MCP |
| #9 interfaces | MCP `interface_list` | Live MCP |
| #7 PF | Workspace client | MCP bypass: no `pf_states`/`pf_statistics` tools yet (pre-#7) |

Fixtures: `tests/fixtures/phase0-diagnostics/`

## #8 — Firewall log analysis

**Bug confirmed on live MCP.** Raw logs use `protoname`, `src`, `dst`, `srcport`, `dstport`, `rid`, `rulenr`, `label` — but `analysis` reports `protocols: {unknown: 5}` and `top_sources/destinations: unknown`.

Canonical implementation target: `opnsense_mcp/tools/firewall_logs.py` (both MCP servers register it).

Sample keys captured in `firewall_logs_sample.json`.

## #9 — Interface health

**`interface_list` is sufficient** for v2 — no extra statistics API merge required on this firmware.

Representative interfaces in `interface_list_sample.json`:

| Interface | Notes for health tool |
|-----------|----------------------|
| `ax1` (WAN) | Real input errors (1675); rollover-like `output errors` uint64 artifact |
| `ax0_vlan81` | Non-zero output errors (2866); VLAN parent `ax0` |
| `igb0` | Unassigned, no carrier |
| `bridge0` | Bridge members `igb3`, `ax0_vlan5` |
| `ax0_vlan5` | Disabled VLAN (`enabled: false`) |

SFP metadata present on `ax1` (temperature, voltage). Counter rollover values validate v2 `counter_anomaly` rule.

## #7 — PF state and statistics

### State rows — use `query_states`, not `pf_states`

| Endpoint | Method | Result |
|----------|--------|--------|
| `/api/diagnostics/firewall/pf_states` | GET/POST | **Metadata only**: `{current, limit}` (~6k / 1.6M) |
| `/api/diagnostics/firewall/query_states` | POST `{"current":1,"rowCount":N}` | **Rows** with 22 fields per state |

Row keys: `label`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `proto`, `ipproto`, `interface`, `iface`, `state`, `age`, `expires`, `pkts`, `bytes`, `direction`, `rule`, `id`, NAT fields, etc.

**Action:** Update #7 v2 implementation to list states via `query_states`; use `pf_states` GET only for state-table pressure (`current`/`limit`).

### PF statistics — empty on this key

| Endpoint | Method | Result |
|----------|--------|--------|
| `/api/diagnostics/firewall/pf_statistics` | GET/POST | **Empty list `[]`** |

**Action:** Bucket `7a` implements best-effort parser + falls back to state-table health from `pf_states` meta when statistics payload is empty. File GitLab note on issue #7 if live smoke still empty after implementation.

## Integration impact

- Current FastMCP tool count: **52**
- After #7 + #9: **55** (+ `pf_states`, `pf_statistics`, `interface_health`)
- #8 enhances existing `get_logs` (no count change)

## Next step

Bucket plan: [diagnostics-features-buckets.md](diagnostics-features-buckets.md)
