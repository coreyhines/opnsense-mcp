# Traffic Shaper & FQ-CoDel — Feature Spec

Status: **spec complete** (interview + Phase 0 live API spike).
Last updated: 2026-06-20.
Target branch: `feat/traffic-shaper-spec` → implementation TBD.

> **Phase 0 spike:** read-only probes against production firewall validated all
> list/get/statistics endpoints. First audit run found **config/runtime scheduler
> drift** (config says FQ-CoDel; statistics report FIFO). See
> [Spike results](#phase-0-spike-results-2026-06-20).

---

## Summary

Add MCP tools so an agent can **fully manage** OPNsense traffic shaping (pipes,
queues, rules, global settings), **observe** runtime behavior, **audit** config
against best practices, and **explain** changes in plain language.

Implementation is **REST-only** (no SSH fallback in v1). Mutations **apply by
default** with auto-`reconfigure`; agents get structured JSON plus human-readable
summaries. A **restore-from-snapshot** tool provides rollback.

**Out of scope v1:** per-firewall-rule limiters, legacy ALTQ, VPN-interface edge
cases, bulk import/export, cross-MCP correlation (CloudVision/Coroot).

---

## Goals (user stories)

### Core

| Story | Description |
|-------|-------------|
| Greenfield setup | Create FQ-CoDel bufferbloat shaping from scratch (pipes + queues + rules) |
| Tune | Adjust bandwidth and scheduler parameters after ISP change or bufferbloat testing |
| Edit existing | Modify/disable/toggle in-place config without rebuilding |
| Troubleshoot | Read stats/logs, correlate with gateway and capture, explain whether shaping works |
| Temp disable | Toggle shaping off and back on without deleting objects |

### Additional (interview)

| Story | Description |
|-------|-------------|
| Audit / compliance | Compare live config + runtime stats to best-practice checklist; report drift |
| Multi-user explain | Plain-language summary of current config and what a change would do |

### Success criteria

Agent can:

1. Read full shaper config (normalized flat view + raw if needed).
2. Mutate config, auto-reconfigure, and confirm pending vs applied state.
3. Read `service/statistics` with **structured interpretation hints** (drops, util vs cap, ECN, scheduler match).
4. Optionally correlate with `gateway_status`, `get_logs`, `packet_capture`, and external test guidance (waveform.net, speedtest).
5. Compare statistics against an optional **baseline** snapshot from a prior call.
6. Run `audit_shaper_config` and `explain_shaper_config` for non-technical users.

**Audience:** homelab-friendly DX with production-style guardrails (validation, confirm-on-delete, no LAN shaping).

---

## Scope

### In scope (v1)

| Layer | OPNsense API | MCP coverage |
|-------|--------------|--------------|
| Pipes | `add_pipe`, `set_pipe`, `get_pipe`, `search_pipes`, `del_pipe`, `toggle_pipe` | Full CRUD + list |
| Queues | `add_queue`, `set_queue`, `get_queue`, `search_queues`, `del_queue`, `toggle_queue` | Full CRUD + list |
| Rules | `add_rule`, `set_rule`, `get_rule`, `search_rules`, `del_rule`, `toggle_rule` | Full CRUD + list |
| Global | `settings/get`, `settings/set` | Read + write |
| Service | `service/reconfigure`, `service/statistics` | Auto on apply; dedicated stats tool |
| Presets | — | `apply_shaper_preset` (e.g. `bufferbloat_wan`) |
| Snapshots | — | Pre-mutation snapshot + `restore_shaper_snapshot` |
| Audit / explain | — | Dedicated read tools |

**Schedulers:** all pipe schedulers exposed by OPNsense (FQ-CoDel, FQ-PIE, FIFO, QFQ, DRR, WFQ, CoDel, PIE fields).

**Integrations with existing MCP tools:**

- `interface_list` — resolve WAN/LAN, **line rate** for bandwidth validation (diagnostics `get_interface_config` returned 403 on spike; use `interface_list` statistics instead).
- `aliases` — validate rule source/destination when not `any`.
- `fw_rules` — cross-reference related firewall rules (informational; per-rule limiters out of scope).

**Dual-stack:** agent workflows must create **paired** IPv4 (`proto: ip`) and IPv6 (`proto: ip6`) shaper rules when using presets or greenfield setup.

### Out of scope (v1)

- Per-firewall-rule **limiters** (separate from traffic shaper module)
- Legacy **ALTQ**
- **WireGuard/IPsec** interface-specific shaping edge cases
- Bulk **upload/download** pipes & queues
- **CloudVision / Coroot** correlation (deferred)
- **Readonly MCP env flag** (API key permissions sufficient)
- SSH / `ipfw` CLI verification

---

## Phase 0 spike results (2026-06-20)

Environment: production firewall (`fw.freeblizz.com`), existing MCP API key, OPNsense
recent stable (24.x/25.x class).

### Current config (edit-in-place baseline)

| UUID (prefix) | Type | Name | Notes |
|---------------|------|------|-------|
| `e93038e5…` | Pipe 10000 | Download pipe | 1776 Mbit/s, FQ-CoDel (config), ECN on |
| `f9b19d27…` | Pipe 10001 | Upload pipe | 325 Mbit/s, FQ-CoDel (config), ECN on |
| `84c6c7d8…` | Queue | Download queue | → Download pipe, weight 100 |
| `14cc84dd…` | Queue | Upload queue | → Upload pipe, weight 100 |
| `690c995b…` | Rule | Download Rule | WAN, **in**, proto **ip**, → Download queue |
| `5122c31a…` | Rule | Upload Rule | WAN, **out**, proto **ip**, → Upload queue |

FQ-CoDel advanced fields (`fqcodel_quantum`, `fqcodel_limit`, `fqcodel_flows`,
`codel_target`, `codel_interval`) are **empty strings** in config → OPNsense defaults.

### Runtime statistics (active shaping)

- Download rule: ~3.2M pkts, ~2.5 GB (last accessed 2026-06-20)
- Upload rule: ~2.8M pkts, ~2.2 GB
- Pipes report configured bandwidth correctly in stats (`1.776 Gbit/s`, `325 Mbit/s`)

### Critical audit finding: scheduler drift

| Source | Download pipe scheduler |
|--------|-------------------------|
| `settings/get` | `fq_codel` selected |
| `service/statistics` | `sched_type: FIFO` |

Both pipes show FIFO at runtime despite FQ-CoDel in saved config. **v1 audit tool
must flag this.** Post-apply verification should compare config scheduler to
`statistics.scheduler.sched_type` and recommend reconfigure or full pipe rewrite if
mismatch persists (see OPNsense issues around scheduler apply).

### Dual-stack gap

Only `proto: ip` rules exist. Interview requirement: paired v4/v6 rules. Audit
should report **missing IPv6 shaper rules** as a finding.

### API response shapes

1. **`GET /api/trafficshaper/settings/get`** — full tree under `ts` with GUI enum
   objects: `{ "field": { "option": { "selected": 0|1, "value": "..." } } }`.
   Use for **serialize** on write (full payload, mirror GUI).

2. **`POST /api/trafficshaper/settings/search_{pipes,queues,rules}`** with
   `{"current": 1, "rowCount": 50}` — flat rows for listing (`interface: "wan"`,
   `proto: "ip"`, `target: "<uuid>"`).

3. **`GET /api/trafficshaper/service/statistics`** — `{ "status": "ok", "items": [...] }`
   with pipes, queues, template queues, per-rule `pkts`/`bytes`/`accessed`.

4. **Apply path:** `POST /api/trafficshaper/service/reconfigure` (not `flushreload`
   for applying pending GUI changes — see OPNsense forum/issue #7014).

### Permissions

| Endpoint | Result |
|----------|--------|
| trafficshaper/* | OK with existing MCP key |
| diagnostics/interface/get_interface_config/ax1 | 403 Forbidden |
| interface_list (MCP) | OK — WAN `ax1` line rate 10 Gbit/s |

Bandwidth validation guardrail: compare pipe Mbit/s to `interface_list` **line rate**
for selected rule interface (WAN only for v1).

---

## Architecture

### Request flow

```
MCP client
  → FastMCP tool (e.g. set_shaper_pipe)
  → ShaperTool / ShaperService
  → normalize (read) / serialize (write)
  → OPNsenseClient._make_request
  → POST/GET /api/trafficshaper/...
  → [on apply] POST /api/trafficshaper/service/reconfigure
  → interpret statistics + audit checks
  → { structured: {...}, summary: "...", hints: [...] }
```

### New code layout (proposed)

```
opnsense_mcp/
├── tools/
│   ├── shaper_pipes.py      # list/get/set/add/delete/toggle pipe
│   ├── shaper_queues.py
│   ├── shaper_rules.py
│   ├── shaper_settings.py   # global get/set
│   ├── shaper_service.py    # statistics, apply/reconfigure
│   ├── shaper_audit.py      # audit_shaper_config, explain_shaper_config
│   ├── shaper_presets.py    # apply_shaper_preset
│   └── shaper_snapshot.py   # restore_shaper_snapshot
└── utils/
    ├── shaper_normalize.py  # GUI ↔ flat models
    ├── shaper_serialize.py  # flat → full GUI POST body
    ├── shaper_interpret.py  # statistics → hints + verdict
    └── shaper_audit_rules.py # best-practice checklist
```

Register all tools in `fastmcp_server.py` and legacy `server.py` if still required.

### Data model (flat agent view)

Agents and tests use **flat** records; serialization layer converts to GUI payloads.

**Pipe (flat):**

```python
{
  "uuid": "...",
  "number": "10000",
  "description": "Download pipe",
  "enabled": True,
  "bandwidth": 1776,
  "bandwidth_metric": "Mbit",  # bit|Kbit|Mbit|Gbit
  "scheduler": "fq_codel",     # fq_codel|fifo|fq_pie|qfq|rr|""
  "mask": "none",
  "codel_enable": False,
  "codel_target_ms": None,     # empty → default
  "codel_interval_ms": None,
  "codel_ecn_enable": True,
  "fqcodel_quantum": None,
  "fqcodel_limit": None,
  "fqcodel_flows": None,
  "pie_enable": False,
}
```

**Queue (flat):** `uuid`, `description`, `enabled`, `pipe_uuid`, `weight`, mask/CoDel/PIE fields.

**Rule (flat):** `uuid`, `description`, `enabled`, `interface`, `interface2`, `direction`
(`in`|`out`|both), `proto` (`ip`|`ip6`|`tcp`|…), `source`, `destination`, ports, DSCP,
`target_uuid` (queue or pipe), `sequence`.

### Write semantics

| Decision | Choice |
|----------|--------|
| Default mutation | **Apply immediately** (`apply=true` default) |
| Reconfigure | Auto-call `service/reconfigure` when apply=true |
| Response | Include `pending_changes`, `reconfigure_result`, **pre-change snapshot** id |
| Payload | **Full GUI payload** on update (fetch `get_*` first, merge, post) |
| Idempotency | Identical re-send → **error/warning** (do not silent no-op) |
| Delete | Hard delete with **confirmation token** (Pi-hole-style two-step) |
| Defaults on create | **MCP opinionated** (preset or documented defaults); see Presets |

### Snapshot / rollback

Before any destructive or broad mutation:

1. Capture `settings/get` + `search_*` summaries + timestamp.
2. Store in-memory snapshot map keyed by `snapshot_id` (session-scoped initially; document limitation for SSE multi-tenant).
3. `restore_shaper_snapshot(snapshot_id, apply=true)` replays saved JSON via `set` / per-resource sets + reconfigure.

Future: persist snapshots to disk if SSE deploy needs cross-session rollback.

---

## MCP tools (v1)

Granular, resource-oriented tools. Each write tool accepts `apply: bool = true`.

### Read

| Tool | Purpose |
|------|---------|
| `list_shaper_pipes` | Flat list (+ optional filters) |
| `get_shaper_pipe` | One pipe by uuid or description |
| `list_shaper_queues` | Flat list |
| `get_shaper_queue` | One queue |
| `list_shaper_rules` | Flat list |
| `get_shaper_rule` | One rule |
| `get_shaper_settings` | Global shaper settings |
| `shaper_statistics` | Runtime stats + **structured hints**; optional `baseline_id` for compare |
| `audit_shaper_config` | Best-practice checklist + drift vs statistics |
| `explain_shaper_config` | Plain-language narrative for non-technical users |

### Write

| Tool | Purpose |
|------|---------|
| `add_shaper_pipe` / `set_shaper_pipe` | Create / update (full payload) |
| `add_shaper_queue` / `set_shaper_queue` | Create / update |
| `add_shaper_rule` / `set_shaper_rule` | Create / update |
| `toggle_shaper_pipe` / `toggle_shaper_queue` / `toggle_shaper_rule` | Enable/disable |
| `delete_shaper_pipe` / `delete_shaper_queue` / `delete_shaper_rule` | Requires `confirm` token |
| `set_shaper_settings` | Global settings |
| `apply_shaper` | Explicit reconfigure (when prior call used `apply=false`) |
| `apply_shaper_preset` | Named preset workflow |
| `restore_shaper_snapshot` | Rollback |

### Tool output contract

Every tool returns:

```python
{
  "status": "success" | "error" | "warning",
  "structured": { ... },           # machine-readable
  "summary": "Human markdown/table", # agent-facing prose
  "hints": ["..."],                  # interpretation / next steps
  "snapshot_id": "...",              # present on mutations
}
```

Follow repo rule: summarize for users; do not dump raw JSON unless asked.

---

## Presets

### `bufferbloat_wan`

Opinionated defaults from [OPNsense FQ-CoDel how-to](https://docs.opnsense.org/manual/how-tos/shaper_bufferbloat.html):

| Parameter | Default behavior |
|-----------|------------------|
| Download / upload bandwidth | **85% of supplied ISP rates** (caller passes measured or advertised rates) |
| Scheduler | `fq_codel` both pipes |
| ECN | enabled on pipes |
| Queues | one per pipe, weight 100 |
| Rules | WAN **in** → download queue (`proto: ip` + `proto: ip6`); WAN **out** → upload queue (both protos) |
| FQ-CoDel tunables | omit → OPNsense defaults unless caller overrides |

Preset must **edit in place** when pipes/queues/rules already exist (match by description or uuid list from audit).

Other preset names (future): `gaming_low_latency`, `conservative_80pct`.

---

## Observability & interpretation

### Primary: `shaper_statistics`

Parse `items[]`:

- **Pipes:** `bw`, `description`, `uuid`, `scheduler.sched_type`, `flowset`
- **Queues:** `weight`, `flows`, rule attachment
- **Rules:** `pkts`, `bytes`, `accessed`, `rule_uuid`

### Structured hints (examples)

| Condition | Hint |
|-----------|------|
| Config scheduler ≠ runtime `sched_type` | `critical`: scheduler drift — FQ-CoDel configured but FIFO active |
| Rule `pkts` == 0 while WAN traffic expected | `warning`: rule may not match traffic (check proto/direction/interface) |
| Missing `ip6` rules | `warning`: IPv6 traffic not shaped |
| Pipe bandwidth > interface line rate | `error`: cap exceeds WAN physical rate |
| Pipe on non-WAN interface | `warning`: LAN shaping discouraged |
| `queue_params: droptail` + high load | suggest bufferbloat test / tune bandwidth |

### Secondary MCP tools

| Tool | Use |
|------|-----|
| `gateway_status` | Before/after latency & loss when monitor configured |
| `get_logs` | Shaper-related syslog if present |
| `packet_capture` | WAN capture during user speed test |
| External | Agent suggests waveform.net or similar |

### Baseline compare

`shaper_statistics(baseline_id=...)` stores prior reading server-side (session map):
delta on rule `pkts`/`bytes`, scheduler type unchanged, etc.

---

## Audit checklist (`audit_shaper_config`)

| Check | Severity |
|-------|----------|
| Download + upload pipes exist and enabled | error if missing |
| Scheduler FQ-CoDel (or user policy) on WAN pipes | warning if not |
| Config scheduler matches runtime statistics | error on drift |
| Paired IPv4 + IPv6 rules for WAN in/out | warning if missing |
| Bandwidth ≤ 85–95% of reference ISP rate (if rates supplied) | info/warning |
| Bandwidth ≤ WAN interface line rate | error |
| ECN enabled on FQ-CoDel pipes | info |
| No shaper rules on LAN interfaces | warning |
| Queues linked to correct pipes | error |
| Rules target queues (not mis-targeted pipes) | warning |
| Global shaper enabled (if exposed in settings/get) | info |

Output: scored report + `explain_shaper_config`-ready narrative.

---

## Safety guardrails

| Guardrail | Implementation |
|-----------|----------------|
| No LAN shaping | Reject or warn when rule `interface` not in `{wan, ...}` allowlist |
| Bandwidth vs interface | `interface_list` line rate check |
| Delete confirmation | Two-step token like Pi-hole remove |
| Description required | On create (optional on update) |
| Snapshot before mutate | Always return `snapshot_id` |
| Minimal other caps | Trust agent + API key otherwise |

---

## Testing strategy

| Layer | Approach |
|-------|----------|
| Unit | Fixture JSON from Phase 0 spike (`tests/fixtures/shaper/`) — normalize, serialize, interpret, audit |
| Integration (homelab) | **May mutate** with explicit confirmation; read-only in CI |
| Live smoke | Extend `benchmark_performance.py` with shaper read tools |
| Agent sessions | Primary E2E — audit → tune → statistics → explain |

Idempotency test: identical `set_shaper_pipe` → expect warning/error.

---

## OPNsense API reference

Module: `trafficshaper` — [official API table](https://docs.opnsense.org/development/api/core/trafficshaper.html).

**Service:**

- `POST service/reconfigure` — apply pending changes
- `GET service/statistics` — runtime counters
- `POST service/flushreload` — not equivalent to GUI Apply

**Settings (subset):** `get`, `set`, `add_*`, `set_*`, `del_*`, `toggle_*`, `search_*`, `get_*`.

Minimum OPNsense: **recent stable 24.x / 25.x** (spike target); document exact minimum after implementation QA.

---

## Implementation phases

### Phase 1 — Read path

- `utils/shaper_normalize.py`, `shaper_interpret.py`, `shaper_audit_rules.py`
- Read tools + `shaper_statistics` + `audit_shaper_config` + `explain_shaper_config`
- Unit tests from fixtures
- `benchmark_performance.py` read smoke

### Phase 2 — Write path

- `shaper_serialize.py`, snapshot store
- CRUD + toggle + delete (confirm) + `apply_shaper` + `restore_shaper_snapshot`
- Auto-reconfigure, pending/applied state, idempotency warnings

### Phase 3 — Presets & docs

- `apply_shaper_preset` (`bufferbloat_wan`)
- Update `docs/REFERENCE/FUNCTION_REFERENCE.md`
- Example agent flows in spec or EXAMPLES (optional follow-up)

**Rollout:** ship when API coverage complete — **no feature flag**.

---

## Open questions (resolved)

| Question | Resolution |
|----------|------------|
| Import/export | Skip v1 |
| Dry-run default | Apply by default; support `apply=false` for staging |
| SSH verify | REST only v1 |
| Readonly MCP | No — API key ACL |
| Multi-WAN | Single WAN v1 |
| Existing config | Edit in place; preset matches by description/uuid |

---

## References

- [OPNsense Trafficshaper API](https://docs.opnsense.org/development/api/core/trafficshaper.html)
- [Fighting Bufferbloat with FQ_CoDel](https://docs.opnsense.org/manual/how-tos/shaper_bufferbloat.html)
- [Apply vs flushreload (issue #7014)](https://github.com/opnsense/core/issues/7014)
- DHCP move spec pattern: `docs/research/dhcp-host-move-feasibility.md`
