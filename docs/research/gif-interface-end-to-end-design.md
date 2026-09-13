# GIF interface end-to-end — design

**Date:** 2026-09-12  
**Status:** draft for review  
**Scope:** GIF-only end-to-end (device → assign → enable/address), general GIF CRUD; Hurricane Electric Tunnel Broker is a tested example, not a special API.

## Decisions (locked)

| Decision | Choice |
|----------|--------|
| Depth | End-to-end: create device, assign, enable/address, verify |
| Width (v1) | GIF only; GRE / bridge / LAGG / VXLAN later |
| Acceptance shape | General GIF + assign/enable/address; Tunnel Broker as live/example test |
| Tool surface | Extend `interface_device` (Approach 1) |

## Goals

- Agents can create, list, update, and delete GIF devices via MCP.
- Agents can assign a free `gifN` to an OPNsense interface id (`optX` or named).
- Agents can enable and put a static address on that assignment when needed, using the existing SSH path where the API cannot.
- A Tunnel Broker-style setup is expressible by composing those actions (no HE-specific parameters).
- Success is verified by re-read, not by HTTP 200 / `reconfigure` ok alone.

## Non-goals (v1)

- GRE, bridge, LAGG, VXLAN, PPP.
- Orchestrated single-shot `configure_gif` that hides partial failure.
- Inventing default IPv6 gateway inside `interface_device` (use existing `routing` tools; document the step).
- Expanding the API key’s privileges automatically (call out the ACL gap).

## Architecture

Extend the existing `interface_device` grouped tool.

```
create_gif / update_gif / list_gif / delete_gif
        │
        ▼  gif_settings MVC (+ reconfigure)
     gifN device exists
        │
        ▼  assign (assignment MVC)
     optX (or chosen id) bound to gifN
        │
        ▼  set_address (existing SSH tool) when enable/static needed
     interface enabled + address confirmed by ifconfig read-back
        │
        ▼  diagnostics / routing (existing) for verify + gateway
```

### Backend map

| Action | Backend | Notes |
|--------|---------|-------|
| `list_gif`, `create_gif`, `update_gif`, `delete_gif` | `/api/interfaces/gif_settings/{search_item,get_item,add_item,set_item,del_item,reconfigure}` | Probed model: live `Gif.xml` on fw |
| `assign` | `/api/interfaces/assignment/{search_item,get_item,add_item?,set_item?}` | Device bind only; no addressing |
| `set_address` | existing `set_interface_address` | SSH; expires when model gains `ipaddr`/`ipaddrv6` |
| VLAN / loopback | unchanged | |

## Live research (this firewall)

### Gif.xml (read from `/usr/local/opnsense/mvc/app/models/OPNsense/Interfaces/Gif.xml`)

Array item fields under `gif`:

| Model field | Role |
|-------------|------|
| `local-addr` | Volatile `LinkAddressField`; required; default `wan`. Dispatches into `if` or `ipaddr`. |
| `if` | Parent interface name when local-addr is an interface. |
| `ipaddr` | Parent as ordinary/CARP address when not an interface key. |
| `gifif` | Device name; required; mask `^gif(\d)*$`; unique. |
| `remote-addr` | Outer peer; `NetworkField`, mask not allowed. |
| `tunnel-local-addr` | Inner local; `NetworkField`, mask not allowed. |
| `tunnel-remote-addr` | Inner remote; `NetworkField`, mask not allowed. |
| `tunnel-remote-net` | Prefix length for tunnel remote; integer 1–128; **default 32**; required. |
| `descr` | Description. |
| `link1` | Boolean (ECN-friendly behaviour in UI/docs). |
| `link2` | Boolean (route via configured gateway / related). |
| `noclamp` | Boolean (ingress-filter related in UI). |

Caller-facing names (stable MCP surface) map to these wire keys; the mapper is tested against a captured `get_item` fixture once ACL allows the probe.

### Assignment API

- `GET /api/interfaces/assignment/get_item/` works with the current key.
- Blank/assignment rows expose: `descr`, `identifier`, `icon`, `optgroup`, `if`, `lock` (matches existing `set_interface_address` docs).
- Search rows use those keys; sample: `uuid`/`identifier` = `wan`, `if` = `ax1`.
- No address fields — confirmed.

### Privilege gap (blocking for GIF CRUD until fixed)

- `gif_settings/*` returned **HTTP 403 Forbidden** with the current API credentials used from this workstation.
- Assignment endpoints succeed.
- Spec requirement: document the OPNsense ACL privilege needed for GIF (Interfaces → Devices → GIF / equivalent API privilege). Implementation and live tests cannot pass until the key used by MCP has that privilege. File/track as an ops prerequisite, not a code workaround.

## Components

### GIF tools (new)

Pattern: same as VLAN (`MkVlanTool` / `ListVlansTool` / delete+confirm): `run_apply`, reuse existing device if idempotent key matches, project list rows to public fields.

**Idempotency for create:** reuse an existing GIF when `if`/`ipaddr` + `remote-addr` + `tunnel-local-addr` + `tunnel-remote-addr` already match (do not delete/recreate; may already be assigned).

**`create_gif` / `update_gif` inputs (MCP):**

| Param | Required | Maps toward |
|-------|----------|-------------|
| `parent` | yes (create) | `if` when it is an interface key; else `ipaddr` |
| `remote` | yes | `remote-addr` |
| `tunnel_local` | yes | `tunnel-local-addr` |
| `tunnel_remote` | yes | `tunnel-remote-addr` |
| `tunnel_remote_net` | no (default: 32; HE IPv6 examples use 64 — caller must set) | `tunnel-remote-net` |
| `device` | no | `gifif` (auto if omitted, following firmware behaviour) |
| `description` | no | `descr` |
| `ecn` | no | `link1` |
| `link2` | no | `link2` |
| `noclamp` | no | `noclamp` |
| `apply` | no, default **false** | `reconfigure` |

**`list_gif`:** project uuid, device (`gifif`), parent (`if`/`ipaddr`), remote, tunnel endpoints, descr, enabled-ish flags.

**`delete_gif`:** confirm token; refuse if any assignment `if` equals the GIF device name.

### `assign` (new member of `interface_device`)

| Param | Required | Notes |
|-------|----------|-------|
| `device` | yes | e.g. `gif0`; must appear in assignment blank `if` options |
| `identifier` | no | Prefer firmware-assigned `optN` if omitted |
| `description` | no | `descr` |
| `apply` | no, default false | Reload assignments |

Returns the assignment identifier and device. Re-read via `search_item` before reporting success.

Exact add vs set endpoint and JSON envelope are finalized in implementation after a privileged probe / captured fixture (assignment blank is already readable).

### `set_address` (existing)

Unchanged. Used after assign to enable and optionally set a static when the GIF device fields are not enough for the operator’s goal. For classic HE setups, tunnel endpoints are primarily on the GIF device (`tunnel-*-addr`); enable of the assigned interface may still require this path or an enable-only write discovered during implementation.

## Error handling

| Case | Behaviour |
|------|-----------|
| GIF API 403 | `status: error` with explicit “API privilege missing for gif_settings”; no partial invent |
| Invalid addresses | Refuse via `ipaddress` parse (no string injection into SSH/PHP) |
| `tunnel_remote_net` out of 1–128 | Refuse |
| Create when identical tunnel exists | Reuse; `created: false` |
| Delete while assigned | Refuse with holder list |
| Delete without confirm | `confirmation_required` + token |
| `apply` / reconfigure configd refuse at HTTP 200 | `applied: false` via `run_apply` |
| Assign device not in blank options | Refuse (device not instantiate / wrong name) |
| Address write | Existing set_interface_address safety + exact ifconfig read-back |

## Testing

### Unit / contract

- Fixture from live `get_item` / `search_item` once ACL allows; `test_fixture_shapes` style asserts non-empty projected fields.
- Mapper: MCP params ↔ wire keys (including `local-addr` / `if` / `ipaddr` dispatch).
- Idempotent create reuse.
- Delete refuses when assignment holds device.
- Confirm token required on delete.
- `apply` default declared false for GIF writes.
- Grouped `interface_device` schema: no type unions, no `constructor` / prototype keys (Cursor).
- Guidance strings only name real actions.

### Live / example (Tunnel Broker shape, not HE-branded API)

Documented sequence (dry-run then apply) using disposable addresses in documentation ranges where possible, or a clearly flagged lab GIF:

1. `create_gif` with parent/remote/tunnel fields + `tunnel_remote_net=64` for v6 example  
2. `assign`  
3. enable / address as required  
4. `list_gif` + assignment search + interface diagnostics  
5. teardown: confirm delete after unassign  

Optional: ICMP allow for broker peer is out of band (`fw_rule` / aliases) — note in the example, do not bury inside GIF tools.

### Privilege prerequisite test

- A check or smoke step that fails clearly when `gif_settings/search_item` is 403, so “zero GIFs” is not confused with “empty list”.

## Tool group registration

Update `GROUPS["interface_device"]` description and members, e.g.:

- `list_gif`, `create_gif`, `update_gif`, `delete_gif`
- `assign`
- existing vlan / loopback / `set_address`

Regenerate tool surface golden snapshot in the same change.

## Implementation order

1. Grant API key GIF privileges; capture `get_item` blank + search fixtures.  
2. GIF list/create/update/delete + apply + tests.  
3. `assign` + delete-guard against holders.  
4. Wire into `interface_device`; surface contract.  
5. Document Tunnel Broker example composition + routing follow-up.  
6. Live smoke on lab GIF; teardown.

## Risks

| Risk | Mitigation |
|------|------------|
| 403 until ACL fixed | Explicit error; ops step before claiming done |
| `tunnel-remote-net` default 32 surprises IPv6 users | Document; HE example always passes 64 |
| Assignment write shape differs from blank | Probe under privilege; fixture-driven |
| GIF tunnel addrs vs assigned interface addrs confuse callers | Docs: device carries tunnel endpoints; assignment is enable/policy object |
| Partial multi-step failure | No mega-orchestrator; each step reports `applied` / holders |

## Open items resolved at implementation (not design blockers)

- Exact JSON envelope for `add_item` (`{"gif": {...}}` vs nested `local-addr`).  
- Whether enable-only can be done without a dummy address via SSH/API.  
- Precise OPNsense privilege name string for the runbook.
