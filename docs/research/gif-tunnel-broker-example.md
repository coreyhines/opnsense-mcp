# GIF tunnel broker — composition example

**Date:** 2026-09-13  
**Scope:** Document how to stand up a tunnel-broker-style GIF using existing MCP tools. No broker-specific parameters; compose `interface_device`, `routing`, and `diagnostics` actions yourself.

**Related:** [GIF end-to-end design](gif-interface-end-to-end-design.md), [GIF API privilege prerequisite](gif-api-privilege.md)

## What this is not

There is no `configure_gif` orchestrator. Each step reports its own `status`, `applied`, and errors. Partial failure stays visible so you can stop or roll back deliberately.

## Lab addresses only

Examples below use documentation ranges (RFC 5737, RFC 3849). Replace with values your broker assigns before applying on a live firewall.

| Role | Example value |
|------|----------------|
| Parent interface | `wan` (your WAN interface identifier) |
| Outer remote peer | `198.51.100.1` |
| Inner local (client) | `2001:db8:1000::2` |
| Inner remote (broker) | `2001:db8:1000::1` |
| Assigned interface address | `2001:db8:1000::2/64` |
| Default gateway next hop | `2001:db8:1000::1` |

## Prerequisites

### 1. API privilege for GIF CRUD

`interface_device` GIF actions call `/api/interfaces/gif_settings/*`. Without **Interfaces → Devices → GIF** on the MCP API key, `create_gif` / `list_gif` / `delete_gif` return `status: error` with an explicit privilege message — not an empty list.

See [gif-api-privilege.md](gif-api-privilege.md) for the fix and a curl check.

Assignment endpoints may work before GIF privilege is granted; that is not enough to create the tunnel device.

### 2. ICMP to the broker peer (out of band)

Many brokers require the outer tunnel endpoint to respond to ping before the tunnel comes up. Allow that in firewall policy separately, for example:

- `fw_rule(action=create, ...)` on the WAN interface, or
- an alias covering the broker's outer addresses, referenced from a pass rule.

Do not bury ICMP policy inside GIF tools; it is operator policy, not part of device creation.

### 3. SSH for `set_address`

`set_address` uses the existing SSH path because the 26.7 assignment API has no address fields. Ensure MCP SSH credentials are configured when enable/static addressing is required.

## Important defaults

| Field | Firmware default | IPv6 broker note |
|-------|------------------|------------------|
| `tunnel_remote_net` | **32** | Pass **64** for typical IPv6 `/64` point-to-point broker tunnels |

Tunnel endpoints (`tunnel_local`, `tunnel_remote`) live on the **GIF device**. The **assignment** (`optN`) is the interface object for enable, policy, and routing. When the assigned interface must be enabled or carry a static address beyond what the GIF device fields provide, use `set_address` after `assign`.

## Workflow (dry-run then apply)

Run each write with `apply=false` first, inspect the response, then repeat with `apply=true`.

### Step 1 — Create the GIF device

```
interface_device(
  action=create_gif,
  parent=wan,
  remote=198.51.100.1,
  tunnel_local=2001:db8:1000::2,
  tunnel_remote=2001:db8:1000::1,
  tunnel_remote_net=64,
  description=Lab tunnel broker GIF,
  apply=false
)
```

Then `apply=true` once the staged payload looks correct.

Idempotency: if the same parent + outer remote + inner endpoints already exist, the tool reuses the row (`created: false`) instead of recreating it.

Capture `device` (for example `gif0`) and `uuid` from the response.

### Step 2 — Assign the device to an interface id

```
interface_device(
  action=assign,
  device=gif0,
  description=Lab tunnel broker,
  apply=false
)
```

Then `apply=true`. Capture `identifier` (for example `opt12`).

If `device` is not yet assignable, `create_gif` may need `apply=true` first so the kernel instantiates `gif0`.

### Step 3 — Enable and set the interface address (when needed)

Broker inner endpoints are on the GIF device, but the assigned interface may still be disabled or lack the address routing expects. Use SSH-backed addressing:

```
interface_device(
  action=set_address,
  interface=opt12,
  address=2001:db8:1000::2,
  subnet_bits=64,
  reason=Lab tunnel broker enable
)
```

Success is confirmed by ifconfig read-back, not by HTTP 200 alone.

### Step 4 — Gateway and routes (existing `routing` tools)

GIF tools do not invent a default gateway. Create one on the assigned interface when the broker expects IPv6 transit through the inner remote:

```
routing(
  action=create_gateway,
  name=LAB_TUNNEL6,
  interface=opt12,
  gateway=2001:db8:1000::1,
  ipprotocol=inet6,
  far_gateway=true,
  monitor_disable=true,
  apply=true
)
```

Add static routes with `routing(action=create_route, ...)` when your design needs prefixes beyond default routing. Use `routing(action=list_gateways)` and `routing(action=gateway_status)` to confirm monitoring state.

### Step 5 — Verify

Re-read configuration; do not trust a single write response.

```
interface_device(action=list_gif)
diagnostics(action=interfaces)
diagnostics(action=interface_health, interface=opt12)
routing(action=list_gateways)
```

Reachability from the firewall:

```
diagnostics(
  action=ping,
  target=2001:db8:1000::1,
  family=inet6,
  source_address=2001:db8:1000::2,
  count=3
)
```

Ping the broker's routed IPv6 test target (documentation range or broker-assigned) once the gateway is up.

## Teardown (reverse order)

`delete_gif` refuses while the device is still assigned. Unassign first.

### Unassign (no MCP action in v1)

There is no `interface_device(action=unassign)` yet. Remove the assignment row before deleting the GIF:

1. **UI:** Interfaces → Assignments → delete the row bound to `gif0`.
2. **API:** `POST /api/interfaces/assignment/del_item/{uuid}` where `uuid` comes from `GET /api/interfaces/assignment/search_item` for the row whose `if` equals `gif0`.

Re-read assignment search and confirm no row still references `gif0`.

### Delete the GIF device

Two-step confirm, same pattern as other destructive tools:

```
interface_device(action=delete_gif, uuid=<uuid>)
```

Returns `confirmation_required` and a token. Then:

```
interface_device(
  action=delete_gif,
  uuid=<uuid>,
  confirm=<token>,
  apply=true
)
```

### Optional cleanup

Remove the lab gateway and any static routes with `routing(action=delete_gateway, ...)` and `routing(action=delete_route, ...)`. Revert any temporary ICMP pass rule added in prerequisites.

## Failure modes (quick reference)

| Symptom | Likely cause |
|---------|----------------|
| 403 on `create_gif` | Missing GIF API privilege — see prerequisite doc |
| `device not assignable` | GIF not applied yet, or wrong device name |
| `delete_gif` refused | Assignment still holds `gif0` — unassign first |
| Ping fails, tunnel exists | ICMP blocked on WAN, wrong inner addresses, or gateway not created |
| `tunnel_remote_net=32` on IPv6 | Default 32 used; pass **64** for broker-style `/64` tunnels |
