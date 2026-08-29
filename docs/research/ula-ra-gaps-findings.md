# Wave 0 spike results — ula-ra-gaps

Date: 2026-08-28. Read-only against OPNsense 26.7.3_8. Both spikes answered.

## S1 — the dnsmasq range object

`GET /api/dnsmasq/settings/get_range/<uuid>` on the VLAN10 v6 range returns 18 fields:

```
constructor  description  domain      domain_type  end_addr   interface
lease_time   mode         nosync      prefix_len   ra_interval
ra_mode      ra_mtu       ra_priority ra_router_lifetime
set_tag      start_addr   subnet_mask
```

Same set as `search_range` minus the `%`-prefixed display fields and `uuid`. Four are MVC
selects, not scalars, so a writer has to flatten them:

| Field | Options | Current |
|---|---|---|
| `ra_mode` | `ra-only`, `slaac`, `ra-names`, `ra-stateless`, `ra-advrouter`, `off-link` | `slaac` |
| `ra_priority` | `` (Normal), `high`, `low` | Normal |
| `constructor` | 14 interfaces | `opt13` |
| `domain_type` | `interface`, `range` | `range` |

### There is no preferred-lifetime field

The only lifetime is `ra_router_lifetime`, which is the router's own lifetime, not a prefix's.
Nothing in the model expresses the advertised prefix's preferred lifetime.

This closes the open question in issue #27 with a negative answer, and it costs the migration
its phase-3 lever. Advertising the delegated prefix with preferred-lifetime 0 so clients drain
off it gracefully is **not** reachable through this API. What remains:

- drop track6 from the interface, so dnsmasq stops advertising the prefix outright (this is
  phase 4, without the graceful phase 3 in front of it);
- or shorten the range `lease_time`, since dnsmasq derives advertised lifetimes from it in
  SLAAC mode — an indirect lever, unverified here;
- or do phase 3 in the UI.

B4 can still route RA writes to the serving daemon and verify applied state. It cannot deliver
a deprecate action, and should not claim one.

## S2 — track-interface with a chosen prefix-id

Not expressible through the API. Probed every read model under `/api/interfaces/`:

| Endpoint | Returns |
|---|---|
| `loopback_settings/get` | `{"loopback": {"loopback": []}}` — a device list, no addressing fields |
| `settings/get` | global IPv6/offload toggles (`dhcp6_duid`, `disableipv6`, offload flags) |
| `overview/interfacesInfo` | read-only status rows |
| `vip_settings/get`, `vlan_settings/get` | VIP and VLAN models, neither carries interface addressing |

There is no MVC model for per-interface IP configuration anywhere in `/api/interfaces/`, so
`ipaddrv6=track6` with `track6-interface` and `track6-prefix-id` cannot be written over the
API. It lives in `config.xml` and is reachable by UI or config edit only. This is the same
assignment hole that sent `set_interface_address` down the SSH path.

**B5 takes branch (b) of issue #28**: document the supported PD-holder shape and refuse the
unsupported one with a recorded reason. No implementation. The spec's standing rule applies
here rather than an SSH workaround: *"Only if G0/G2 fail; then say UI. No silent ifconfig."*

## Consequences for the plan

| Bucket | Change |
|---|---|
| B1 | Unchanged, and confirmed: `get_range` carries `constructor` and four selects that `_flat_range_payload` drops. |
| B4 | Narrows. Routing, verification and the both-daemons guard stay. The deprecate action is dropped as unimplementable. |
| B5 | Narrows to document-and-refuse, as its brief anticipated. |
| #27 | Its open question is answered; the answer removes a capability the issue implied was reachable. |

## What shipped

- **B1**: `_flat_range_payload` replaced with get-and-merge, so toggling a v6 range no longer blanks `constructor`; `list_ranges` returns the `ra_*` fields; create/update accept and validate them.
- **B3**: `opnsense_mcp/utils/ra_daemon.py`, a pure classifier returning per-interface verdicts of `dnsmasq` / `radvd` / `both` / `none` with reason codes.
- **B4**: RA writes consult the verdict and refuse when the wrong daemon would be written; `apply_ula` verifies after reconfiguring; a deprecate request is refused by name.
- **B5**: track-interface addressing refused with the manual steps, since no API expresses it.

Phase 3 (graceful deprecate) remains unavailable. The dnsmasq range model has no preferred-lifetime field, so advertising the delegated prefix with preferred-lifetime 0 so clients drain off it is not reachable through this API. It is reachable only by a UI action or a `config.xml` edit, neither of which a tool can perform without the same SSH workaround this project has already ruled out for interface addressing.
