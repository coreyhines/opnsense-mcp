# WireGuard read and reconcile tools (WG-1)

Date: 2026-08-30
Issue: #39
Status: design, approved for planning

> Addresses, hostnames and instance names in this document are sanitised to the
> conventions in `.site-identifiers.json`. `docs/` is scanned by
> `tests/test_no_site_identifiers.py`, so the real values stay on the firewall.
> Every shape below was captured live from OPNsense 26.7.3_8 during discovery.

## Why

The server has no WireGuard capability at all. Three instances, twelve peer
references and the whole overlay are invisible to it, so working on the VPN
means reading XML by hand. Discovery also found three IPv6 defects on the
tunnel interface that no existing tool could have surfaced, which is the
argument for the reconcile half rather than for reads alone.

This slice is the first of a programme. WG-2 (writes), WG-3 (provisioning),
TS-0 and TS-1 (Tailscale) are separate specs. Nothing here writes to the
firewall.

## What is actually on the box

| instance | device | enabled | tunnel addresses | peers | shape |
|---|---|---|---|---|---|
| `wg0HomeVpn` | wg0 | yes | `192.168.10.1/24`, `fd0b:cafe:f::1/64` | 10 | road warrior |
| `wg1RemoteLabUsers` | wg1 | no | `192.168.11.1` (no prefix length) | 1, dangling | road warrior |
| `wg2SiteToSite` | wg2 | no | `172.20.181.2/24` | 1 | site to site |

Nine of the ten road-warrior peers carry exactly one `/32`. One carries both a
`/32` and a `/128`, and it is the only dual-stack peer on the box. The
site-to-site peer carries four entries of mixed width, one of which is the
remote LAN `192.168.99.0/24` and is correctly outside the tunnel network.

The site-to-site instance is a complete, deliberately disabled worked example:
instance, peer, gateway `wgs2s` on `opt12`, and a static route to the remote
LAN, all disabled together. It is read as a specimen and never modified.

## Non-goals

No writes of any kind. No key generation, no client-config export, no enabling
or disabling anything. No Tailscale. `reconcile` has no apply path, so there is
no write to get wrong in this slice.

## Surface

One new group in `utils/tool_groups.py`, three operations in a new module
`opnsense_mcp/tools/wireguard.py` sharing a `_WgToolBase` in the shape of
`_V6ToolBase`.

| action | tool class | tool name |
|---|---|---|
| `list_instances` | `ListWgInstancesTool` | `list_wg_instances` |
| `list_peers` | `ListWgPeersTool` | `list_wg_peers` |
| `reconcile` | `ReconcileWgTool` | `reconcile_wg` |

Group description: "WireGuard overlay: instances, peers, and drift between the
stored config and the running kernel state."

### Endpoints

```
WG_SERVER  = {"search": "/api/wireguard/server/searchServer",
              "get":    "/api/wireguard/server/getServer"}
WG_CLIENT  = {"search": "/api/wireguard/client/searchClient",
              "get":    "/api/wireguard/client/getClient",
              "info":   "/api/wireguard/client/getServerInfo"}
WG_SERVICE = {"show":   "/api/wireguard/service/show"}
CORE_SERVICE = "/api/core/service/search"
```

`searchServer` and `search_server` are the same route: the action segment
resolves case- and underscore-insensitively. The module and controller segments
do not, and a mis-cased one returns 403 rather than 404. Pick one spelling and
keep it; do not add fallback logic between spellings.

`getServerInfo` is GET-only and answers a POST with `{"status": "failed"}` at
HTTP 200. It is listed here because WG-3 needs it for address allocation; WG-1
does not call it.

## Read rules

These are the rules that produce the tools' behaviour. Each one exists because
discovery found the failure it prevents.

### 1. List from `search`, never from `get`

`dns`, `tunneladdress`, `carp_depend_on` and `peers` are comma-joined strings in
a search row and `{key: {value, selected}}` maps in a get. The other eighteen
fields are identical in both. A normalizer fed the wrong shape therefore returns
four wrong columns and eighteen right ones, and raises nothing. This is the
`source_net` failure in a new place.

`get` is used only to read one record, and only through the `selected == 1`
filter below.

### 2. Membership comes from `selected == 1`, never from the keys

`getServer`'s `peers` map enumerates every peer configured anywhere on the box,
with membership carried only by the flag. Observed: 11 keys / 10 selected on
wg0, 11 / 1 on wg2, 11 / 0 on wg1. `list(get["peers"])` reports every peer as
belonging to every instance. On wg0 that reads plausibly.

An empty list is encoded as one selected node with an empty key,
`{"": {"value": "", "selected": 1}}`, so a length check cannot distinguish empty
from one entry. Drop empty-string keys.

Two different semantics share the node-map syntax. Free-text list fields
(`tunneladdress`, `dns`) use key equal to value. Picker fields (`peers`,
`carp_depend_on`) use the key as the stored value and the value as a human
label: `carp_depend_on` reads `{"": {"value": "None", "selected": 1}}`, where
`None` is display text that must never be written back. One generic flattener
over all four fields corrupts `carp_depend_on`.

### 3. `privkey` and `psk` never leave the tool

Both read paths return the instance private key in cleartext on every row,
unasked, with no extra scope. Peers carry `psk` the same way; peer `privkey` is
present and always empty, because OPNsense holds no peer private key.

Every tool strips both before returning and emits `has_privkey` / `has_psk`
booleans instead. The read path allowlists the fields it emits rather than
denylisting secrets, so a field added upstream is omitted by default.

### 4. `%`-prefixed keys are display only, and conditionally absent

`UIModelGrid` emits `%field` only when the resolved description differs from the
raw value, so the key is absent rather than empty when nothing resolves. On this
firewall `%peers` is missing from exactly the instance a health tool most wants
to report on: wg1, whose only peer uuid resolves to no client.

Access with `.get("%peers", "")`, never branch on key presence, and never derive
membership from a resolved name. Raw lists join on `,`; resolved lists join on
`, `, so a shared `split(",")` leaves a leading space on every name after the
first.

### 5. Branch on the body, not the HTTP code

`getServer` and `getClient` answer an unknown uuid with `[]` at HTTP 200: an
empty array, not an object, not a 404. `getServer` with no uuid at all answers
200 with a fully-formed blank template for a new instance, so a path built by
string concatenation with an empty uuid silently reads a template.

The GET-only endpoints answer a POST with `{"status": "failed"}` at 200.
`_make_request` raises only on `result == "failed"`, so none of these surface as
errors today.

Every read therefore checks `isinstance(payload, dict)` and the presence of its
root key before touching it.

### 6. Omit `rowCount`, then assert `len(rows) == total`

Omitting `rowCount` returns every row, verified on a 179-row grid. `total` only
exceeds the returned rows when `rowCount` is passed explicitly. Asserting
equality turns any future change in that default into a test failure rather than
a silently short list, which is the `_refuse_if_truncated` posture already used
in `ipv6_stack.py`.

### 7. A 200 is not evidence that a filter was applied

Unknown request parameters are accepted and ignored on every grid tested. The
peer filter key is `servers`, and it must be an array: `{"servers": [uuid]}`
filters, `server_uuid` is silently ignored and returns everything, and passing
`servers` as a bare string returns HTTP 500. So the two failure modes are a
silent no-op and a hard 500, with nothing in between.

Any filter the tools promise is verified in the test suite by comparing the
filtered total against the unfiltered total. The tool narrows again on the rows
that come back, because a filter the grid ignored is invisible in a 200, and an
instance name that matches no row is refused: an empty `servers` array is the
idiom for no filter, so sending one asks for every peer on the firewall.

## `list_wg_instances`

No required parameters. Optional `name` or `uuid` to select one.

Per instance: `uuid`, `name`, `enabled`, `instance` index, `interface` device,
`port`, `mtu`, `tunnel_addresses[]`, `dns[]`, `peer_uuids[]`, `peer_names[]`,
`dangling_peers[]`, `gateway`, `disableroutes`, `has_privkey`, `running`, and
`shape`.

`running` comes from `/api/core/service/search`, whose row id embeds the server
uuid, cross-checked against the `service/show` interface row's `status`. It does
not come from `/api/wireguard/service/status`, which returns the literal string
`unknown` while the interface is up and moving traffic, because the plugin
declares no configd status action.

`shape` is `road_warrior`, `site_to_site` or `unknown`, and always ships with
the evidence it was derived from (`disableroutes`, a set `gateway`, peer entries
wider than a host route). It is a label for a human reader and is never used as
a gate anywhere in the code.

`dangling_peers` is the difference between the uuids in the search row's `peers`
and the uuids that `searchClient` actually returns. The three servers reference
twelve peer uuids and eleven peers exist, so this is a live condition, not a
hypothetical.

## `list_wg_peers`

Optional `instance` (uuid or name) and `name`.

Per peer: `uuid`, `name`, `enabled`, `instance_uuids[]`, `instance_names[]`,
`allowed_ips[]`, `keepalive`, `has_psk`, and `runtime`.

`allowed_ips` is read from the field named **`tunneladdress`**. The client model
has no `allowed_ips` key. A field literally named `allowed_ips` exists only on
server rows and is empty on all three, so a normalizer reaching for the obvious
name gets an always-empty column and a green test suite.

`runtime` is the `service/show` peer row, or `null` with a `runtime_absent`
reason. Fields: `handshake_epoch`, `handshake_age`, `endpoint`, `transfer_rx`,
`transfer_tx`, `kernel_allowed_ips[]`, `peer_status_raw`, `connected`.

`connected` is derived from `handshake_epoch != 0`, not from transfer counters.
The eight peers that have never connected all carry non-zero `transfer_tx`
against zero `transfer_rx`, so a `tx > 0 or rx > 0` health check calls every
peer on the box healthy.

`peer_status_raw` is reported but not interpreted. Only `stale` and `offline`
were observed across two samplings forty minutes apart; the third value and its
threshold are unverified, so the enum is not encoded.

`service/show` returns one array holding two row schemas discriminated by
`type`. The interface row carries `peer-status: offline` and a plausible-looking
`name`, so a normalizer that does not branch on `type` first reports the
instance itself as an extra, permanently-offline peer. Interface-only keys are
`fwmark`, `listen-port`, `status`; peer-only keys are `allowed-ips`,
`latest-handshake`, `persistent-keepalive`, `transfer-rx`, `transfer-tx`. The
missing keys are absent, not empty.

`endpoint` means three different things across this API and is never read
without knowing which row holds it: a live `host:port` or the literal `(none)`
on a `service/show` peer row, the listen port on a `service/show` interface row,
and an empty string on every config row.

## `reconcile_wg`

No parameters. Report only. `status` reports whether the audit ran; findings
live in the payload, following the shaper-audit rule that a tool says whether
the operation ran rather than what it found.

Three checks.

### A. Peer address containment

Each `allowed_ips` entry is compared against the tunnel networks of the
instances the peer belongs to.

- A **host route** (`/32`, `/128`) inside its instance network: `current`.
- A **host route outside** it: `drifted`. This is the check that would have
  caught a peer left on a retired delegation.
- A **network entry outside** it: `routed_prefix`, cross-checked against the
  static routes and the gateway, and never reported as drift.

The width distinction is what keeps the site-to-site instance's
`192.168.99.0/24` from being flagged, and it comes from the data rather than
from an exception carved out for one instance.

The comparison is arithmetic on parsed networks, never string prefixes.

### B. Instance address liveness

For each wg device: every address the **kernel** holds is accounted for by the
instance's `tunneladdress` or by the interface assignment, and every
`tunneladdress` entry is present on the device. Both directions.

The predicate is deliberately not "this prefix looks retired". The site's
delegated `/56` is current and live, tracked right now by nine interfaces. A
rule keyed on the prefix would flag nine correctly-configured VLANs while
missing the actual defect, which is an address the kernel holds that no config
accounts for.

Note that the tunnel device is the only interface whose ULA comes from a
WireGuard `tunneladdress` rather than from an ipalias virtual IP, so this check
reads two different config sources depending on the device.

### C. Route cross-check, both directions

Every route on a wg device maps to a kernel allowed-IP or to a connected tunnel
network, and every kernel allowed-IP has a route. Both directions, because
discovery found one defect of each kind on the same interface.

`/api/diagnostics/interface/get_routes` returns a bare top-level array with no
`rows`/`total` wrapper, unlike every WireGuard endpoint, so a shared response
normalizer cannot be used on it. Route destinations omit the prefix length on
host routes, so the implied `/32` or `/128` is supplied by the caller before
comparison.

### Comparing kernel to config

Allowed-IPs compare **as sets**. They match for all ten peers as sets and for
nine of ten as strings, because the kernel emits v6 first while the config
preserves entry order. Nine single-stack peers means a string comparator passes
every fixture built from a typical peer and fails only on the one dual-stack
peer, which is the only one where it matters.

### Outcomes

Per item, following `reconcile_npt`'s vocabulary: `current`, `drifted`, or an
unresolved kind. Unresolved kinds are `instance_disabled`, `no_runtime`,
`dangling_peer`, `unreadable_address`, `no_interface`, `no_prefix_length`.

`no_prefix_length` is the road-warrior instance whose whole tunnel address is
`192.168.11.1`, with no prefix length. Read as a network that is a single /32,
every peer of it is a host route outside its own tunnel, so containment says it
cannot judge the entry rather than reporting drift it has no basis for.

`instance_disabled` matters because absence from the kernel view has two causes.
Disabled instances are absent from `service/show`, from the interface list and
from the route table entirely, with no placeholder, and a disabled instance's
`getServer` returns the same fully-populated tree as an enabled one. Only the
config's `enabled` field distinguishes disabled from broken, so it is read
before any absence is called a fault.

Output carries `checked`, `counts` by outcome, and `results`.

### What this tool cannot tell you

Server-side allowed-IPs are the addresses that belong to a peer, which fixes
routing **to** that peer. The destinations a peer sends through the tunnel live
in that peer's own client configuration, which this API cannot read. The tool
states this in its own output, so a clean report is not mistaken for
end-to-end reachability.

## Tests

The deliverable is the tests, not the tools. Each is verified by reintroducing
the defect and watching it fail.

| test | fails when |
|---|---|
| `test_no_tool_output_contains_a_private_key` | the `privkey`/`psk` strip is removed |
| `test_membership_is_not_taken_from_the_get_node_map` | membership uses map keys instead of `selected == 1` |
| `test_an_empty_node_map_is_not_read_as_one_entry` | the empty-string key is kept |
| `test_a_dangling_peer_uuid_is_reported_not_dropped` | the peer join assumes 1:1 |
| `test_membership_survives_a_missing_resolved_key` | `%peers` is indexed, or used for membership |
| `test_kernel_and_config_allowed_ips_compare_as_sets` | the comparator compares joined strings |
| `test_an_allowed_ip_without_a_route_is_reported` | the route check runs one direction |
| `test_a_route_without_an_allowed_ip_is_reported` | the route check runs the other direction |
| `test_a_site_to_site_network_entry_is_not_drift` | containment ignores prefix width |
| `test_a_disabled_instance_absent_from_the_kernel_is_not_a_fault` | absence is read as breakage |
| `test_a_filter_that_did_not_filter_is_detected` | a 200 is taken as proof the filter applied |
| `test_an_interface_row_is_not_reported_as_a_peer` | `service/show` rows are not split on `type` |
| `test_a_non_dict_payload_is_treated_as_not_found` | `[]` at HTTP 200 is read as a record |
| `test_a_truncated_listing_is_refused_not_returned` | `len(rows) == total` is not asserted |
| `test_every_normalized_instance_has_a_non_empty_tunnel_address` | a normalizer returns empty for every row |
| `test_no_wireguard_key_material_in_fixtures` | a 44-character base64 key is committed |

The last one is new coverage for the whole repository, not just this module.
`test_no_site_identifiers.py` matches addresses and hostnames, so nothing today
would catch a committed private key.

The existing repository-wide checks apply unchanged and are part of the
acceptance criteria: `test_guidance_names_are_real.py`,
`test_schema_completeness.py`, `test_surface_consistency.py`,
`test_fixture_shapes.py`, `test_shape_check.py`, and the grouped-tool collision
check.

## Fixtures

Captured from 26.7.3 into `tests/fixtures/opnsense-26.7.3/`:

| file | why it exists |
|---|---|
| `wg_searchserver_rows.json` | the flat server shape, three instances, two distinct key sets |
| `wg_getserver_dangling.json` | search and get disagreeing about the same instance |
| `wg_searchclient_rows.json` | eleven peers, ten host routes and one site-to-site set |
| `wg_service_show_rows.json` | both row types, the dual-stack peer's reordered allowed-IPs |
| `wg_get_routes_wg0.json` | the bare-array route shape, including both route defects |

Two prerequisites before any of these land.

1. The sanitiser has no rule for the site's current ULA prefix. Its existing ULA
   rule predates the migration and does not match, so a captured fixture would
   reach `test_no_site_identifiers.py` unsanitised. Add the rule first. The RFC
   1918 range this site addresses in is also deliberately not allow-listed by
   that test, so peer endpoints and the wg1 resolver need rewriting too.
2. Private keys are replaced with a placeholder of the same length, so the shape
   stays honest while the secret does not exist in the repository.

Shape tests take the union of keys across rows and record which are conditional.
Sampling `rows[0]` is not enough: the server grid has two distinct key sets
across three rows because of `%peers`.

## Known defects this slice does not fix

Recorded here so they are not rediscovered, and filed separately.

- `run_apply` cannot accept a WireGuard apply. The plugin's
  `reconfigureAction` overrides the base and returns `{"result": "ok"}` where
  `run_apply` reads `{"status": ...}`, so a successful apply would report as a
  failure. The repository half is confirmed; the response shape is read from
  source and needs one supervised write to verify. WG-1 makes no apply call, so
  this blocks WG-2 rather than this slice.
- Three IPv6 defects sit on the tunnel interface, all found by discovery: an
  orphaned address and connected route from the current delegation that no
  config accounts for, a host route from a genuinely previous delegation for a
  peer address no client record contains, and a missing host route for the one
  live dual-stack peer. `reconcile_wg` is designed to report all three; fixing
  them is operations, not code.
- Peer membership is written through the client model rather than the server.
  The client controller walks every server node and edits its `peers` list, so
  a write that posts `server.peers` directly fights it. This constrains
  WG-2 and is recorded now because it is not visible from a read.
