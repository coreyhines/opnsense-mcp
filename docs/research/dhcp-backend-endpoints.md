# DHCP Backend API Endpoints (OPNsense)

Scope: lease list/search/delete paths for Kea and dnsmasq, plus low-cost backend detection probes.  
Status: based on OPNsense API docs + OPNsense issue/source snippets + ISC Kea API docs.

## Quick Endpoint Matrix

| Backend | v4 list/search | v4 delete | v6 list/search | v6 delete | Probe (lightweight) |
| --- | --- | --- | --- | --- | --- |
| ISC DHCP (baseline in OPNsense) | `GET /api/dhcpv4/leases/search_lease` | `POST /api/dhcpv4/leases/del_lease/{ip}` | `GET /api/dhcpv6/leases/search_lease` (+ `search_prefix`) | `POST /api/dhcpv6/leases/del_lease/{ip}` | `GET /api/dhcpv4/service/status`, `GET /api/dhcpv6/service/status` |
| Kea (OPNsense) | **Likely** `GET /api/kea/leases4/search` (see uncertainty) | **Unknown/likely present under** `/api/kea/leases4/*` | **Likely** `GET /api/kea/leases6/search` (see uncertainty) | **Unknown/likely present under** `/api/kea/leases6/*` | `GET /api/kea/service/status` |
| dnsmasq (OPNsense) | `GET /api/dnsmasq/leases/search` (supports protocol filtering in controller) | No documented lease-delete endpoint | same endpoint returns both families; filter by protocol | No documented lease-delete endpoint | `GET /api/dnsmasq/service/status` |

## Verified OPNsense Findings

- ISC DHCP endpoints are explicitly documented in OPNsense API docs:
  - `dhcpv4`: `search_lease`, `del_lease`
  - `dhcpv6`: `search_lease`, `search_prefix`, `del_lease`
- dnsmasq exposes lease search via `GET /api/dnsmasq/leases/search`; no `del_lease` endpoint is documented.
- dnsmasq lease search response is recordset-style (from controller code path using `searchRecordsetBase(...)`) and includes an extra `interfaces` map in response.
- Kea docs page currently shows an abstract `leases/search` entry, but OPNsense privilege/routing discussions explicitly reference `/api/kea/leases4/*` (and historically service accounts required explicit ACLs for this path).
- OPNsense route calling convention is snake_case in practice (`search_subnet`, etc.); camelCase is deprecated compatibility behavior.

## Response Shape Notes (Implementation-Oriented)

- OPNsense recordset-style endpoints (ISC/dnsmasq/Kea UI-backed searches) typically return:
  - `rows: [...]`
  - paging/count fields (exact key names may vary by controller base implementation)
  - backend-specific extras (example: dnsmasq adds `interfaces`)
- ISC Kea native control API (baseline semantics used by OPNsense Kea integration) returns control-channel style objects:
  - top-level: `result` (0 success, 1 error, 3 empty, 4 conflict), `text`
  - for list/get-all: `arguments.leases: [...]`
  - for delete: usually only `result` + `text`

Example Kea native payloads:

- list all v4: command `lease4-get-all` -> response `{"arguments":{"leases":[...]},"result":0,"text":"..."}`
- list all v6: command `lease6-get-all` -> same structure, lease objects include `type` (`IA_NA`/`IA_PD`) and may include `prefix-len`
- delete: `lease4-del` / `lease6-del` -> `{"result":<int>,"text":"..."}`

## Recommended Probe Strategy

Use service status first (cheap, explicit daemon-level signal):

- ISC: `GET /api/dhcpv4/service/status`, `GET /api/dhcpv6/service/status`
- Kea: `GET /api/kea/service/status`
- dnsmasq: `GET /api/dnsmasq/service/status`

If status is inconclusive, do one lease search probe with minimal page size/default params and treat:

- HTTP 200 with expected JSON shape as backend-present
- HTTP 403 as privilege issue (not absence)
- HTTP 404 as route unavailable/version mismatch

## Uncertainty / Gaps To Validate In Live Target

- Kea lease endpoints in current docs are inconsistent (`leases/search` abstract vs privilege paths `/api/kea/leases4/*`).
- Exact Kea delete route name in OPNsense API is not explicitly documented in public docs (likely under `/api/kea/leases4/*` and `/api/kea/leases6/*`, but needs live verification or direct controller source lookup in the running OPNsense version).
- Exact pagination field names for each search endpoint should be treated as implementation detail and confirmed against real responses.

## Sources

- OPNsense API docs:  
  - <https://docs.opnsense.org/development/api/core/dhcpv4.html>  
  - <https://docs.opnsense.org/development/api/core/dhcpv6.html>  
  - <https://docs.opnsense.org/development/api/core/dnsmasq.html>  
  - <https://docs.opnsense.org/development/api/core/kea.html>
- OPNsense issue on Kea ACL/routes:  
  - <https://github.com/opnsense/core/issues/7770>
- ISC Kea API/command reference (baseline command/response semantics):  
  - <https://kea.readthedocs.io/en/kea-2.6.0/api.html>  
  - <https://reports.kea.isc.org/dev_guide/d9/dda/libdhcp_lease_cmds.html>
