# DHCP Multi-Backend Support Design

## Problem

The OPNsense MCP server currently hardcodes ISC DHCP endpoints for lease management. OPNsense supports three DHCP backends — ISC, dnsmasq, and Kea — and is moving toward Kea as the default. We need to support all three transparently.

## Requirements

- Support ISC, dnsmasq, and Kea DHCP backends for both IPv4 and IPv6
- Full parity across backends: lease listing, searching, and deletion
- Auto-detect which backend is active by probing OPNsense API endpoints
- Lazy detection on first DHCP call, cached for process lifetime
- Existing tools (`DHCPTool`, `DHCPLeaseDeleteTool`) remain unchanged or minimally changed
- No new environment variables required (auto-detect only)

## Architecture: Hybrid Provider Pattern

### Approach

- Define a `DHCPProvider` Protocol for the contract all backends implement
- Each backend is a standalone provider class in its own file
- The `OPNsenseClient` owns detection and instantiation, delegating DHCP methods to the detected provider
- Tools continue calling the same client methods they use today

### File Layout

```
utils/
├── dhcp_provider.py          # Protocol definition + detect_dhcp_backend()
└── dhcp_providers/
    ├── __init__.py            # Re-exports provider classes
    ├── isc.py                 # ISCProvider
    ├── dnsmasq.py             # DnsmasqProvider
    └── kea.py                 # KeaProvider
```

### DHCPProvider Protocol

```python
class DHCPProvider(Protocol):
    name: str  # "isc", "dnsmasq", "kea"

    async def get_v4_leases(self) -> list[dict[str, Any]]: ...
    async def get_v6_leases(self) -> list[dict[str, Any]]: ...
    async def search_v4_leases(self, query: str) -> list[dict[str, Any]]: ...
    async def search_v6_leases(self, query: str) -> list[dict[str, Any]]: ...
    async def delete_v4_lease(self, ip: str) -> dict[str, Any]: ...
    async def delete_v6_lease(self, ip: str) -> dict[str, Any]: ...
```

### Provider Implementations

Each provider class:
- Accepts a `make_request` callable with signature `async (method: str, endpoint: str, **kwargs) -> dict | list` (the same signature as `OPNsenseClient._make_request`, but passed in to avoid coupling to the full client)
- Knows its own endpoint paths for v4/v6 lease listing, searching, and deletion
- Handles its own response parsing (ISC returns `rows`/`leases`, Kea and dnsmasq may differ)

**ISCProvider** is a direct refactor of the current hardcoded logic:
- List: `GET /api/dhcpv4/leases/search_lease`, `GET /api/dhcpv6/leases/search_lease`
- Search: `POST /api/dhcpv4/leases/search_lease` with `{"searchPhrase": query}`
- Delete: `POST /api/dhcpv4/leases/del_lease/{ip}`, `POST /api/dhcpv6/leases/del_lease/{ip}`

**DnsmasqProvider** and **KeaProvider** endpoints require research against the OPNsense API documentation. Each implementation agent will be responsible for discovering and verifying the correct endpoints and response shapes.

### Detection Logic

`detect_dhcp_backend(make_request)` in `dhcp_provider.py`:

1. Probe **Kea** endpoint first (OPNsense's future direction)
2. Probe **dnsmasq** endpoint second
3. Probe **ISC** endpoint third
4. If all probes fail, fall back to ISC and log a warning

The probe order prioritizes Kea because OPNsense is moving in that direction. A successful probe means the endpoint returned a non-error response.

### API Client Changes

In `OPNsenseClient` (`utils/api.py`):

**Remove:**
- `self.dhcpv4_lease_endpoint` attribute
- `self.dhcpv6_lease_endpoint` attribute
- Inline DHCP lease fetching/searching/parsing logic from the four existing methods

**Add:**
- `self._dhcp_provider: DHCPProvider | None = None`
- `async _ensure_dhcp_provider(self)` — lazy detection + caching

**Modify** existing public methods to delegate:

```python
async def get_dhcpv4_leases(self) -> list[dict[str, Any]]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.get_v4_leases()

async def get_dhcpv6_leases(self) -> list[dict[str, Any]]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.get_v6_leases()

async def search_dhcpv4_leases(self, query: str) -> list[dict[str, Any]]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.search_v4_leases(query)

async def search_dhcpv6_leases(self, query: str) -> list[dict[str, Any]]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.search_v6_leases(query)
```

**Add** new public methods for deletion:

```python
async def delete_dhcpv4_lease(self, ip: str) -> dict[str, Any]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.delete_v4_lease(ip)

async def delete_dhcpv6_lease(self, ip: str) -> dict[str, Any]:
    await self._ensure_dhcp_provider()
    return await self._dhcp_provider.delete_v6_lease(ip)
```

### Tool Changes

**`DHCPTool`** — zero changes. It already calls `client.get_dhcpv4_leases()` etc.

**`DHCPLeaseDeleteTool`** — minimal change. Replace direct `_make_request` calls:

```python
# Before:
response = await self.client._make_request("POST", f"/api/dhcpv4/leases/del_lease/{lease_ip}")

# After:
response = await self.client.delete_dhcpv4_lease(lease_ip)
```

Same pattern for IPv6 deletion.

## Testing Strategy

### Provider Unit Tests (`tests/test_dhcp_providers/`)

One test file per backend (`test_isc.py`, `test_dnsmasq.py`, `test_kea.py`):
- Mock `_make_request` at the provider level
- Verify correct endpoint paths for v4 and v6
- Verify response parsing for each backend's response shape
- Verify search passes correct parameters
- Verify delete calls correct endpoint
- Verify error handling (endpoint errors, unexpected response shapes)

### Detection Tests (`tests/test_dhcp_detection.py`)

- Kea selected when Kea probe succeeds
- dnsmasq selected when Kea fails but dnsmasq succeeds
- ISC selected when both Kea and dnsmasq fail
- ISC fallback with warning log when all probes fail
- Caching: detection runs once, second call reuses provider

### Integration Tests

Update existing `test_dhcp_tool.py` and `test_dhcp_lease_delete.py`:
- Mock at the provider level instead of raw endpoint level
- Verify tools work through the new delegation path
- Verify delete tool uses new public methods

## Implementation Notes

- ISCProvider is a safe refactor of existing working code — start here as the baseline
- DnsmasqProvider and KeaProvider require API endpoint research as a prerequisite
- Each provider can be built and tested independently by parallel agents
- The detection function and API client wiring depend on all providers being available
