# DHCP Multi-Backend Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support ISC, dnsmasq, and Kea DHCP backends transparently with auto-detection, for both IPv4 and IPv6 lease operations (list, search, delete).

**Architecture:** A `DHCPProvider` Protocol defines the contract. Three provider classes (ISC, dnsmasq, Kea) implement it. The `OPNsenseClient` lazily detects the active backend on first DHCP call and delegates all DHCP operations to the detected provider. Existing tools require zero or minimal changes.

**Tech Stack:** Python 3.12+, typing.Protocol, asyncio, requests, pytest, ruff

**Spec:** `docs/superpowers/specs/2026-03-26-dhcp-multi-backend-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `opnsense_mcp/utils/dhcp_provider.py` | `DHCPProvider` Protocol + `detect_dhcp_backend()` |
| Create | `opnsense_mcp/utils/dhcp_providers/__init__.py` | Re-exports `ISCProvider`, `DnsmasqProvider`, `KeaProvider` |
| Create | `opnsense_mcp/utils/dhcp_providers/isc.py` | ISC DHCP provider (refactor of current logic) |
| Create | `opnsense_mcp/utils/dhcp_providers/dnsmasq.py` | dnsmasq DHCP provider |
| Create | `opnsense_mcp/utils/dhcp_providers/kea.py` | Kea DHCP provider |
| Modify | `opnsense_mcp/utils/api.py:122-127,719-785` | Remove hardcoded DHCP endpoints/methods, delegate to provider |
| Modify | `opnsense_mcp/tools/dhcp_lease_delete.py:154-156,178-180` | Use new `delete_dhcpv4_lease`/`delete_dhcpv6_lease` public methods |
| Create | `tests/test_dhcp_providers/__init__.py` | Test package |
| Create | `tests/test_dhcp_providers/test_isc.py` | ISC provider unit tests |
| Create | `tests/test_dhcp_providers/test_dnsmasq.py` | dnsmasq provider unit tests |
| Create | `tests/test_dhcp_providers/test_kea.py` | Kea provider unit tests |
| Create | `tests/test_dhcp_detection.py` | Detection logic tests |
| Modify | `tests/test_dhcp_lease_delete.py` | Update mocks for new delegation path |

---

### Task 1: Research dnsmasq and Kea OPNsense API Endpoints

This task is a prerequisite for Tasks 4 and 5. The agent must discover the correct API endpoints and response shapes for dnsmasq and Kea DHCP backends in OPNsense.

**Research sources:**
- OPNsense API docs: https://docs.opnsense.org/development/api.html
- OPNsense source code on GitHub (opnsense/core and opnsense/plugins repos)
- Search for `dnsmasq` and `kea` DHCP controller/API definitions

**Deliverables:** A markdown file at `docs/research/dhcp-backend-endpoints.md` containing:

- [ ] **Step 1: Research Kea DHCP endpoints**

Search the OPNsense API documentation and source code for Kea DHCP4 and DHCP6 endpoints. Document:
- Lease list endpoint (v4 and v6)
- Lease search endpoint and request format (v4 and v6)
- Lease delete endpoint and request format (v4 and v6)
- Response shape for each (JSON key names: `rows`, `leases`, etc.)

- [ ] **Step 2: Research dnsmasq DHCP endpoints**

Same as Step 1 but for dnsmasq. Note: dnsmasq in OPNsense may use a different plugin (`os-dnsmasq-dhcp` or similar). Document the same endpoint details.

- [ ] **Step 3: Identify detection probe endpoints**

For each backend, identify a lightweight endpoint that reliably indicates the backend is installed and active. This could be a service status endpoint or a lease list endpoint that returns 200 when the backend is active and 404 when it's not.

- [ ] **Step 4: Write findings to research file**

Create `docs/research/dhcp-backend-endpoints.md` with structured findings:

```markdown
# DHCP Backend API Endpoints

## ISC (confirmed from current codebase)
- List v4: GET /api/dhcpv4/leases/search_lease
- List v6: GET /api/dhcpv6/leases/search_lease
- Search v4: POST /api/dhcpv4/leases/search_lease {"searchPhrase": "query", "current": 1, "rowCount": -1}
- Search v6: POST /api/dhcpv6/leases/search_lease (same format)
- Delete v4: POST /api/dhcpv4/leases/del_lease/{ip}
- Delete v6: POST /api/dhcpv6/leases/del_lease/{ip}
- Response keys: "rows" or "leases"
- Detection probe: GET /api/dhcpv4/leases/search_lease

## Kea
- List v4: [discovered endpoint]
- ...

## dnsmasq
- List v4: [discovered endpoint]
- ...
```

- [ ] **Step 5: Commit research**

```bash
git add docs/research/dhcp-backend-endpoints.md
git commit -m "docs: research dnsmasq and Kea DHCP API endpoints"
```

---

### Task 2: Create DHCPProvider Protocol and Package Structure

**Files:**
- Create: `opnsense_mcp/utils/dhcp_provider.py`
- Create: `opnsense_mcp/utils/dhcp_providers/__init__.py`

- [ ] **Step 1: Create the dhcp_providers package directory**

```bash
mkdir -p opnsense_mcp/utils/dhcp_providers
```

- [ ] **Step 2: Write the DHCPProvider Protocol**

Create `opnsense_mcp/utils/dhcp_provider.py`:

```python
"""DHCP provider protocol and backend detection for OPNsense."""

import logging
from typing import Any, Callable, Coroutine, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


MakeRequestFn = Callable[
    ...,
    Coroutine[Any, Any, dict[str, Any] | list[Any]],
]
"""Signature: async (method, endpoint, **kwargs) -> dict | list.

Matches OPNsenseClient._make_request without coupling to the class.
"""


@runtime_checkable
class DHCPProvider(Protocol):
    """Contract that every DHCP backend must satisfy."""

    name: str

    async def get_v4_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv4 leases."""
        ...

    async def get_v6_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv6 leases."""
        ...

    async def search_v4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases by hostname, IP, or MAC."""
        ...

    async def search_v6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases by hostname, IP, or MAC."""
        ...

    async def delete_v4_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv4 lease by IP address."""
        ...

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""
        ...
```

- [ ] **Step 3: Write the empty __init__.py for the providers package**

Create `opnsense_mcp/utils/dhcp_providers/__init__.py`:

```python
"""DHCP backend provider implementations."""
```

This will be updated with re-exports as each provider is built.

- [ ] **Step 4: Verify imports work**

Run: `cd /Users/corey/vs-code/opnsense-mcp && uv run python -c "from opnsense_mcp.utils.dhcp_provider import DHCPProvider; print('OK')"`

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add opnsense_mcp/utils/dhcp_provider.py opnsense_mcp/utils/dhcp_providers/__init__.py
git commit -m "feat: add DHCPProvider protocol and providers package"
```

---

### Task 3: Implement ISCProvider (Refactor of Current Logic)

**Files:**
- Create: `opnsense_mcp/utils/dhcp_providers/isc.py`
- Create: `tests/test_dhcp_providers/__init__.py`
- Create: `tests/test_dhcp_providers/test_isc.py`

This is a direct extraction of the existing DHCP logic from `api.py` into a provider class. No new behavior — just restructuring.

- [ ] **Step 1: Write the failing tests for ISCProvider**

Create `tests/test_dhcp_providers/__init__.py` (empty file).

Create `tests/test_dhcp_providers/test_isc.py`:

```python
"""Tests for ISC DHCP provider."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create a mock make_request callable."""
    return AsyncMock()


@pytest.fixture
def provider(make_request: AsyncMock) -> ISCProvider:
    """Create an ISCProvider with mocked request function."""
    return ISCProvider(make_request)


class TestISCProviderName:
    def test_name_is_isc(self, provider: ISCProvider) -> None:
        assert provider.name == "isc"


class TestGetV4Leases:
    @pytest.mark.asyncio
    async def test_returns_leases_from_rows_key(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"rows": [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]}
        result = await provider.get_v4_leases()
        assert result == [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        make_request.assert_called_once_with("GET", "/api/dhcpv4/leases/search_lease")

    @pytest.mark.asyncio
    async def test_returns_leases_from_leases_key(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"leases": [{"ip": "10.0.0.2"}]}
        result = await provider.get_v4_leases()
        assert result == [{"ip": "10.0.0.2"}]

    @pytest.mark.asyncio
    async def test_returns_list_response_directly(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = [{"ip": "10.0.0.3"}]
        result = await provider.get_v4_leases()
        assert result == [{"ip": "10.0.0.3"}]

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.side_effect = Exception("connection error")
        result = await provider.get_v4_leases()
        assert result == []


class TestGetV6Leases:
    @pytest.mark.asyncio
    async def test_returns_leases_from_rows_key(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"rows": [{"ip": "2001:db8::1"}]}
        result = await provider.get_v6_leases()
        assert result == [{"ip": "2001:db8::1"}]
        make_request.assert_called_once_with("GET", "/api/dhcpv6/leases/search_lease")

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.side_effect = Exception("timeout")
        result = await provider.get_v6_leases()
        assert result == []


class TestSearchV4Leases:
    @pytest.mark.asyncio
    async def test_posts_search_phrase(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"rows": [{"ip": "10.0.0.5", "hostname": "test"}]}
        result = await provider.search_v4_leases("test")
        assert result == [{"ip": "10.0.0.5", "hostname": "test"}]
        make_request.assert_called_once_with(
            "POST",
            "/api/dhcpv4/leases/search_lease",
            json={"searchPhrase": "test", "current": 1, "rowCount": -1},
        )

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.side_effect = Exception("error")
        result = await provider.search_v4_leases("test")
        assert result == []


class TestSearchV6Leases:
    @pytest.mark.asyncio
    async def test_posts_search_phrase(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"rows": [{"ip": "2001:db8::5"}]}
        result = await provider.search_v6_leases("test")
        assert result == [{"ip": "2001:db8::5"}]
        make_request.assert_called_once_with(
            "POST",
            "/api/dhcpv6/leases/search_lease",
            json={"searchPhrase": "test", "current": 1, "rowCount": -1},
        )


class TestDeleteV4Lease:
    @pytest.mark.asyncio
    async def test_deletes_by_ip(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"status": "ok"}
        result = await provider.delete_v4_lease("10.0.0.1")
        assert result == {"status": "ok"}
        make_request.assert_called_once_with(
            "POST", "/api/dhcpv4/leases/del_lease/10.0.0.1"
        )

    @pytest.mark.asyncio
    async def test_returns_error_on_exception(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.side_effect = Exception("fail")
        result = await provider.delete_v4_lease("10.0.0.1")
        assert result["status"] == "error"
        assert "fail" in result["error"]


class TestDeleteV6Lease:
    @pytest.mark.asyncio
    async def test_deletes_by_ip(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.return_value = {"status": "ok"}
        result = await provider.delete_v6_lease("2001:db8::1")
        assert result == {"status": "ok"}
        make_request.assert_called_once_with(
            "POST", "/api/dhcpv6/leases/del_lease/2001:db8::1"
        )

    @pytest.mark.asyncio
    async def test_returns_error_on_exception(
        self, provider: ISCProvider, make_request: AsyncMock
    ) -> None:
        make_request.side_effect = Exception("fail")
        result = await provider.delete_v6_lease("2001:db8::1")
        assert result["status"] == "error"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_dhcp_providers/test_isc.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'opnsense_mcp.utils.dhcp_providers.isc'`

- [ ] **Step 3: Implement ISCProvider**

Create `opnsense_mcp/utils/dhcp_providers/isc.py`:

```python
"""ISC DHCP provider for OPNsense."""

import logging
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# Type alias for the make_request callable
MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]


class ISCProvider:
    """DHCP provider for the ISC DHCP backend.

    Uses the /api/dhcpv4/ and /api/dhcpv6/ endpoint families.
    """

    name: str = "isc"

    V4_LEASE_ENDPOINT = "/api/dhcpv4/leases/search_lease"
    V6_LEASE_ENDPOINT = "/api/dhcpv6/leases/search_lease"
    V4_DELETE_ENDPOINT = "/api/dhcpv4/leases/del_lease"
    V6_DELETE_ENDPOINT = "/api/dhcpv6/leases/del_lease"

    def __init__(self, make_request: MakeRequestFn) -> None:
        """Initialize with a make_request callable from OPNsenseClient.

        Args:
            make_request: Async callable matching OPNsenseClient._make_request signature.
        """
        self._request = make_request

    def _extract_leases(self, response: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
        """Extract lease list from an API response.

        ISC endpoints return either {"rows": [...]}, {"leases": [...]}, or a bare list.
        """
        if isinstance(response, dict):
            if "leases" in response:
                return response["leases"]
            if "rows" in response:
                return response["rows"]
        return response if isinstance(response, list) else []

    async def get_v4_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv4 leases."""
        try:
            response = await self._request("GET", self.V4_LEASE_ENDPOINT)
            return self._extract_leases(response)
        except Exception:
            logger.exception("ISC: failed to get DHCPv4 leases")
            return []

    async def get_v6_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv6 leases."""
        try:
            response = await self._request("GET", self.V6_LEASE_ENDPOINT)
            return self._extract_leases(response)
        except Exception:
            logger.exception("ISC: failed to get DHCPv6 leases")
            return []

    async def search_v4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases by hostname, IP, or MAC."""
        try:
            response = await self._request(
                "POST",
                self.V4_LEASE_ENDPOINT,
                json={"searchPhrase": query, "current": 1, "rowCount": -1},
            )
            return self._extract_leases(response)
        except Exception:
            logger.exception("ISC: failed to search DHCPv4 leases")
            return []

    async def search_v6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases by hostname, IP, or MAC."""
        try:
            response = await self._request(
                "POST",
                self.V6_LEASE_ENDPOINT,
                json={"searchPhrase": query, "current": 1, "rowCount": -1},
            )
            return self._extract_leases(response)
        except Exception:
            logger.exception("ISC: failed to search DHCPv6 leases")
            return []

    async def delete_v4_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv4 lease by IP address."""
        try:
            response = await self._request("POST", f"{self.V4_DELETE_ENDPOINT}/{ip}")
            return response if isinstance(response, dict) else {"status": "ok"}
        except Exception as e:
            logger.exception("ISC: failed to delete DHCPv4 lease %s", ip)
            return {"status": "error", "error": str(e)}

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""
        try:
            response = await self._request("POST", f"{self.V6_DELETE_ENDPOINT}/{ip}")
            return response if isinstance(response, dict) else {"status": "ok"}
        except Exception as e:
            logger.exception("ISC: failed to delete DHCPv6 lease %s", ip)
            return {"status": "error", "error": str(e)}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_dhcp_providers/test_isc.py -v`

Expected: All tests PASS

- [ ] **Step 5: Update dhcp_providers/__init__.py re-export**

Update `opnsense_mcp/utils/dhcp_providers/__init__.py`:

```python
"""DHCP backend provider implementations."""

from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider

__all__ = ["ISCProvider"]
```

- [ ] **Step 6: Lint**

Run: `uv run ruff check opnsense_mcp/utils/dhcp_providers/ opnsense_mcp/utils/dhcp_provider.py && uv run ruff format opnsense_mcp/utils/dhcp_providers/ opnsense_mcp/utils/dhcp_provider.py`

Fix any issues.

- [ ] **Step 7: Commit**

```bash
git add opnsense_mcp/utils/dhcp_providers/isc.py opnsense_mcp/utils/dhcp_providers/__init__.py tests/test_dhcp_providers/__init__.py tests/test_dhcp_providers/test_isc.py
git commit -m "feat: implement ISCProvider with tests"
```

---

### Task 4: Implement KeaProvider

**Files:**
- Create: `opnsense_mcp/utils/dhcp_providers/kea.py`
- Create: `tests/test_dhcp_providers/test_kea.py`

**Prerequisite:** Task 1 (endpoint research). Use the discovered endpoints from `docs/research/dhcp-backend-endpoints.md`. If the research found that Kea uses `/api/kea/dhcpv4/...` style endpoints, use those. If endpoints mirror ISC's structure under a different prefix, adapt accordingly. If deletion is not supported by the Kea API, the `delete_v4_lease` and `delete_v6_lease` methods should return `{"status": "error", "error": "Lease deletion not supported by Kea backend"}`.

- [ ] **Step 1: Write failing tests for KeaProvider**

Create `tests/test_dhcp_providers/test_kea.py`. Follow the same test structure as `tests/test_dhcp_providers/test_isc.py` but with:
- `from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider`
- The correct endpoint paths discovered in Task 1
- The correct response shapes discovered in Task 1
- Test that `provider.name == "kea"`

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_dhcp_providers/test_kea.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement KeaProvider**

Create `opnsense_mcp/utils/dhcp_providers/kea.py`. Follow the same class structure as `ISCProvider` in `opnsense_mcp/utils/dhcp_providers/isc.py`:
- `name = "kea"`
- Use the endpoint paths discovered in Task 1
- Implement `_extract_leases()` to handle Kea's response shape
- All six methods: `get_v4_leases`, `get_v6_leases`, `search_v4_leases`, `search_v6_leases`, `delete_v4_lease`, `delete_v6_lease`

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_dhcp_providers/test_kea.py -v`

Expected: All tests PASS

- [ ] **Step 5: Update dhcp_providers/__init__.py**

Add `KeaProvider` to the re-exports in `opnsense_mcp/utils/dhcp_providers/__init__.py`:

```python
"""DHCP backend provider implementations."""

from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider

__all__ = ["ISCProvider", "KeaProvider"]
```

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check opnsense_mcp/utils/dhcp_providers/kea.py tests/test_dhcp_providers/test_kea.py
uv run ruff format opnsense_mcp/utils/dhcp_providers/kea.py tests/test_dhcp_providers/test_kea.py
git add opnsense_mcp/utils/dhcp_providers/kea.py opnsense_mcp/utils/dhcp_providers/__init__.py tests/test_dhcp_providers/test_kea.py
git commit -m "feat: implement KeaProvider with tests"
```

---

### Task 5: Implement DnsmasqProvider

**Files:**
- Create: `opnsense_mcp/utils/dhcp_providers/dnsmasq.py`
- Create: `tests/test_dhcp_providers/test_dnsmasq.py`

**Prerequisite:** Task 1 (endpoint research). Same guidance as Task 4 — use discovered endpoints and response shapes from `docs/research/dhcp-backend-endpoints.md`.

- [ ] **Step 1: Write failing tests for DnsmasqProvider**

Create `tests/test_dhcp_providers/test_dnsmasq.py`. Follow the same test structure as `tests/test_dhcp_providers/test_isc.py` but with:
- `from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider`
- The correct endpoint paths discovered in Task 1
- The correct response shapes discovered in Task 1
- Test that `provider.name == "dnsmasq"`

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_dhcp_providers/test_dnsmasq.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement DnsmasqProvider**

Create `opnsense_mcp/utils/dhcp_providers/dnsmasq.py`. Follow the same class structure as `ISCProvider`:
- `name = "dnsmasq"`
- Use the endpoint paths discovered in Task 1
- Implement `_extract_leases()` to handle dnsmasq's response shape
- All six methods

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_dhcp_providers/test_dnsmasq.py -v`

Expected: All tests PASS

- [ ] **Step 5: Update dhcp_providers/__init__.py**

Add `DnsmasqProvider` to the re-exports:

```python
"""DHCP backend provider implementations."""

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider

__all__ = ["DnsmasqProvider", "ISCProvider", "KeaProvider"]
```

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check opnsense_mcp/utils/dhcp_providers/dnsmasq.py tests/test_dhcp_providers/test_dnsmasq.py
uv run ruff format opnsense_mcp/utils/dhcp_providers/dnsmasq.py tests/test_dhcp_providers/test_dnsmasq.py
git add opnsense_mcp/utils/dhcp_providers/dnsmasq.py opnsense_mcp/utils/dhcp_providers/__init__.py tests/test_dhcp_providers/test_dnsmasq.py
git commit -m "feat: implement DnsmasqProvider with tests"
```

---

### Task 6: Implement detect_dhcp_backend() and Detection Tests

**Files:**
- Modify: `opnsense_mcp/utils/dhcp_provider.py` (add `detect_dhcp_backend()`)
- Create: `tests/test_dhcp_detection.py`

**Prerequisite:** Tasks 3, 4, 5 (all providers exist). Task 1 (detection probe endpoints).

- [ ] **Step 1: Write failing tests for detection**

Create `tests/test_dhcp_detection.py`:

```python
"""Tests for DHCP backend auto-detection."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_provider import detect_dhcp_backend
from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create a mock make_request callable."""
    return AsyncMock()


class TestDetectDHCPBackend:
    @pytest.mark.asyncio
    async def test_selects_kea_when_kea_responds(self, make_request: AsyncMock) -> None:
        """Kea endpoint succeeds — should select KeaProvider."""
        # Kea probe succeeds on first call
        make_request.return_value = {"rows": []}
        provider = await detect_dhcp_backend(make_request)
        assert isinstance(provider, KeaProvider)
        assert provider.name == "kea"

    @pytest.mark.asyncio
    async def test_selects_dnsmasq_when_kea_fails(self, make_request: AsyncMock) -> None:
        """Kea fails, dnsmasq succeeds — should select DnsmasqProvider."""
        call_count = 0

        async def side_effect(method: str, endpoint: str, **kwargs: object) -> dict:
            nonlocal call_count
            call_count += 1
            # First call is Kea probe — fail it
            if call_count == 1:
                raise Exception("not found")
            # Second call is dnsmasq probe — succeed
            return {"rows": []}

        make_request.side_effect = side_effect
        provider = await detect_dhcp_backend(make_request)
        assert isinstance(provider, DnsmasqProvider)
        assert provider.name == "dnsmasq"

    @pytest.mark.asyncio
    async def test_selects_isc_when_kea_and_dnsmasq_fail(
        self, make_request: AsyncMock
    ) -> None:
        """Both Kea and dnsmasq fail, ISC succeeds — should select ISCProvider."""
        call_count = 0

        async def side_effect(method: str, endpoint: str, **kwargs: object) -> dict:
            nonlocal call_count
            call_count += 1
            # First two probes fail (Kea, dnsmasq)
            if call_count <= 2:
                raise Exception("not found")
            # Third is ISC probe — succeed
            return {"rows": []}

        make_request.side_effect = side_effect
        provider = await detect_dhcp_backend(make_request)
        assert isinstance(provider, ISCProvider)
        assert provider.name == "isc"

    @pytest.mark.asyncio
    async def test_falls_back_to_isc_when_all_fail(
        self, make_request: AsyncMock
    ) -> None:
        """All probes fail — should fall back to ISCProvider with warning."""
        make_request.side_effect = Exception("all endpoints down")
        provider = await detect_dhcp_backend(make_request)
        assert isinstance(provider, ISCProvider)
        assert provider.name == "isc"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_dhcp_detection.py -v`

Expected: FAIL — `ImportError: cannot import name 'detect_dhcp_backend'`

- [ ] **Step 3: Implement detect_dhcp_backend()**

Add to `opnsense_mcp/utils/dhcp_provider.py` (after the Protocol class):

```python
from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


# Probe order: Kea first (OPNsense future direction), then dnsmasq, then ISC.
# Each entry: (probe_endpoint, provider_class)
# The probe endpoints should come from the Task 1 research.
_BACKEND_PROBES: list[tuple[str, type]] = [
    ("<kea_probe_endpoint_from_research>", KeaProvider),
    ("<dnsmasq_probe_endpoint_from_research>", DnsmasqProvider),
    (ISCProvider.V4_LEASE_ENDPOINT, ISCProvider),
]


async def detect_dhcp_backend(make_request: MakeRequestFn) -> DHCPProvider:
    """Probe OPNsense API to determine which DHCP backend is active.

    Tries Kea, then dnsmasq, then ISC. Falls back to ISC if all probes fail.

    Args:
        make_request: Async callable matching OPNsenseClient._make_request.

    Returns:
        An instantiated DHCPProvider for the detected backend.
    """
    for probe_endpoint, provider_cls in _BACKEND_PROBES:
        try:
            await make_request("GET", probe_endpoint)
            provider = provider_cls(make_request)
            logger.info("Detected DHCP backend: %s (via %s)", provider.name, probe_endpoint)
            return provider
        except Exception:
            logger.debug("DHCP probe failed for %s endpoint: %s", provider_cls.name, probe_endpoint)
            continue

    logger.warning("All DHCP backend probes failed — falling back to ISC")
    return ISCProvider(make_request)
```

**Note:** Replace `<kea_probe_endpoint_from_research>` and `<dnsmasq_probe_endpoint_from_research>` with the actual endpoints discovered in Task 1.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_dhcp_detection.py -v`

Expected: All tests PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check opnsense_mcp/utils/dhcp_provider.py tests/test_dhcp_detection.py
uv run ruff format opnsense_mcp/utils/dhcp_provider.py tests/test_dhcp_detection.py
git add opnsense_mcp/utils/dhcp_provider.py tests/test_dhcp_detection.py
git commit -m "feat: implement detect_dhcp_backend with probe logic and tests"
```

---

### Task 7: Wire Providers into OPNsenseClient

**Files:**
- Modify: `opnsense_mcp/utils/api.py`

**Prerequisite:** Task 6 (detection + all providers ready)

- [ ] **Step 1: Add provider attribute and detection method to OPNsenseClient.__init__**

In `opnsense_mcp/utils/api.py`, add import at the top:

```python
from opnsense_mcp.utils.dhcp_provider import DHCPProvider, detect_dhcp_backend
```

In `__init__()`, replace lines 125-127:

```python
        # Use official endpoints for DHCP leases
        self.dhcpv4_lease_endpoint = "/api/dhcpv4/leases/search_lease"
        self.dhcpv6_lease_endpoint = "/api/dhcpv6/leases/search_lease"
```

with:

```python
        # DHCP provider — lazily detected on first DHCP call
        self._dhcp_provider: DHCPProvider | None = None
        self._dhcp_provider_lock = asyncio.Lock()
```

- [ ] **Step 2: Add _ensure_dhcp_provider method**

Add this method to `OPNsenseClient` (after `_ensure_firewall_log_endpoint`, around line 157):

```python
    async def _ensure_dhcp_provider(self) -> None:
        """Detect and cache the DHCP backend provider on first use."""
        if self._dhcp_provider is not None:
            return
        async with self._dhcp_provider_lock:
            if self._dhcp_provider is not None:
                return
            self._dhcp_provider = await detect_dhcp_backend(self._make_request)
```

- [ ] **Step 3: Replace the four existing DHCP methods**

Replace `get_dhcpv4_leases` (lines 719-734):

```python
    async def get_dhcpv4_leases(self) -> list[dict[str, Any]]:
        """Get DHCPv4 lease table from OPNsense."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.get_v4_leases()
```

Replace `get_dhcpv6_leases` (lines 736-751):

```python
    async def get_dhcpv6_leases(self) -> list[dict[str, Any]]:
        """Get DHCPv6 lease table from OPNsense."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.get_v6_leases()
```

Replace `search_dhcpv4_leases` (lines 753-768):

```python
    async def search_dhcpv4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases server-side by hostname, IP, or MAC."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.search_v4_leases(query)
```

Replace `search_dhcpv6_leases` (lines 770-785):

```python
    async def search_dhcpv6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases server-side by hostname, IP, or MAC."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.search_v6_leases(query)
```

- [ ] **Step 4: Add new delete methods**

Add these two new public methods after the search methods:

```python
    async def delete_dhcpv4_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv4 lease by IP address."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.delete_v4_lease(ip)

    async def delete_dhcpv6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""
        await self._ensure_dhcp_provider()
        return await self._dhcp_provider.delete_v6_lease(ip)
```

- [ ] **Step 5: Run existing tests to check nothing broke**

Run: `uv run pytest tests/ -v`

Expected: All existing tests PASS (the mock client in tests should still work since the method signatures haven't changed)

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check opnsense_mcp/utils/api.py
uv run ruff format opnsense_mcp/utils/api.py
git add opnsense_mcp/utils/api.py
git commit -m "refactor: wire DHCP provider detection into OPNsenseClient"
```

---

### Task 8: Update DHCPLeaseDeleteTool to Use New Public Methods

**Files:**
- Modify: `opnsense_mcp/tools/dhcp_lease_delete.py:154-156,178-180`
- Modify: `tests/test_dhcp_lease_delete.py`

- [ ] **Step 1: Update the delete tool**

In `opnsense_mcp/tools/dhcp_lease_delete.py`, replace the IPv4 deletion block (around line 153-156):

```python
                        # Before:
                        response = await self.client._make_request(
                            "POST", f"/api/dhcpv4/leases/del_lease/{lease_ip}"
                        )
```

with:

```python
                        response = await self.client.delete_dhcpv4_lease(lease_ip)
```

Replace the IPv6 deletion block (around line 178-180):

```python
                        # Before:
                        response = await self.client._make_request(
                            "POST", f"/api/dhcpv6/leases/del_lease/{lease_ip}"
                        )
```

with:

```python
                        response = await self.client.delete_dhcpv6_lease(lease_ip)
```

- [ ] **Step 2: Update test mocks**

In `tests/test_dhcp_lease_delete.py`, update the `mock_client` fixture. Replace:

```python
        client._make_request = AsyncMock()
```

with:

```python
        client.delete_dhcpv4_lease = AsyncMock(return_value={"status": "ok"})
        client.delete_dhcpv6_lease = AsyncMock(return_value={"status": "ok"})
```

Update any test assertions that check `client._make_request` calls to instead check `client.delete_dhcpv4_lease` or `client.delete_dhcpv6_lease`.

- [ ] **Step 3: Run delete tool tests**

Run: `uv run pytest tests/test_dhcp_lease_delete.py -v`

Expected: All tests PASS

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/ -v`

Expected: All tests PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check opnsense_mcp/tools/dhcp_lease_delete.py tests/test_dhcp_lease_delete.py
uv run ruff format opnsense_mcp/tools/dhcp_lease_delete.py tests/test_dhcp_lease_delete.py
git add opnsense_mcp/tools/dhcp_lease_delete.py tests/test_dhcp_lease_delete.py
git commit -m "refactor: use public delete methods in DHCPLeaseDeleteTool"
```

---

### Task 9: Final Integration Verification

**Files:** None new — verification only.

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`

Expected: All tests PASS

- [ ] **Step 2: Lint entire project**

Run: `uv run ruff check . && uv run ruff format --check .`

Expected: No errors

- [ ] **Step 3: Verify protocol conformance**

Run: `uv run python -c "
from opnsense_mcp.utils.dhcp_provider import DHCPProvider
from opnsense_mcp.utils.dhcp_providers import ISCProvider, KeaProvider, DnsmasqProvider
from unittest.mock import AsyncMock
mr = AsyncMock()
for cls in (ISCProvider, KeaProvider, DnsmasqProvider):
    p = cls(mr)
    assert isinstance(p, DHCPProvider), f'{cls.__name__} does not satisfy DHCPProvider protocol'
    print(f'{cls.__name__}: OK')
print('All providers conform to DHCPProvider protocol')
"`

Expected: All three providers print OK

- [ ] **Step 4: Commit any final fixes if needed**

If Steps 1-3 revealed issues, fix and commit. Otherwise, no action needed.

---

## Parallelism Guide

Tasks that can run in parallel (independent of each other):
- **Tasks 3, 4, 5** can run in parallel (each provider is independent), provided Task 1 completes first for Tasks 4 and 5
- **Task 2** must complete before Tasks 3, 4, 5 (they import from the Protocol module)

Dependency chain:
```
Task 1 (research) ──────────────┐
Task 2 (protocol) ──┬──────────┐│
                     │          ││
                Task 3 (ISC)  Task 4 (Kea)  Task 5 (dnsmasq)
                     │          │             │
                     └──────────┴─────────────┘
                              │
                        Task 6 (detection)
                              │
                        Task 7 (wire into client)
                              │
                        Task 8 (update delete tool)
                              │
                        Task 9 (final verification)
```
