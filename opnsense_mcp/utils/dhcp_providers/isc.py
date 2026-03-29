"""ISC DHCP provider for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]


class ISCProvider:
    """DHCP provider for the ISC DHCP backend."""

    name = "isc"
    V4_LEASE_ENDPOINT = "/api/dhcpv4/leases/search_lease"
    V6_LEASE_ENDPOINT = "/api/dhcpv6/leases/search_lease"
    V4_DELETE_ENDPOINT = "/api/dhcpv4/leases/del_lease"
    V6_DELETE_ENDPOINT = "/api/dhcpv6/leases/del_lease"
    SERVICE_STATUS_ENDPOINT_V4 = "/api/dhcpv4/service/status"

    def __init__(self, make_request: MakeRequestFn) -> None:
        """Initialize provider with request function."""
        self._request = make_request

    def _extract_leases(
        self, response: dict[str, Any] | list[Any]
    ) -> list[dict[str, Any]]:
        """Extract leases from either rows/leases dict or list."""
        if isinstance(response, dict):
            if "leases" in response and isinstance(response["leases"], list):
                return response["leases"]
            if "rows" in response and isinstance(response["rows"], list):
                return response["rows"]
            return []
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        return []

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
        except Exception as exc:
            logger.exception("ISC: failed to delete DHCPv4 lease %s", ip)
            return {"status": "error", "error": str(exc)}

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""
        try:
            response = await self._request("POST", f"{self.V6_DELETE_ENDPOINT}/{ip}")
            return response if isinstance(response, dict) else {"status": "ok"}
        except Exception as exc:
            logger.exception("ISC: failed to delete DHCPv6 lease %s", ip)
            return {"status": "error", "error": str(exc)}
