"""Kea DHCP provider for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]


class KeaProvider:
    """DHCP provider for the Kea backend."""

    name = "kea"
    V4_LEASE_ENDPOINT = "/api/kea/leases4/search"
    V6_LEASE_ENDPOINT = "/api/kea/leases6/search"
    SERVICE_STATUS_ENDPOINT = "/api/kea/service/status"

    def __init__(self, make_request: MakeRequestFn) -> None:
        """Initialize provider with request function."""
        self._request = make_request

    def _extract_leases(
        self, response: dict[str, Any] | list[Any]
    ) -> list[dict[str, Any]]:
        """Extract leases from common OPNsense/Kea response shapes."""
        if isinstance(response, dict):
            if "rows" in response and isinstance(response["rows"], list):
                return response["rows"]
            if "leases" in response and isinstance(response["leases"], list):
                return response["leases"]
            arguments = response.get("arguments")
            if isinstance(arguments, dict) and isinstance(
                arguments.get("leases"), list
            ):
                return arguments["leases"]
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
            logger.exception("Kea: failed to get DHCPv4 leases")
            return []

    async def get_v6_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv6 leases."""
        try:
            response = await self._request("GET", self.V6_LEASE_ENDPOINT)
            return self._extract_leases(response)
        except Exception:
            logger.exception("Kea: failed to get DHCPv6 leases")
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
            logger.exception("Kea: failed to search DHCPv4 leases")
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
            logger.exception("Kea: failed to search DHCPv6 leases")
            return []

    async def delete_v4_lease(self, ip: str) -> dict[str, Any]:
        """Delete is not documented for OPNsense Kea backend."""
        return {
            "status": "error",
            "error": "Lease deletion not supported by Kea backend",
            "ip": ip,
        }

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete is not documented for OPNsense Kea backend."""
        return {
            "status": "error",
            "error": "Lease deletion not supported by Kea backend",
            "ip": ip,
        }
