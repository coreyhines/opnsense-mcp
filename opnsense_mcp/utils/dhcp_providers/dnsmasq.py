"""dnsmasq DHCP provider for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]


class DnsmasqProvider:
    """DHCP provider for the dnsmasq backend."""

    name = "dnsmasq"
    LEASE_ENDPOINT = "/api/dnsmasq/leases/search"
    SERVICE_STATUS_ENDPOINT = "/api/dnsmasq/service/status"

    def __init__(self, make_request: MakeRequestFn) -> None:
        """Initialize provider with request function."""
        self._request = make_request

    def _extract_leases(
        self, response: dict[str, Any] | list[Any]
    ) -> list[dict[str, Any]]:
        """Extract leases from common OPNsense response formats."""
        if isinstance(response, dict):
            if "rows" in response and isinstance(response["rows"], list):
                return response["rows"]
            if "leases" in response and isinstance(response["leases"], list):
                return response["leases"]
            return []
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        return []

    def _filter_family(
        self, leases: list[dict[str, Any]], family: int
    ) -> list[dict[str, Any]]:
        """Split mixed-family leases into IPv4/IPv6 buckets."""
        filtered: list[dict[str, Any]] = []
        for lease in leases:
            protocol = str(lease.get("protocol", "")).lower()
            address = str(lease.get("ip") or lease.get("address") or "")
            if family == 4:
                if protocol in {"ipv4", "v4"} or (
                    "." in address and ":" not in address
                ):
                    filtered.append(lease)
            elif protocol in {"ipv6", "v6"} or ":" in address:
                filtered.append(lease)
        return filtered

    async def get_v4_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv4 leases."""
        try:
            response = await self._request("GET", self.LEASE_ENDPOINT)
            return self._filter_family(self._extract_leases(response), family=4)
        except Exception:
            logger.exception("dnsmasq: failed to get DHCPv4 leases")
            return []

    async def get_v6_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv6 leases."""
        try:
            response = await self._request("GET", self.LEASE_ENDPOINT)
            return self._filter_family(self._extract_leases(response), family=6)
        except Exception:
            logger.exception("dnsmasq: failed to get DHCPv6 leases")
            return []

    async def search_v4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases by hostname, IP, or MAC."""
        try:
            response = await self._request(
                "POST",
                self.LEASE_ENDPOINT,
                json={"searchPhrase": query, "current": 1, "rowCount": -1},
            )
            return self._filter_family(self._extract_leases(response), family=4)
        except Exception:
            logger.exception("dnsmasq: failed to search DHCPv4 leases")
            return []

    async def search_v6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases by hostname, IP, or MAC."""
        try:
            response = await self._request(
                "POST",
                self.LEASE_ENDPOINT,
                json={"searchPhrase": query, "current": 1, "rowCount": -1},
            )
            return self._filter_family(self._extract_leases(response), family=6)
        except Exception:
            logger.exception("dnsmasq: failed to search DHCPv6 leases")
            return []

    async def delete_v4_lease(self, ip: str) -> dict[str, Any]:
        """Delete is not documented for OPNsense dnsmasq backend."""
        return {
            "status": "error",
            "error": "Lease deletion not supported by dnsmasq backend",
            "ip": ip,
        }

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete is not documented for OPNsense dnsmasq backend."""
        return {
            "status": "error",
            "error": "Lease deletion not supported by dnsmasq backend",
            "ip": ip,
        }
