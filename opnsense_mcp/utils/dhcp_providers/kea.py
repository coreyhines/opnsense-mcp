"""Kea DHCP provider for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

from opnsense_mcp.utils.dhcp_scope import resolve_kea_scope
from opnsense_mcp.utils.dhcp_subnet_dns import (
    DhcpScope,
    Family,
    SubnetDnsSnapshot,
    parse_dns_server_list,
    unwrap_model_payload,
)

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]


class KeaProvider:
    """DHCP provider for the Kea backend."""

    name = "kea"
    V4_LEASE_ENDPOINT = "/api/kea/leases4/search"
    V6_LEASE_ENDPOINT = "/api/kea/leases6/search"
    SERVICE_STATUS_ENDPOINT = "/api/kea/service/status"
    V4_SUBNET_SEARCH_ENDPOINT = "/api/kea/dhcpv4/search_subnet"
    V6_SUBNET_SEARCH_ENDPOINT = "/api/kea/dhcpv6/search_subnet"
    V4_SUBNET_GET_ENDPOINT = "/api/kea/dhcpv4/get_subnet"
    V6_SUBNET_GET_ENDPOINT = "/api/kea/dhcpv6/get_subnet"
    V4_SUBNET_SET_ENDPOINT = "/api/kea/dhcpv4/set_subnet"
    V6_SUBNET_SET_ENDPOINT = "/api/kea/dhcpv6/set_subnet"
    RECONFIGURE_ENDPOINT = "/api/kea/service/reconfigure"
    SUBNET_DNS_SUPPORTED = True
    HOST_MOVE_SUPPORTED = False

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

    def _subnet_model_key(self, family: Family) -> str:
        """Return the Kea subnet payload key for a family."""
        return "subnet4" if family == "ipv4" else "subnet6"

    def _subnet_get_endpoint(self, family: Family) -> str:
        """Return the Kea get_subnet endpoint prefix for a family."""
        return (
            self.V4_SUBNET_GET_ENDPOINT
            if family == "ipv4"
            else self.V6_SUBNET_GET_ENDPOINT
        )

    def _subnet_set_endpoint(self, family: Family) -> str:
        """Return the Kea set_subnet endpoint prefix for a family."""
        return (
            self.V4_SUBNET_SET_ENDPOINT
            if family == "ipv4"
            else self.V6_SUBNET_SET_ENDPOINT
        )

    async def _load_subnet_payload(
        self,
        uuid: str,
        family: Family,
    ) -> dict[str, Any]:
        """Load the full Kea subnet model payload."""
        response = await self._request(
            "GET",
            f"{self._subnet_get_endpoint(family)}/{uuid}",
        )
        model_key = self._subnet_model_key(family)
        payload = unwrap_model_payload(response, model_key, "subnet")
        payload["uuid"] = uuid
        return payload

    def _extract_dns_servers(
        self,
        subnet_payload: dict[str, Any],
        family: Family,
    ) -> list[str]:
        """Extract DNS servers from a Kea subnet payload."""
        option_data = subnet_payload.get("option_data")
        if not isinstance(option_data, dict):
            return []
        dns_entry = option_data.get("domain_name_servers")
        if isinstance(dns_entry, dict):
            raw = str(dns_entry.get("value") or "")
        else:
            raw = str(dns_entry or "")
        return parse_dns_server_list(raw, family)

    def _apply_dns_servers_to_payload(
        self,
        subnet_payload: dict[str, Any],
        family: Family,
        servers: list[str],
    ) -> dict[str, Any]:
        """Return a subnet payload with updated DNS servers."""
        updated = dict(subnet_payload)
        updated["option_data_autocollect"] = "0"
        option_data = updated.get("option_data")
        if not isinstance(option_data, dict):
            option_data = {}
        option_data = dict(option_data)
        option_data["domain_name_servers"] = {
            "value": ",".join(servers),
            "selected": 1,
        }
        updated["option_data"] = option_data
        return updated

    async def _read_subnet_snapshot(
        self,
        *,
        subnet: str | None,
        interface: str | None,
        family: Family,
    ) -> tuple[DhcpScope, SubnetDnsSnapshot]:
        """Read current DNS servers and full subnet payload for rollback."""
        scope, row = await resolve_kea_scope(
            self._request,
            subnet=subnet,
            interface=interface,
            family=family,
        )
        uuid = str(row.get("uuid") or "")
        if not uuid:
            msg = f"Kea {family} subnet row is missing uuid"
            raise ValueError(msg)
        payload = await self._load_subnet_payload(uuid, family)
        servers = self._extract_dns_servers(payload, family)
        return scope, SubnetDnsSnapshot(
            family=family,
            servers=servers,
            backend_payload=payload,
        )

    async def _write_subnet_snapshot(
        self,
        snapshot: SubnetDnsSnapshot,
    ) -> None:
        """Write a Kea subnet payload."""
        payload = snapshot.backend_payload
        if not payload or not payload.get("uuid"):
            msg = "Missing Kea subnet payload for write"
            raise ValueError(msg)
        uuid = str(payload["uuid"])
        family = snapshot.family
        model_key = self._subnet_model_key(family)
        await self._request(
            "POST",
            f"{self._subnet_set_endpoint(family)}/{uuid}",
            json={model_key: payload},
        )

    async def list_subnet_dns(
        self,
        *,
        subnet: str | None = None,
        interface: str | None = None,
    ) -> dict[str, Any]:
        """Return scoped IPv4/IPv6 DNS servers from Kea subnet option data."""
        scope_v4, ipv4 = await self._read_subnet_snapshot(
            subnet=subnet,
            interface=interface,
            family="ipv4",
        )
        try:
            _, ipv6 = await self._read_subnet_snapshot(
                subnet=subnet,
                interface=interface,
                family="ipv6",
            )
            ipv6_servers = ipv6.servers
        except ValueError:
            ipv6_servers = []

        return {
            "backend": self.name,
            "scope": {
                "interface": scope_v4.interface,
                "subnet": scope_v4.subnet,
                "description": scope_v4.description,
            },
            "ipv4": ipv4.servers,
            "ipv6": ipv6_servers,
        }

    async def set_subnet_dns(
        self,
        *,
        subnet: str | None = None,
        interface: str | None = None,
        family: Family,
        servers: list[str],
    ) -> dict[str, Any]:
        """Update scoped DNS servers for one family with rollback on failure."""
        scope, before = await self._read_subnet_snapshot(
            subnet=subnet,
            interface=interface,
            family=family,
        )
        payload = before.backend_payload
        if not payload:
            msg = f"No Kea {family} subnet payload available for update"
            raise ValueError(msg)

        after_payload = self._apply_dns_servers_to_payload(payload, family, servers)
        after = SubnetDnsSnapshot(
            family=family,
            servers=servers,
            backend_payload=after_payload,
        )

        try:
            await self._write_subnet_snapshot(after)
            await self._request("POST", self.RECONFIGURE_ENDPOINT)
        except Exception as exc:
            logger.exception("Kea subnet DNS update failed; rolling back")
            restore_error: str | None = None
            try:
                await self._write_subnet_snapshot(before)
                await self._request("POST", self.RECONFIGURE_ENDPOINT)
            except Exception as restore_exc:
                restore_error = str(restore_exc)
                logger.exception("Kea subnet DNS rollback failed")
            return {
                "status": "error",
                "backend": self.name,
                "family": family,
                "scope": {
                    "interface": scope.interface,
                    "subnet": scope.subnet,
                    "description": scope.description,
                },
                "before": before.servers,
                "attempted": servers,
                "error": str(exc),
                "restored": restore_error is None,
                "restore_error": restore_error,
            }

        return {
            "status": "success",
            "backend": self.name,
            "family": family,
            "scope": {
                "interface": scope.interface,
                "subnet": scope.subnet,
                "description": scope.description,
            },
            "before": before.servers,
            "after": servers,
            "applied": True,
            "renewal_note": (
                "DHCP clients keep prior DNS until they renew or reconnect"
            ),
        }

    async def move_host(
        self,
        *,
        identifier: str,
        ipv4_target: int | str | None,
        ipv6_target: int | str | None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Host move is not supported on this backend yet."""
        return {
            "status": "error",
            "error": f"Host move not supported by {self.name} backend",
        }

    async def delete_host(
        self,
        *,
        identifier: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Host delete is not supported on this backend yet."""
        return {
            "status": "error",
            "error": f"Host delete not supported by {self.name} backend",
        }
