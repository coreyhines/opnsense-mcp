"""dnsmasq DHCP provider for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

from opnsense_mcp.utils.dhcp_scope import resolve_scope_from_selectors
from opnsense_mcp.utils.dhcp_subnet_dns import (
    DhcpScope,
    Family,
    SubnetDnsSnapshot,
    extract_rows,
    format_dns_server_list,
    interface_matches,
    parse_dns_server_list,
)

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]
_UNSET: object = object()


class DnsmasqProvider:
    """DHCP provider for the dnsmasq backend."""

    name = "dnsmasq"
    LEASE_ENDPOINT = "/api/dnsmasq/leases/search"
    SERVICE_STATUS_ENDPOINT = "/api/dnsmasq/service/status"
    OPTIONS_SEARCH_ENDPOINT = "/api/dnsmasq/settings/search_option"
    OPTION_GET_ENDPOINT = "/api/dnsmasq/settings/get_option"
    OPTION_SET_ENDPOINT = "/api/dnsmasq/settings/set_option"
    OPTION_ADD_ENDPOINT = "/api/dnsmasq/settings/add_option"
    OPTION_DEL_ENDPOINT = "/api/dnsmasq/settings/del_option"
    RANGES_SEARCH_ENDPOINT = "/api/dnsmasq/settings/search_range"
    RECONFIGURE_ENDPOINT = "/api/dnsmasq/service/reconfigure"
    WRITE_TIMEOUT_SECONDS = 30
    RECONFIGURE_TIMEOUT_SECONDS = 60
    SUBNET_DNS_SUPPORTED = True
    HOST_SEARCH_ENDPOINT = "/api/dnsmasq/settings/search_host"
    HOST_GET_ENDPOINT = "/api/dnsmasq/settings/get_host"
    HOST_ADD_ENDPOINT = "/api/dnsmasq/settings/add_host"
    HOST_SET_ENDPOINT = "/api/dnsmasq/settings/set_host"
    HOST_DEL_ENDPOINT = "/api/dnsmasq/settings/del_host"
    HOST_MOVE_SUPPORTED = True

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

    async def resolve_subnet_scope(
        self,
        *,
        subnet: str | None,
        interface: str | None,
    ) -> DhcpScope:
        """Resolve a subnet/interface selector to a dnsmasq DHCP scope."""
        return await resolve_scope_from_selectors(
            self._request,
            subnet=subnet,
            interface=interface,
            range_search_endpoint=self.RANGES_SEARCH_ENDPOINT,
        )

    async def _load_options(self) -> list[dict[str, Any]]:
        """Load all dnsmasq DHCP option rows."""
        response = await self._request("GET", self.OPTIONS_SEARCH_ENDPOINT)
        return extract_rows(response)

    async def _load_ranges(self) -> list[dict[str, Any]]:
        """Load all dnsmasq DHCP range rows."""
        response = await self._request("GET", self.RANGES_SEARCH_ENDPOINT)
        return extract_rows(response)

    async def _scope_dhcp_tag(self, scope: DhcpScope) -> str | None:
        """
        Return the dhcp ``set_tag`` UUID applied to clients on this scope.

        OPNsense tags DHCP clients from range ``set_tag`` values. Scoped DNS
        options must use the same ``tag`` (not ``interface``) to take effect.
        """
        for row in await self._load_ranges():
            row_interface = str(row.get("interface") or "").strip()
            if not interface_matches(row_interface, scope.interface):
                continue
            set_tag = str(row.get("set_tag") or "").strip()
            if set_tag:
                return set_tag
        return None

    def _option_matches_scope(
        self,
        row: dict[str, Any],
        scope: DhcpScope,
        family: Family,
        dhcp_tag: str | None,
    ) -> bool:
        """Return True when an option row matches scope and DNS family."""
        row_tag = str(row.get("tag") or "").strip()
        row_interface = str(row.get("interface") or "").strip()
        if dhcp_tag:
            if row_tag != dhcp_tag:
                return False
        elif not interface_matches(row_interface, scope.interface):
            return False
        if family == "ipv4":
            return str(row.get("option") or "").strip() == "6"
        return str(row.get("option6") or "").strip() == "23"

    async def _find_option_row(
        self,
        scope: DhcpScope,
        family: Family,
        dhcp_tag: str | None,
    ) -> dict[str, Any] | None:
        """Find the dnsmasq option row for scoped DNS servers."""
        for row in await self._load_options():
            if self._option_matches_scope(row, scope, family, dhcp_tag):
                return row
        return None

    def _flat_option_payload(
        self,
        row: dict[str, Any],
        scope: DhcpScope,
        family: Family,
        value: str,
        dhcp_tag: str | None,
    ) -> dict[str, Any]:
        """Build a flat dnsmasq option payload accepted by set_option."""
        use_tag = str(row.get("tag") or dhcp_tag or "")
        payload: dict[str, Any] = {
            "uuid": str(row.get("uuid") or ""),
            "type": str(row.get("type") or "set"),
            "interface": ""
            if use_tag
            else str(row.get("interface") or scope.interface),
            "tag": use_tag,
            "set_tag": str(row.get("set_tag") or ""),
            "value": value,
            "force": str(row.get("force") or ("1" if use_tag else "0")),
            "description": str(row.get("description") or ""),
        }
        if family == "ipv4":
            payload["option"] = "6"
            payload["option6"] = ""
        else:
            payload["option6"] = "23"
            payload["option"] = ""
        return payload

    async def _read_option_snapshot(
        self,
        scope: DhcpScope,
        family: Family,
        dhcp_tag: str | None | object = _UNSET,
    ) -> SubnetDnsSnapshot:
        """Read current scoped DNS servers for one family."""
        if dhcp_tag is _UNSET:
            resolved_tag = await self._scope_dhcp_tag(scope)
        else:
            resolved_tag = dhcp_tag
        row = await self._find_option_row(scope, family, resolved_tag)
        if not row:
            return SubnetDnsSnapshot(family=family, servers=[], backend_payload=None)
        value = str(row.get("value") or "")
        servers = parse_dns_server_list(value, family)
        payload = self._flat_option_payload(row, scope, family, value, resolved_tag)
        return SubnetDnsSnapshot(
            family=family,
            servers=servers,
            backend_payload=payload,
        )

    async def list_subnet_dns(
        self,
        *,
        subnet: str | None = None,
        interface: str | None = None,
    ) -> dict[str, Any]:
        """Return scoped IPv4/IPv6 DNS servers from dnsmasq DHCP options."""
        scope = await self.resolve_subnet_scope(subnet=subnet, interface=interface)
        dhcp_tag = await self._scope_dhcp_tag(scope)
        ipv4 = await self._read_option_snapshot(scope, "ipv4", dhcp_tag)
        ipv6 = await self._read_option_snapshot(scope, "ipv6", dhcp_tag)
        return {
            "backend": self.name,
            "scope": {
                "interface": scope.interface,
                "subnet": scope.subnet,
                "description": scope.description,
            },
            "ipv4": ipv4.servers,
            "ipv6": ipv6.servers,
        }

    async def _write_option_snapshot(
        self,
        scope: DhcpScope,
        snapshot: SubnetDnsSnapshot,
        dhcp_tag: str | None | object = _UNSET,
    ) -> None:
        """Write one dnsmasq option snapshot for rollback or apply."""
        family = snapshot.family
        formatted = format_dns_server_list(snapshot.servers, family)
        payload = snapshot.backend_payload

        if payload and payload.get("uuid"):
            uuid = str(payload["uuid"])
            option_data = {
                key: value for key, value in payload.items() if key != "uuid"
            }
            option_data["value"] = formatted
            await self._request(
                "POST",
                f"{self.OPTION_SET_ENDPOINT}/{uuid}",
                json={"option": option_data},
                timeout=self.WRITE_TIMEOUT_SECONDS,
            )
            return

        if not snapshot.servers:
            return

        if dhcp_tag is _UNSET:
            resolved_tag = await self._scope_dhcp_tag(scope)
        else:
            resolved_tag = dhcp_tag
        new_option: dict[str, Any] = {
            "type": "set",
            "interface": "" if resolved_tag else scope.interface,
            "value": formatted,
            "force": "1" if resolved_tag else "0",
            "tag": resolved_tag or "",
            "set_tag": "",
            "description": "",
        }
        if family == "ipv4":
            new_option["option"] = "6"
            new_option["option6"] = ""
        else:
            new_option["option6"] = "23"
            new_option["option"] = ""
        await self._request(
            "POST",
            self.OPTION_ADD_ENDPOINT,
            json={"option": new_option},
            timeout=self.WRITE_TIMEOUT_SECONDS,
        )

    async def _delete_option(self, uuid: str) -> None:
        """Delete a dnsmasq DHCP option row."""
        await self._request(
            "POST",
            f"{self.OPTION_DEL_ENDPOINT}/{uuid}",
            timeout=self.WRITE_TIMEOUT_SECONDS,
        )

    async def _reconfigure(self) -> None:
        """Apply dnsmasq configuration changes."""
        await self._request(
            "POST",
            self.RECONFIGURE_ENDPOINT,
            timeout=self.RECONFIGURE_TIMEOUT_SECONDS,
        )

    async def set_subnet_dns(
        self,
        *,
        subnet: str | None = None,
        interface: str | None = None,
        family: Family,
        servers: list[str],
    ) -> dict[str, Any]:
        """Update scoped DNS servers for one family with rollback on failure."""
        scope = await self.resolve_subnet_scope(subnet=subnet, interface=interface)
        dhcp_tag = await self._scope_dhcp_tag(scope)
        before = await self._read_option_snapshot(scope, family, dhcp_tag)
        after = SubnetDnsSnapshot(
            family=family,
            servers=servers,
            backend_payload=before.backend_payload,
        )
        created_new = before.backend_payload is None and not before.servers

        try:
            await self._write_option_snapshot(scope, after, dhcp_tag)
            if created_new and after.backend_payload is None:
                refreshed = await self._read_option_snapshot(scope, family, dhcp_tag)
                after.backend_payload = refreshed.backend_payload
            await self._reconfigure()
        except Exception as exc:
            logger.exception("dnsmasq subnet DNS update failed; rolling back")
            restore_error: str | None = None
            try:
                if (
                    created_new
                    and after.backend_payload
                    and after.backend_payload.get("uuid")
                ):
                    await self._delete_option(str(after.backend_payload["uuid"]))
                else:
                    await self._write_option_snapshot(scope, before, dhcp_tag)
                await self._reconfigure()
            except Exception as restore_exc:
                restore_error = str(restore_exc)
                logger.exception("dnsmasq subnet DNS rollback failed")
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

    async def list_hosts(self, search: str = "") -> list[dict[str, Any]]:
        """Return host reservation rows (optionally filtered by searchPhrase)."""
        response = await self._request(
            "POST",
            self.HOST_SEARCH_ENDPOINT,
            json={"current": 1, "rowCount": -1, "searchPhrase": search},
        )
        return extract_rows(response)

    async def get_host(self, uuid: str) -> dict[str, Any]:
        """Return the form-model host record for a uuid (GET, no body)."""
        response = await self._request("GET", f"{self.HOST_GET_ENDPOINT}/{uuid}")
        return response if isinstance(response, dict) else {}

    async def add_host(self, host_payload: dict[str, Any]) -> dict[str, Any]:
        """Create a host reservation; returns {'result','uuid'}."""
        response = await self._request(
            "POST",
            self.HOST_ADD_ENDPOINT,
            json={"host": host_payload},
            timeout=self.WRITE_TIMEOUT_SECONDS,
        )
        return response if isinstance(response, dict) else {}

    async def set_host(self, uuid: str, host_payload: dict[str, Any]) -> dict[str, Any]:
        """Update a host reservation by uuid."""
        response = await self._request(
            "POST",
            f"{self.HOST_SET_ENDPOINT}/{uuid}",
            json={"host": host_payload},
            timeout=self.WRITE_TIMEOUT_SECONDS,
        )
        return response if isinstance(response, dict) else {}

    async def del_host(self, uuid: str) -> dict[str, Any]:
        """Delete a host reservation by uuid. Empty JSON body is required."""
        response = await self._request(
            "POST",
            f"{self.HOST_DEL_ENDPOINT}/{uuid}",
            json={},
            timeout=self.WRITE_TIMEOUT_SECONDS,
        )
        return response if isinstance(response, dict) else {}
