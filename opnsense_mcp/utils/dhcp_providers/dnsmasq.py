"""dnsmasq DHCP provider for OPNsense."""

import ipaddress
import logging
import re
from collections.abc import Callable, Coroutine
from typing import Any

from opnsense_mcp.utils.dhcp_host import (
    DhcpHostRecord,
    apply_v4_suffix,
    apply_v6_suffix,
    find_ipv4_conflicts,
    flatten_host_for_write,
    format_ip_field,
    normalize_client_id,
    parse_ip_field,
)
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
_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)


def _normalize_mac(mac: str) -> str:
    """Return lowercase colon-separated MAC address, or raise ValueError."""
    normalized = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(normalized):
        msg = f"Invalid MAC address: {mac!r}"
        raise ValueError(msg)
    return normalized


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
    RANGE_GET_ENDPOINT = "/api/dnsmasq/settings/get_range"
    RANGE_SET_ENDPOINT = "/api/dnsmasq/settings/set_range"
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
            "interface": (
                "" if use_tag else str(row.get("interface") or scope.interface)
            ),
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

    async def _find_host(self, identifier: str) -> dict[str, Any] | None:
        """Find a single host row by hostname or MAC.

        If multiple rows share the same MAC or hostname, the first match in the
        returned order is used.
        """
        needle = identifier.strip().lower()

        def _match(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
            for row in rows:
                if str(row.get("host") or "").lower() == needle:
                    return row
                if str(row.get("hwaddr") or "").lower() == needle:
                    return row
            return None

        # OPNsense server-side search is fuzzy and may return rows that match the
        # identifier in some other field (e.g. description) but not by host/MAC.
        # Try the filtered result first, then fall back to the full list if the
        # exact-match scan finds nothing.
        match = _match(await self.list_hosts(search=identifier))
        if match is not None:
            return match
        return _match(await self.list_hosts())

    async def move_host(
        self,
        *,
        identifier: str,
        ipv4_target: int | str | None,
        ipv6_target: int | str | None,
        new_hostname: str | None = None,
        client_id: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Move a host reservation to new v4 and/or v6 addresses."""
        row = await self._find_host(identifier)
        if row is None:
            return {
                "status": "error",
                "error": f"No host reservation matched {identifier!r}",
            }
        rec = DhcpHostRecord.from_row(row)

        new_ipv4 = rec.ipv4
        new_ipv6 = rec.ipv6_suffix
        if ipv4_target is not None:
            if rec.ipv4:
                new_ipv4 = apply_v4_suffix(rec.ipv4, ipv4_target)
            else:
                raw = str(ipv4_target).strip()
                if "." in raw:
                    new_ipv4 = str(ipaddress.ip_address(raw))
                else:
                    return {
                        "status": "error",
                        "error": (
                            f"{rec.host} has no IPv4 reservation; "
                            "provide a full address (e.g. 10.0.3.13)"
                        ),
                    }
        if ipv6_target is not None:
            new_ipv6 = apply_v6_suffix(ipv6_target)

        new_host = rec.host
        if new_hostname is not None:
            stripped = new_hostname.strip()
            if not stripped:
                return {
                    "status": "error",
                    "error": "new_hostname must be non-empty when provided",
                }
            new_host = stripped

        current_client_id = normalize_client_id(str(rec.raw.get("client_id") or ""))
        new_client_id = current_client_id
        if client_id is not None:
            try:
                new_client_id = normalize_client_id(client_id)
            except ValueError as exc:
                return {"status": "error", "error": str(exc)}

        raw_ip = str(rec.raw.get("ip") or "")
        canonical_ip = format_ip_field(new_ipv4, new_ipv6)
        needs_ip_rewrite = bool(canonical_ip and raw_ip != canonical_ip)

        if (
            new_ipv4 == rec.ipv4
            and new_ipv6 == rec.ipv6_suffix
            and new_host == rec.host
            and new_client_id == current_client_id
            and not needs_ip_rewrite
        ):
            return {
                "status": "noop",
                "backend": self.name,
                "note": "No address or hostname changes requested.",
            }

        all_hosts = await self.list_hosts()
        leases = self._extract_leases(
            await self._request(
                "POST",
                self.LEASE_ENDPOINT,
                json={"current": 1, "rowCount": -1, "searchPhrase": ""},
            )
        )
        conflicts: list[dict[str, Any]] = []
        if new_ipv4 and new_ipv4 != rec.ipv4:
            conflicts = find_ipv4_conflicts(
                target_ipv4=new_ipv4,
                moving_uuid=rec.uuid,
                hosts=all_hosts,
                leases=leases,
            )
        if new_client_id and new_client_id != current_client_id:
            for row in all_hosts:
                if str(row.get("uuid") or "") == rec.uuid:
                    continue
                existing = normalize_client_id(str(row.get("client_id") or ""))
                if existing and existing == new_client_id:
                    conflicts.append(
                        {
                            "kind": "reservation",
                            "reason": "duplicate client_id",
                            "host": str(row.get("host") or ""),
                            "client_id": new_client_id,
                            "uuid": str(row.get("uuid") or ""),
                        }
                    )

        planned = {
            "host": rec.host,
            "hwaddr": rec.hwaddr,
            "hostname": (
                {"from": rec.host, "to": new_host} if new_host != rec.host else None
            ),
            "ipv4": (
                {"from": rec.ipv4, "to": new_ipv4} if new_ipv4 != rec.ipv4 else None
            ),
            "ipv6": (
                {"from": rec.ipv6_suffix, "to": new_ipv6}
                if new_ipv6 != rec.ipv6_suffix
                else None
            ),
            "client_id": (
                {"from": current_client_id or None, "to": new_client_id or None}
                if new_client_id != current_client_id
                else None
            ),
        }

        if conflicts:
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "conflicts": conflicts,
            }

        if dry_run:
            return {
                "status": "dry_run",
                "backend": self.name,
                "planned": planned,
                "note": "No changes applied. Re-run with dry_run=false to apply.",
            }

        original_payload = flatten_host_for_write(
            rec, new_ipv4=rec.ipv4, new_ipv6=rec.ipv6_suffix
        )
        new_payload = flatten_host_for_write(
            rec,
            new_ipv4=new_ipv4,
            new_ipv6=new_ipv6,
            new_client_id=new_client_id,
        )
        if new_host != rec.host:
            new_payload["host"] = new_host
        try:
            await self.set_host(rec.uuid, new_payload)
            await self._reconfigure()
        except Exception as exc:
            logger.exception("host move failed; rolling back")
            restore_error: str | None = None
            try:
                await self.set_host(rec.uuid, original_payload)
                await self._reconfigure()
            except Exception as restore_exc:
                restore_error = str(restore_exc)
                logger.exception("host move rollback failed")
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "error": str(exc),
                "restored": restore_error is None,
                "restore_error": restore_error,
            }

        return {
            "status": "success",
            "backend": self.name,
            "planned": planned,
            "renewal_note": (
                "Reservation updated. Client keeps its old address until it "
                "renews or reboots. IPv6 applies only to stateful-DHCPv6 clients."
            ),
        }

    async def create_host(
        self,
        *,
        hostname: str,
        mac: str,
        ipv4: str | None = None,
        ipv6: int | str | None = None,
        client_id: str | None = None,
        descr: str = "",
        domain: str = "",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Create a new dnsmasq host reservation."""
        try:
            normalized_mac = _normalize_mac(mac)
        except ValueError as exc:
            return {"status": "error", "error": str(exc)}

        if not hostname.strip():
            return {"status": "error", "error": "hostname is required"}

        normalized_ipv4: str | None = None
        if ipv4 is not None:
            raw = str(ipv4).strip()
            try:
                import ipaddress as _ipaddress

                addr = _ipaddress.ip_address(raw)
                if addr.version != 4:
                    return {
                        "status": "error",
                        "error": f"Expected IPv4 address, got {raw!r}",
                    }
                normalized_ipv4 = str(addr)
            except ValueError:
                return {"status": "error", "error": f"Invalid IPv4 address: {raw!r}"}

        normalized_ipv6: str | None = None
        if ipv6 is not None:
            try:
                normalized_ipv6 = apply_v6_suffix(ipv6)
            except ValueError as exc:
                return {"status": "error", "error": str(exc)}

        if normalized_ipv4 is None and normalized_ipv6 is None:
            return {
                "status": "error",
                "error": "At least one of ipv4 or ipv6 is required",
            }

        normalized_client_id = ""
        if client_id is not None:
            try:
                normalized_client_id = normalize_client_id(client_id)
            except ValueError as exc:
                return {"status": "error", "error": str(exc)}

        all_hosts = await self.list_hosts()
        leases = self._extract_leases(
            await self._request(
                "POST",
                self.LEASE_ENDPOINT,
                json={"current": 1, "rowCount": -1, "searchPhrase": ""},
            )
        )

        conflicts: list[dict[str, Any]] = []
        for row in all_hosts:
            if str(row.get("hwaddr") or "").lower() == normalized_mac:
                conflicts.append(
                    {
                        "kind": "reservation",
                        "reason": "duplicate MAC",
                        "host": str(row.get("host") or ""),
                        "hwaddr": normalized_mac,
                        "uuid": str(row.get("uuid") or ""),
                    }
                )
        if normalized_client_id:
            for row in all_hosts:
                existing = normalize_client_id(str(row.get("client_id") or ""))
                if existing and existing == normalized_client_id:
                    conflicts.append(
                        {
                            "kind": "reservation",
                            "reason": "duplicate client_id",
                            "host": str(row.get("host") or ""),
                            "client_id": normalized_client_id,
                            "uuid": str(row.get("uuid") or ""),
                        }
                    )
        if normalized_ipv4:
            conflicts.extend(
                find_ipv4_conflicts(
                    target_ipv4=normalized_ipv4,
                    moving_uuid="",
                    hosts=all_hosts,
                    leases=leases,
                    promoting_mac=normalized_mac,
                )
            )

        planned = {
            "host": hostname.strip(),
            "hwaddr": normalized_mac,
            "ipv4": normalized_ipv4,
            "ipv6_suffix": normalized_ipv6,
            "client_id": normalized_client_id or None,
            "descr": descr,
            "domain": domain,
        }

        if conflicts:
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "conflicts": conflicts,
            }

        if dry_run:
            return {
                "status": "dry_run",
                "backend": self.name,
                "planned": planned,
                "note": "No changes applied. Re-run with apply=true to create.",
            }

        host_payload: dict[str, Any] = {
            "host": hostname.strip(),
            "hwaddr": normalized_mac,
            "ip": format_ip_field(normalized_ipv4, normalized_ipv6),
            "domain": domain,
            "descr": descr,
            "local": "",
            "cnames": "",
            "client_id": normalized_client_id,
            "lease_time": "",
            "ignore": "0",
            "set_tag": "",
            "comments": "",
            "aliases": "",
        }

        try:
            result = await self.add_host(host_payload)
            if result.get("result") != "saved":
                return {
                    "status": "error",
                    "backend": self.name,
                    "planned": planned,
                    "error": f"API returned: {result}",
                }
            await self._reconfigure()
        except Exception as exc:
            logger.exception("create_host failed for %s", hostname)
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "error": str(exc),
            }

        return {
            "status": "success",
            "backend": self.name,
            "created": {**planned, "uuid": str(result.get("uuid", ""))},
        }

    async def _resolve_host_row(self, identifier: str) -> dict[str, Any] | None:
        """Find a host row by hostname, MAC, or reservation uuid."""
        row = await self._find_host(identifier)
        if row is not None:
            return row
        needle = identifier.strip().lower()
        for candidate in await self.list_hosts():
            if str(candidate.get("uuid") or "").lower() == needle:
                return candidate
        return None

    async def delete_host(
        self,
        *,
        identifier: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Delete a host reservation by hostname, MAC, or uuid."""
        row = await self._resolve_host_row(identifier)
        if row is None:
            return {
                "status": "error",
                "error": f"No host reservation matched {identifier!r}",
            }
        rec = DhcpHostRecord.from_row(row)
        planned = rec.to_summary()

        if dry_run:
            return {
                "status": "dry_run",
                "backend": self.name,
                "planned": planned,
                "note": "No changes applied. Re-run with dry_run=false to apply.",
            }

        try:
            await self.del_host(rec.uuid)
            await self._reconfigure()
        except Exception as exc:
            logger.exception("host delete failed for %s", rec.host)
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "error": str(exc),
            }

        return {
            "status": "success",
            "backend": self.name,
            "deleted": planned,
        }

    async def _find_range_row(
        self,
        *,
        subnet: str | None = None,
        interface: str | None = None,
        uuid: str | None = None,
    ) -> dict[str, Any] | None:
        """Find a dnsmasq DHCP range by uuid or scope selectors."""
        if uuid:
            needle = uuid.strip().lower()
            for row in await self._load_ranges():
                if str(row.get("uuid") or "").lower() == needle:
                    return row
            return None
        scope = await self.resolve_subnet_scope(subnet=subnet, interface=interface)
        for row in await self._load_ranges():
            row_interface = str(row.get("interface") or "").strip()
            if interface_matches(row_interface, scope.interface):
                return row
        return None

    async def _get_range_model(self, uuid: str) -> dict[str, Any]:
        response = await self._request("GET", f"{self.RANGE_GET_ENDPOINT}/{uuid}")
        if isinstance(response, dict) and isinstance(response.get("range"), dict):
            return response["range"]
        if isinstance(response, dict):
            return response
        return {}

    def _flat_range_payload(self, row: dict[str, Any], *, enabled: bool) -> dict[str, Any]:
        """Build flat range payload for set_range (preserve pool fields)."""
        return {
            "uuid": str(row.get("uuid") or ""),
            "interface": str(row.get("interface") or ""),
            "set_tag": str(row.get("set_tag") or ""),
            "start_addr": str(row.get("start_addr") or ""),
            "end_addr": str(row.get("end_addr") or ""),
            "domain": str(row.get("domain") or ""),
            "domain_search_list": str(row.get("domain_search_list") or ""),
            "nosync": str(row.get("nosync") or "0"),
            "dhcpv4": str(row.get("dhcpv4") or "1"),
            "dhcpv6": str(row.get("dhcpv6") or "0"),
            "ra_mode": str(row.get("ra_mode") or ""),
            "ra_priority": str(row.get("ra_priority") or ""),
            "description": str(row.get("description") or ""),
            "disabled": "0" if enabled else "1",
        }

    async def toggle_range(
        self,
        *,
        enabled: bool,
        subnet: str | None = None,
        interface: str | None = None,
        uuid: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Enable or disable a dnsmasq DHCP range and reconfigure."""
        row = await self._find_range_row(subnet=subnet, interface=interface, uuid=uuid)
        if row is None:
            return {
                "status": "error",
                "backend": self.name,
                "error": "No matching DHCP range found for scope",
                "subnet": subnet,
                "interface": interface,
                "uuid": uuid,
            }

        range_uuid = str(row.get("uuid") or "")
        current_disabled = str(row.get("disabled") or "0") == "1"
        target_enabled = enabled
        if current_disabled == (not target_enabled):
            return {
                "status": "noop",
                "backend": self.name,
                "uuid": range_uuid,
                "enabled": target_enabled,
                "interface": row.get("interface"),
                "start_addr": row.get("start_addr"),
                "end_addr": row.get("end_addr"),
            }

        model = await self._get_range_model(range_uuid)
        merged = {**row, **model} if model else dict(row)
        payload = self._flat_range_payload(merged, enabled=target_enabled)
        planned = {
            "uuid": range_uuid,
            "enabled": target_enabled,
            "interface": payload.get("interface"),
            "start_addr": payload.get("start_addr"),
            "end_addr": payload.get("end_addr"),
        }

        if dry_run:
            return {
                "status": "dry_run",
                "backend": self.name,
                "planned": planned,
                "note": "No changes applied. Re-run with apply=true to toggle.",
            }

        try:
            await self._request(
                "POST",
                f"{self.RANGE_SET_ENDPOINT}/{range_uuid}",
                json={"range": payload},
                timeout=self.WRITE_TIMEOUT_SECONDS,
            )
            await self._reconfigure()
        except Exception as exc:
            logger.exception("dnsmasq range toggle failed")
            return {
                "status": "error",
                "backend": self.name,
                "planned": planned,
                "error": str(exc),
            }

        return {
            "status": "success",
            "backend": self.name,
            "uuid": range_uuid,
            "enabled": target_enabled,
            "interface": payload.get("interface"),
            "start_addr": payload.get("start_addr"),
            "end_addr": payload.get("end_addr"),
            "applied": True,
        }
