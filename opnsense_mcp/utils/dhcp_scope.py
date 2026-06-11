"""Resolve DHCP scopes from subnet CIDR and/or interface selectors."""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.dhcp_subnet_dns import (
    DhcpScope,
    cidr_matches,
    extract_rows,
    interface_matches,
    normalize_cidr,
)

logger = logging.getLogger(__name__)


async def load_interface_overview(
    make_request: Any,
) -> dict[str, dict[str, Any]]:
    """Load interface overview export keyed by interface identifier."""
    merged: dict[str, dict[str, Any]] = {}
    try:
        response = await make_request("GET", "/api/interfaces/overview/export")
    except Exception:
        logger.exception("Failed to fetch interface overview export")
        return merged

    if isinstance(response, list):
        for entry in response:
            if not isinstance(entry, dict):
                continue
            key = (
                entry.get("identifier")
                or entry.get("device")
                or entry.get("name")
                or ""
            )
            if key:
                merged[str(key)] = entry
    elif isinstance(response, dict):
        for key, value in response.items():
            if isinstance(value, dict):
                merged[str(key)] = value
    return merged


def resolve_interface_key(
    selector: str,
    overview: dict[str, dict[str, Any]],
) -> str | None:
    """Resolve a user interface selector to an OPNsense interface key."""
    needle = selector.strip()
    if not needle:
        return None

    if needle in overview:
        return needle

    needle_lc = needle.lower()
    for key, entry in overview.items():
        candidates = [
            key,
            str(entry.get("identifier") or ""),
            str(entry.get("description") or ""),
            str(entry.get("device") or ""),
            str(entry.get("name") or ""),
        ]
        if any(candidate and candidate.lower() == needle_lc for candidate in candidates):
            return key
    return None


def interface_ipv4_network(
    interface_key: str,
    overview: dict[str, dict[str, Any]],
) -> str | None:
    """Return the primary IPv4 network for an interface, if known."""
    entry = overview.get(interface_key, {})
    for field in ("subnet", "ipaddr", "address"):
        raw = entry.get(field)
        if not raw or not str(raw).strip():
            continue
        value = str(raw).strip()
        if "/" in value:
            try:
                return normalize_cidr(value)
            except ValueError:
                continue
        if field == "ipaddr":
            prefix = str(entry.get("subnet") or "").strip()
            if prefix.isdigit():
                try:
                    return normalize_cidr(f"{value}/{prefix}")
                except ValueError:
                    continue
    return None


async def resolve_scope_from_selectors(
    make_request: Any,
    *,
    subnet: str | None,
    interface: str | None,
    range_search_endpoint: str,
) -> DhcpScope:
    """
    Resolve subnet/interface selectors to a DHCP scope.

    ``range_search_endpoint`` is backend-specific (dnsmasq ranges or Kea subnets).
    """
    if not subnet and not interface:
        msg = "Provide subnet (CIDR) and/or interface"
        raise ValueError(msg)

    overview = await load_interface_overview(make_request)
    resolved_interface = (
        resolve_interface_key(interface, overview) if interface else None
    )
    if interface and not resolved_interface:
        msg = f"Unknown interface {interface!r}"
        raise ValueError(msg)

    normalized_subnet = normalize_cidr(subnet) if subnet else None
    if normalized_subnet and resolved_interface:
        iface_subnet = interface_ipv4_network(resolved_interface, overview)
        if iface_subnet and not cidr_matches(normalized_subnet, iface_subnet):
            msg = (
                f"Subnet {normalized_subnet} does not match interface "
                f"{resolved_interface} network {iface_subnet}"
            )
            raise ValueError(msg)
        description = overview.get(resolved_interface, {}).get("description")
        return DhcpScope(
            interface=resolved_interface,
            subnet=normalized_subnet,
            description=str(description) if description else None,
        )

    if resolved_interface:
        iface_subnet = interface_ipv4_network(resolved_interface, overview)
        description = overview.get(resolved_interface, {}).get("description")
        return DhcpScope(
            interface=resolved_interface,
            subnet=iface_subnet,
            description=str(description) if description else None,
        )

    if normalized_subnet is None:
        msg = "subnet selector is required when interface is not provided"
        raise ValueError(msg)
    response = await make_request("GET", range_search_endpoint)
    rows = extract_rows(response)
    for row in rows:
        row_subnet = str(
            row.get("subnet")
            or row.get("network")
            or row.get("range")
            or ""
        ).strip()
        row_interface = str(row.get("interface") or "").strip()
        if row_subnet and cidr_matches(row_subnet, normalized_subnet):
            if not row_interface:
                msg = f"No interface mapped to subnet {normalized_subnet}"
                raise ValueError(msg)
            return DhcpScope(
                interface=row_interface,
                subnet=normalized_subnet,
                description=str(row.get("description") or "") or None,
            )
        start = str(row.get("start") or row.get("rangestart") or "").strip()
        end = str(row.get("end") or row.get("rangeend") or "").strip()
        if start and end:
            try:
                candidate = normalize_cidr(f"{start}/{normalized_subnet.split('/')[1]}")
            except (IndexError, ValueError):
                candidate = ""
            if candidate and cidr_matches(candidate, normalized_subnet):
                if not row_interface:
                    msg = f"No interface mapped to subnet {normalized_subnet}"
                    raise ValueError(msg)
                return DhcpScope(
                    interface=row_interface,
                    subnet=normalized_subnet,
                    description=str(row.get("description") or "") or None,
                )

    msg = f"No DHCP scope found for subnet {normalized_subnet}"
    raise ValueError(msg)


async def resolve_kea_scope(
    make_request: Any,
    *,
    subnet: str | None,
    interface: str | None,
    family: str,
) -> tuple[DhcpScope, dict[str, Any]]:
    """Resolve scope and return the matching Kea subnet row."""
    endpoint = (
        "/api/kea/dhcpv4/search_subnet"
        if family == "ipv4"
        else "/api/kea/dhcpv6/search_subnet"
    )
    resolved_interface: str | None = None
    overview: dict[str, dict[str, Any]] = {}
    if interface:
        overview = await load_interface_overview(make_request)
        resolved_interface = resolve_interface_key(interface, overview)
        if not resolved_interface:
            msg = f"Unknown interface {interface!r}"
            raise ValueError(msg)

    normalized_subnet = normalize_cidr(subnet) if subnet else None
    response = await make_request("GET", endpoint)
    rows = extract_rows(response)

    if normalized_subnet:
        for row in rows:
            row_subnet = str(row.get("subnet") or "").strip()
            if row_subnet and cidr_matches(row_subnet, normalized_subnet):
                return (
                    DhcpScope(
                        interface=resolved_interface or str(row.get("interface") or ""),
                        subnet=normalized_subnet,
                        description=str(row.get("description") or "") or None,
                    ),
                    row,
                )
        msg = f"No Kea {family} subnet found for {normalized_subnet}"
        raise ValueError(msg)

    if resolved_interface is None:
        msg = "interface selector is required when subnet is not provided"
        raise ValueError(msg)
    if not overview:
        overview = await load_interface_overview(make_request)
    iface_subnet = interface_ipv4_network(resolved_interface, overview)
    for row in rows:
        row_interface = str(row.get("interface") or "").strip()
        if row_interface and interface_matches(row_interface, resolved_interface):
            row_subnet = str(row.get("subnet") or "").strip() or iface_subnet
            return (
                DhcpScope(
                    interface=resolved_interface,
                    subnet=row_subnet or None,
                    description=str(row.get("description") or "") or None,
                ),
                row,
            )
        row_subnet = str(row.get("subnet") or "").strip()
        if iface_subnet and row_subnet and cidr_matches(row_subnet, iface_subnet):
            return (
                DhcpScope(
                    interface=resolved_interface,
                    subnet=row_subnet,
                    description=str(row.get("description") or "") or None,
                ),
                row,
            )

    msg = f"No Kea {family} subnet found for interface {resolved_interface}"
    raise ValueError(msg)
