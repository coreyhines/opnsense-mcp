"""Shared helpers for DHCP per-subnet DNS configuration."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Literal

logger = logging.getLogger(__name__)

Family = Literal["ipv4", "ipv6"]
MAX_DNS_SLOTS = 2


@dataclass(frozen=True)
class DhcpScope:
    """Resolved DHCP scope for subnet DNS operations."""

    interface: str
    subnet: str | None = None
    description: str | None = None


@dataclass
class SubnetDnsSnapshot:
    """Stored DNS state for one address family within a scope."""

    family: Family
    servers: list[str]
    backend_payload: dict[str, Any] | None = None


def normalize_family(value: str) -> Family:
    """Normalize and validate an address family string."""
    family = value.strip().lower()
    if family in {"ipv4", "v4", "inet"}:
        return "ipv4"
    if family in {"ipv6", "v6", "inet6"}:
        return "ipv6"
    msg = f"Invalid family {value!r}; expected ipv4 or ipv6"
    raise ValueError(msg)


def validate_address(address: str, family: Family) -> str:
    """Validate an IP address for the requested family."""
    cleaned = address.strip()
    if not cleaned:
        msg = "Empty DNS server address is not allowed"
        raise ValueError(msg)
    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        msg = f"Invalid IP address for {family}: {address!r}"
        raise ValueError(msg) from exc
    if family == "ipv4" and parsed.version != 4:
        msg = f"Expected IPv4 address, got {address!r}"
        raise ValueError(msg)
    if family == "ipv6" and parsed.version != 6:
        msg = f"Expected IPv6 address, got {address!r}"
        raise ValueError(msg)
    return cleaned


def validate_addresses(addresses: list[str], family: Family) -> list[str]:
    """Validate a list of DNS server addresses."""
    if not addresses:
        msg = "At least one DNS server address is required"
        raise ValueError(msg)
    if len(addresses) > MAX_DNS_SLOTS:
        msg = f"At most {MAX_DNS_SLOTS} DNS servers are allowed per family"
        raise ValueError(msg)
    return [validate_address(item, family) for item in addresses]


def parse_dns_server_list(raw: str, family: Family) -> list[str]:
    """Parse a comma-separated DNS server list from backend config."""
    if not raw or not str(raw).strip():
        return []
    servers: list[str] = []
    for part in str(raw).split(","):
        token = part.strip()
        if not token:
            continue
        if family == "ipv6" and token.startswith("[") and token.endswith("]"):
            token = token[1:-1].strip()
        servers.append(validate_address(token, family))
    return servers[:MAX_DNS_SLOTS]


def format_dns_server_list(servers: list[str], family: Family) -> str:
    """Format DNS servers for backend storage."""
    cleaned = validate_addresses(servers, family) if servers else []
    if family == "ipv6":
        return ",".join(f"[{addr}]" for addr in cleaned)
    return ",".join(cleaned)


def merge_slot_update(
    current: list[str],
    *,
    dns_server: str | None = None,
    dns_servers: list[str] | None = None,
    slot: int | None = None,
    family: Family,
) -> list[str]:
    """
    Merge a slot-oriented DNS update into the current server list.

    Single address updates slot 1 by default; pass slot=2 to update secondary.
    """
    if dns_server and dns_servers is not None:
        msg = "Provide either dns_server or dns_servers, not both"
        raise ValueError(msg)
    if dns_server is None and dns_servers is None:
        msg = "Provide dns_server or dns_servers"
        raise ValueError(msg)

    slots: list[str | None] = [
        current[0] if len(current) > 0 else None,
        current[1] if len(current) > 1 else None,
    ]

    if dns_servers is not None:
        if len(dns_servers) == 0:
            msg = "Empty dns_servers list is not allowed"
            raise ValueError(msg)
        validated = validate_addresses(dns_servers, family)
        if len(validated) == 1:
            target = slot or 1
            if target not in (1, 2):
                msg = "slot must be 1 or 2"
                raise ValueError(msg)
            slots[target - 1] = validated[0]
        else:
            slots[0], slots[1] = validated[0], validated[1]
    else:
        if dns_server is None:
            msg = "dns_server or dns_servers is required"
            raise ValueError(msg)
        validated_one = validate_address(dns_server, family)
        target = slot or 1
        if target not in (1, 2):
            msg = "slot must be 1 or 2"
            raise ValueError(msg)
        slots[target - 1] = validated_one

    merged = [item for item in slots if item]
    return validate_addresses(merged, family) if merged else []


def extract_rows(response: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Extract record rows from common OPNsense list responses."""
    if isinstance(response, list):
        return [row for row in response if isinstance(row, dict)]
    if isinstance(response, dict):
        rows = response.get("rows")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def normalize_cidr(value: str) -> str:
    """Return canonical network CIDR notation."""
    network = ipaddress.ip_network(value.strip(), strict=False)
    return f"{network.network_address}/{network.prefixlen}"


def cidr_matches(value: str, target: str) -> bool:
    """Return True when two CIDR strings refer to the same network."""
    try:
        return normalize_cidr(value) == normalize_cidr(target)
    except ValueError:
        return False


def network_contains_ip(cidr: str, ip_value: str) -> bool:
    """Return True when an IP belongs to a CIDR network."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(ip_value.strip())
        return address in network
    except ValueError:
        return False


def unwrap_model_payload(
    response: dict[str, Any] | list[Any],
    *keys: str,
) -> dict[str, Any]:
    """Unwrap nested OPNsense model payloads such as {"option": {...}}."""
    if not isinstance(response, dict):
        return {}
    for key in keys:
        nested = response.get(key)
        if isinstance(nested, dict):
            return nested
    return response


def interface_matches(candidate: str, target: str) -> bool:
    """Compare interface identifiers case-insensitively."""
    return candidate.strip().lower() == target.strip().lower()
