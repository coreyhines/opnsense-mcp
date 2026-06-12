"""Pure helpers for DHCP host (reservation) records — no I/O."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

# Fields preserved verbatim when rewriting a host record back to the API.
_PASSTHROUGH_FIELDS = (
    "host",
    "domain",
    "local",
    "cnames",
    "client_id",
    "hwaddr",
    "lease_time",
    "ignore",
    "set_tag",
    "descr",
    "comments",
    "aliases",
)


def parse_ip_field(raw: str) -> tuple[str | None, str | None]:
    """Split a dnsmasq host ``ip`` field into (ipv4, ipv6) parts.

    The field is a comma-joined list; entries containing ':' are IPv6
    (including bare suffixes like '::2'), everything else IPv4.
    """
    ipv4: str | None = None
    ipv6: str | None = None
    for token in str(raw or "").split(","):
        part = token.strip()
        if not part:
            continue
        if ":" in part:
            ipv6 = part
        else:
            ipv4 = part
    return ipv4, ipv6


def format_ip_field(ipv4: str | None, ipv6: str | None) -> str:
    """Join (ipv4, ipv6) back into a dnsmasq ``ip`` field, v4 first."""
    parts = [p for p in (ipv4, ipv6) if p]
    return ",".join(parts)


@dataclass
class DhcpHostRecord:
    """A dnsmasq host reservation, decomposed for editing."""

    uuid: str
    host: str
    ipv4: str | None
    ipv6_suffix: str | None
    hwaddr: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> DhcpHostRecord:
        """Build a record from a ``search_host`` row."""
        ipv4, ipv6 = parse_ip_field(str(row.get("ip") or ""))
        return cls(
            uuid=str(row.get("uuid") or ""),
            host=str(row.get("host") or ""),
            ipv4=ipv4,
            ipv6_suffix=ipv6,
            hwaddr=str(row.get("hwaddr") or "").lower(),
            raw=dict(row),
        )

    def to_summary(self) -> dict[str, Any]:
        """Return a normalized reservation row for MCP list output."""
        return {
            "uuid": self.uuid,
            "host": self.host,
            "descr": str(self.raw.get("descr") or ""),
            "hwaddr": self.hwaddr,
            "client_id": str(self.raw.get("client_id") or ""),
            "ipv4": self.ipv4,
            "ipv6_suffix": self.ipv6_suffix,
            "has_ipv6": bool(self.ipv6_suffix),
            "ip": str(self.raw.get("ip") or ""),
        }


def apply_v4_suffix(current_ipv4: str, target: int | str) -> str:
    """Return a new IPv4 address: replace the last octet (int target) or
    validate a full address (str target) within the current /24-style network.
    """
    base = ipaddress.ip_address(current_ipv4.strip())
    if base.version != 4:
        msg = f"Not an IPv4 address: {current_ipv4!r}"
        raise ValueError(msg)
    if isinstance(target, int) or str(target).isdigit():
        octet = int(target)
        if not 1 <= octet <= 254:
            msg = f"IPv4 host octet out of range (1-254): {octet}"
            raise ValueError(msg)
        prefix = ".".join(current_ipv4.split(".")[:3])
        return f"{prefix}.{octet}"
    candidate = ipaddress.ip_address(str(target).strip())
    if candidate.version != 4:
        msg = f"Expected IPv4 address, got {target!r}"
        raise ValueError(msg)
    return str(candidate)


def apply_v6_suffix(target: int | str) -> str:
    """Return a normalized '::N' IPv6 suffix from an int or string form.

    Integer targets use **decimal** ``::N`` to match dnsmasq host reservations
    (e.g. ``10.0.8.15,::15`` — last octet and suffix align).
    """
    if isinstance(target, int) or str(target).isdigit():
        return f"::{int(target)}"
    raw = str(target).strip()
    if raw.startswith("::0x"):
        return f"::{int(raw[4:], 16)}"
    ipaddress.ip_address(raw)
    if not raw.startswith("::"):
        msg = f"IPv6 reservation must be a '::N' suffix, got {raw!r}"
        raise ValueError(msg)
    return raw


def flatten_host_for_write(
    record: DhcpHostRecord,
    *,
    new_ipv4: str | None,
    new_ipv6: str | None,
) -> dict[str, Any]:
    """Build a flat host payload (inner object for ``{"host": ...}``) preserving
    all original fields and replacing only the ``ip`` field.
    """
    payload: dict[str, Any] = {
        key: str(record.raw.get(key, "") or "") for key in _PASSTHROUGH_FIELDS
    }
    payload["ip"] = format_ip_field(new_ipv4, new_ipv6)
    return payload


def find_ipv4_conflicts(
    *,
    target_ipv4: str,
    moving_uuid: str,
    hosts: list[dict[str, Any]],
    leases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return conflicts for ``target_ipv4``: other reservations or active leases
    already holding the address. The host being moved (``moving_uuid``) is ignored.
    """
    conflicts: list[dict[str, Any]] = []
    for row in hosts:
        if str(row.get("uuid") or "") == moving_uuid:
            continue
        v4, _ = parse_ip_field(str(row.get("ip") or ""))
        if v4 == target_ipv4:
            conflicts.append(
                {
                    "kind": "reservation",
                    "host": str(row.get("host") or ""),
                    "address": target_ipv4,
                    "hwaddr": str(row.get("hwaddr") or ""),
                }
            )
    for lease in leases:
        addr = str(lease.get("address") or lease.get("ip") or "")
        if addr == target_ipv4:
            conflicts.append(
                {
                    "kind": "lease",
                    "address": target_ipv4,
                    "hostname": str(lease.get("hostname") or ""),
                    "hwaddr": str(lease.get("hwaddr") or ""),
                }
            )
    return conflicts
