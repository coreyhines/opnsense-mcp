"""Pure helpers for DHCP host (reservation) records — no I/O."""

from __future__ import annotations

import ipaddress  # noqa: F401 # used by later helpers
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
