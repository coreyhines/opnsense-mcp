"""Read-only inventory of address literals contained by an IP prefix."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

ALIASES_SEARCH = "/api/firewall/alias/searchItem"
FILTER_RULES_SEARCH = "/api/firewall/filter/searchRule"
UNBOUND_SEARCH = "/api/unbound/settings/searchHostOverride"
DHCP_HOSTS_SEARCH = "/api/dnsmasq/settings/search_host"

_SEARCH_BODY = {"current": 1, "rowCount": 5000}

Hit = dict[str, str]
Prefix = ipaddress.IPv4Network | ipaddress.IPv6Network


def _rows(response: Any) -> list[dict[str, Any]]:
    """Return mapping rows from an OPNsense search response."""
    if not isinstance(response, dict) or not isinstance(response.get("rows"), list):
        return []
    return [row for row in response["rows"] if isinstance(row, dict)]


def _split_values(value: Any, *, commas: bool = False) -> list[str]:
    """Split a potentially multi-value API field into non-empty candidates."""
    text = str(value or "")
    lines = text.replace(",", "\n").splitlines() if commas else text.splitlines()
    return [line.strip() for line in lines if line.strip()]


def _inside_prefix(value: str, prefix: Prefix) -> tuple[bool, bool]:
    """Return ``(matches, parsed)`` for an address or network candidate."""
    try:
        if "/" in value:
            candidate = ipaddress.ip_network(value, strict=False)
            matches = (
                candidate.version == prefix.version
                and candidate.network_address in prefix
                and candidate.broadcast_address in prefix
            )
        else:
            address = ipaddress.ip_address(value)
            matches = address.version == prefix.version and address in prefix
    except ValueError:
        return False, False
    return matches, True


def _hit(
    source: str,
    row: dict[str, Any],
    *,
    name: str,
    field: str,
    address: str,
) -> Hit:
    """Build the common inventory hit shape."""
    return {
        "source": source,
        "uuid": str(row.get("uuid") or ""),
        "name": name,
        "field": field,
        "address": address,
    }


def _inventory_aliases(response: Any, prefix: Prefix) -> tuple[list[Hit], int]:
    """Inventory address and network members from searchItem alias rows."""
    hits: list[Hit] = []
    skipped = 0
    for row in _rows(response):
        # Current searchItem rows are newline-joined. Commas are also accepted
        # because older OPNsense responses used comma-joined content.
        for value in _split_values(row.get("content"), commas=True):
            matches, parsed = _inside_prefix(value, prefix)
            if not parsed:
                skipped += 1
            elif matches:
                hits.append(
                    _hit(
                        "firewall_alias",
                        row,
                        name=str(row.get("name") or ""),
                        field="content",
                        address=value,
                    )
                )
    return hits, skipped


def _inventory_filter_rules(response: Any, prefix: Prefix) -> tuple[list[Hit], int]:
    """Inventory literal source and destination values from searchRule rows."""
    hits: list[Hit] = []
    skipped = 0
    for row in _rows(response):
        for field in ("source_net", "destination_net"):
            # Comma-joined here too: a single rule commonly carries
            # "fe80::/10,ff02::/16" or "fd00::/8,fe80::/10,::/128". Splitting
            # on newlines alone made each of those one unparseable blob, so a
            # rule literally containing the queried prefix was counted as a
            # skip. The ULA-era shape is exactly the one that was missed.
            for value in _split_values(row.get(field), commas=True):
                matches, parsed = _inside_prefix(value, prefix)
                if not parsed:
                    # This includes ``any`` and alias names. The alias sweep
                    # reports alias members without pretending a rule reference
                    # itself is an address literal.
                    skipped += 1
                elif matches:
                    hits.append(
                        _hit(
                            "filter_rule",
                            row,
                            name=str(row.get("description") or ""),
                            field=field,
                            address=value,
                        )
                    )
    return hits, skipped


def _inventory_unbound(response: Any, prefix: Prefix) -> tuple[list[Hit], int]:
    """Inventory server literals from searchHostOverride rows."""
    hits: list[Hit] = []
    skipped = 0
    for row in _rows(response):
        for value in _split_values(row.get("server")):
            matches, parsed = _inside_prefix(value, prefix)
            if not parsed:
                skipped += 1
            elif matches:
                hostname = str(row.get("hostname") or "")
                domain = str(row.get("domain") or "")
                hits.append(
                    _hit(
                        "unbound_host_override",
                        row,
                        name=f"{hostname}.{domain}".strip("."),
                        field="server",
                        address=value,
                    )
                )
    return hits, skipped


def _is_v6_suffix(value: str) -> bool:
    """Whether a reservation's v6 half is a prefix-relative suffix.

    dnsmasq stores these as `::2`, `::254` -- an interface identifier the
    served prefix is prepended to, which is what the `dhcp create_host`
    schema means by "IPv6 suffix". They parse cleanly as absolute addresses
    in `::/128`, so they used to satisfy `parsed` and fail `matches`, landing
    in neither counter: 94 reservations vanished from a sweep that reported
    itself complete.

    They are reported separately rather than as hits because they are the one
    thing a prefix migration does not have to touch -- the suffix follows
    whatever the interface serves.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 6 and address in ipaddress.ip_network("::/64")


def _inventory_dhcp_hosts(
    response: Any, prefix: Prefix
) -> tuple[list[Hit], int, list[dict[str, str]]]:
    """Inventory dnsmasq search_host rows, separating prefix-relative suffixes."""
    hits: list[Hit] = []
    skipped = 0
    suffixes: list[dict[str, str]] = []
    for row in _rows(response):
        for value in _split_values(row.get("ip"), commas=True):
            if _is_v6_suffix(value):
                suffixes.append(
                    {
                        "uuid": str(row.get("uuid") or ""),
                        "name": str(row.get("host") or ""),
                        "suffix": value,
                    }
                )
                continue
            matches, parsed = _inside_prefix(value, prefix)
            if not parsed:
                skipped += 1
            elif matches:
                hits.append(
                    _hit(
                        "dhcp_reservation",
                        row,
                        name=str(row.get("host") or ""),
                        field="ip",
                        address=value,
                    )
                )
            else:
                # Parsed, outside the prefix, not a suffix. Counted, because a
                # value that lands in no bucket is how the reservations went
                # missing.
                skipped += 1
    return hits, skipped, suffixes


def _combine_inventory(
    inventories: Iterable[tuple[list[Hit], int]],
) -> tuple[list[Hit], int]:
    """Combine per-source hits and skipped counts."""
    hits: list[Hit] = []
    skipped = 0
    for source_hits, source_skipped in inventories:
        hits.extend(source_hits)
        skipped += source_skipped
    return hits, skipped


class InventoryPrefixTool:
    """Find address literals from a prefix across relevant OPNsense config."""

    name = "inventory_prefix"
    description = (
        "Read-only inventory of address literals within a prefix across firewall "
        "aliases, filter rules, Unbound host overrides, and DHCP reservations"
    )
    input_schema = {
        "type": "object",
        "properties": {
            "prefix": {
                "type": "string",
                "description": "IPv4 or IPv6 prefix to inventory",
            }
        },
        "required": ["prefix"],
    }

    def __init__(self, client: Any) -> None:
        """Store the OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the read-only prefix inventory."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        try:
            prefix = ipaddress.ip_network(str(params.get("prefix") or ""), strict=False)
        except ValueError as exc:
            return {"status": "error", "error": f"invalid prefix: {exc}"}

        try:
            aliases, rules, unbound, dhcp_hosts = await asyncio.gather(
                self.client._make_request(
                    "POST", ALIASES_SEARCH, json={**_SEARCH_BODY, "searchPhrase": ""}
                ),
                self.client._make_request(
                    "POST", FILTER_RULES_SEARCH, json=_SEARCH_BODY
                ),
                self.client._make_request("POST", UNBOUND_SEARCH, json=_SEARCH_BODY),
                self.client._make_request(
                    "POST", DHCP_HOSTS_SEARCH, json={**_SEARCH_BODY, "searchPhrase": ""}
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to inventory prefix")
            return {"status": "error", "error": str(exc)}

        dhcp_hits, dhcp_skipped, suffixes = _inventory_dhcp_hosts(dhcp_hosts, prefix)
        hits, skipped = _combine_inventory(
            (
                _inventory_aliases(aliases, prefix),
                _inventory_filter_rules(rules, prefix),
                _inventory_unbound(unbound, prefix),
                (dhcp_hits, dhcp_skipped),
            )
        )
        return {
            "status": "success",
            "prefix": str(prefix),
            "count": len(hits),
            "skipped_count": skipped,
            # Reservations whose v6 half is a prefix-relative suffix. Not hits:
            # they follow whatever prefix the interface serves, so a migration
            # does not rewrite them. Reported because they were previously
            # counted nowhere at all.
            "suffix_count": len(suffixes),
            "suffixes": suffixes,
            "hits": hits,
        }
