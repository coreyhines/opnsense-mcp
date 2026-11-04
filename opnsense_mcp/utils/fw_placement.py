"""Where a written filter rule lands, and whether anything takes its traffic first.

Two writes in agent-fence #4 reported success and did nothing. A block rule was
shadowed by an earlier `quick` pass, and a rule referenced an alias whose table
was still empty because the alias had been staged with `apply=false`. Neither
is visible from the write's own response, so both are checked by re-reading
the ruleset after the write.

Order is taken from the firewall, not derived here. searchRule rows carry
`sort_order` (`<prio_group>.<sequence>`), and pf evaluates rules in that order.
Deriving it is easy to get wrong: a rule on several interfaces is a floating
rule (priority group 200000), so it sorts against floating rules by sequence
and ahead of every single-interface rule (400000), which is not what its
interface field suggests.

Overlap is best effort. Nets are resolved to the live pf table through
`alias_util/list`, which also covers interface and group networks
(`__<name>_network`). Anything that cannot be resolved makes a match
`possible` rather than dropping it: a warning that may be noise is cheaper
than a block rule that silently passes traffic.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

GROUP_SEARCH = "/api/firewall/group/search_item"
ALIAS_TABLE = "/api/firewall/alias_util/list/{name}"
# Enough for any ruleset this tool has met; searchRule pages past it.
ROW_COUNT = 5000
# Shadowing rules listed in full; the rest are counted.
MAX_LISTED = 10

YES, MAYBE, NO = "yes", "maybe", "no"
# Names a pf table can have. `(self)`, `wanip` and the like are not tables.
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_]+$")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes")


def _sort_key(row: dict[str, Any]) -> tuple[int, int] | None:
    """`200000.0000250` as (200000, 250); None when the row carries no order."""
    text = str(row.get("sort_order") or "")
    group, _, seq = text.partition(".")
    try:
        return int(group), int(seq or 0)
    except ValueError:
        return None


def _sequence(row: dict[str, Any]) -> int:
    try:
        return int(str(row.get("sequence") or 0))
    except ValueError:
        return 0


def _tokens(value: Any) -> list[str]:
    return [t.strip() for t in str(value or "").split(",") if t.strip()]


class _NetSpec:
    """A rule side resolved to networks, `all`, or partly unknown."""

    def __init__(self) -> None:
        self.all = False
        self.nets: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self.unknown = False


def _overlap_nets(a: _NetSpec, b: _NetSpec) -> str:
    if a.all and b.all:
        return YES
    if a.all or b.all:
        other = b if a.all else a
        if other.nets:
            return YES
        return MAYBE if other.unknown else NO
    for x in a.nets:
        for y in b.nets:
            if x.version == y.version and x.overlaps(y):
                return YES
    return MAYBE if (a.unknown or b.unknown) else NO


def _port_ranges(
    value: str, port_aliases: dict[str, list[str]]
) -> tuple[bool, list[tuple[int, int]], bool]:
    """(all, ranges, unknown) for a port field."""
    text = str(value or "").strip()
    if text in ("", "any"):
        return True, [], False
    ranges: list[tuple[int, int]] = []
    unknown = False
    pending = _tokens(text)
    seen: set[str] = set()
    while pending:
        item = pending.pop()
        if item in seen:
            continue
        seen.add(item)
        lo, sep, hi = item.replace("-", ":").partition(":")
        try:
            ranges.append((int(lo), int(hi) if sep else int(lo)))
            continue
        except ValueError:
            pass
        if item in port_aliases:
            pending.extend(port_aliases[item])
        else:
            unknown = True
    return False, ranges, unknown


def _overlap_ports(a: str, b: str, port_aliases: dict[str, list[str]]) -> str:
    a_all, a_ranges, a_unknown = _port_ranges(a, port_aliases)
    b_all, b_ranges, b_unknown = _port_ranges(b, port_aliases)
    if a_all or b_all:
        return YES
    for lo1, hi1 in a_ranges:
        for lo2, hi2 in b_ranges:
            if lo1 <= hi2 and lo2 <= hi1:
                return YES
    return MAYBE if (a_unknown or b_unknown) else NO


def _overlap_simple(a: str, b: str, wildcards: tuple[str, ...]) -> str:
    a, b = a.strip().lower(), b.strip().lower()
    if a in wildcards or b in wildcards or a == b:
        return YES
    return NO


def _overlap_ipprotocol(a: str, b: str) -> str:
    def family(v: str) -> set[str]:
        v = v.strip().lower()
        if v in ("", "inet46"):
            return {"inet", "inet6"}
        return {v}

    return YES if family(a) & family(b) else NO


def _overlap_protocol(a: str, b: str) -> str:
    def protos(v: str) -> set[str] | None:
        v = v.strip().lower()
        if v in ("", "any"):
            return None
        return set(v.split("/"))

    pa, pb = protos(a), protos(b)
    if pa is None or pb is None:
        return YES
    return YES if pa & pb else NO


class _Resolver:
    """Caches the lookups one placement check needs."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.groups: dict[str, set[str]] = {}
        self.aliases: dict[str, dict[str, Any]] = {}
        self.tables: dict[str, list[str]] = {}

    async def load(self) -> None:
        data = await self.client._make_request(
            "POST", GROUP_SEARCH, json={"current": 1, "rowCount": 500}
        )
        for row in data.get("rows", []) if isinstance(data, dict) else []:
            members = {m for m in str(row.get("members", "")).split(",") if m}
            self.groups[str(row.get("ifname", ""))] = members
        for row in await self.client.search_aliases():
            self.aliases[str(row.get("name", ""))] = row

    @property
    def port_aliases(self) -> dict[str, list[str]]:
        return {
            name: [
                p
                for p in str(row.get("content", "")).replace("\n", ",").split(",")
                if p
            ]
            for name, row in self.aliases.items()
            if row.get("type") == "port"
        }

    async def _table(self, name: str) -> list[str]:
        """Entries in the live pf table `name`; empty when it has none or is not one."""
        if not _TABLE_NAME.match(name):
            return []
        if name not in self.tables:
            try:
                data = await self.client._make_request(
                    "GET", ALIAS_TABLE.format(name=name)
                )
            except Exception as exc:  # noqa: BLE001 - an unknown net, not a failed check
                logger.debug("alias_util list %s failed: %s", name, exc)
                data = {}
            rows = data.get("rows", []) if isinstance(data, dict) else []
            self.tables[name] = [str(r.get("ip", "")) for r in rows if r.get("ip")]
        return self.tables[name]

    async def resolve_side(self, value: Any, negated: bool) -> _NetSpec:
        spec = _NetSpec()
        tokens = _tokens(value)
        if not tokens or "any" in tokens:
            spec.all = True
        for item in tokens:
            if item == "any":
                continue
            try:
                spec.nets.add(ipaddress.ip_network(item, strict=False))
                continue
            except ValueError:
                pass
            entries: list[str] = []
            if item in self.aliases:
                entries = await self._table(item)
                if not entries and self.aliases[item].get("type") != "internal":
                    # A loaded alias with no entries matches nothing.
                    continue
            if not entries:
                entries = await self._table(f"__{item}_network")
            if not entries:
                spec.unknown = True
                continue
            for entry in entries:
                try:
                    spec.nets.add(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    spec.unknown = True
        if negated:
            # The complement of a set is not worth computing for a warning.
            spec.all, spec.nets, spec.unknown = False, set(), True
        return spec

    def interfaces(self, row: dict[str, Any]) -> set[str] | None:
        """Interface keys a rule applies to; None for every interface."""
        tokens = _tokens(row.get("interface"))
        if not tokens or _truthy(row.get("interfacenot")):
            return None
        keys: set[str] = set()
        for item in tokens:
            keys |= self.groups.get(item, {item})
        return keys


async def _overlaps(
    resolver: _Resolver, ours: dict[str, Any], other: dict[str, Any]
) -> tuple[str, list[str]]:
    """Whether `other` matches some of `ours`'s traffic, and which checks were guesses."""
    checks: dict[str, str] = {}

    a, b = resolver.interfaces(ours), resolver.interfaces(other)
    checks["interface"] = YES if a is None or b is None or a & b else NO
    checks["direction"] = _overlap_simple(
        str(ours.get("direction", "")), str(other.get("direction", "")), ("", "any")
    )
    checks["ipprotocol"] = _overlap_ipprotocol(
        str(ours.get("ipprotocol", "")), str(other.get("ipprotocol", ""))
    )
    checks["protocol"] = _overlap_protocol(
        str(ours.get("protocol", "")), str(other.get("protocol", ""))
    )
    if NO in checks.values():
        return NO, []

    for side in ("source", "destination"):
        mine = await resolver.resolve_side(
            ours.get(f"{side}_net"), _truthy(ours.get(f"{side}_not"))
        )
        theirs = await resolver.resolve_side(
            other.get(f"{side}_net"), _truthy(other.get(f"{side}_not"))
        )
        checks[f"{side}_net"] = _overlap_nets(mine, theirs)
        checks[f"{side}_port"] = _overlap_ports(
            str(ours.get(f"{side}_port", "")),
            str(other.get(f"{side}_port", "")),
            resolver.port_aliases,
        )
        if NO in checks.values():
            return NO, []

    guesses = sorted(k for k, v in checks.items() if v == MAYBE)
    return (MAYBE if guesses else YES), guesses


def _empty_aliases(resolver: _Resolver, row: dict[str, Any]) -> list[dict[str, Any]]:
    """Aliases the rule references whose loaded table holds nothing."""
    found = []
    for field in ("source_net", "source_port", "destination_net", "destination_port"):
        for item in _tokens(row.get(field)):
            alias = resolver.aliases.get(item)
            if alias is None or str(alias.get("current_items", "")) != "0":
                continue
            found.append({"field": field, "name": item, "type": alias.get("type", "")})
    return found


async def check_placement(client: Any, rule_uuid: str) -> dict[str, Any]:
    """Re-read the ruleset and report what runs before `rule_uuid`.

    Never raises: the write it follows has already happened, and a failed
    check must not be reported as a failed write. `ran` says whether it did.
    """
    try:
        data = await client.search_firewall_rules(row_count=ROW_COUNT)
        rows = [r for r in data.get("rows", []) if isinstance(r, dict)]
        ours = next((r for r in rows if r.get("uuid") == rule_uuid), None)
        if ours is None:
            return {"ran": False, "reason": f"rule {rule_uuid} not found on re-read"}
        our_key = _sort_key(ours)
        if our_key is None:
            return {"ran": False, "reason": "searchRule row carries no sort_order"}

        resolver = _Resolver(client)
        await resolver.load()

        shadows: list[dict[str, Any]] = []
        for row in rows:
            key = _sort_key(row)
            if (
                row.get("uuid") == rule_uuid
                or key is None
                or key > our_key
                or not _truthy(row.get("enabled"))
                or not _truthy(row.get("quick"))
            ):
                continue
            verdict, guesses = await _overlaps(resolver, ours, row)
            if verdict == NO:
                continue
            entry: dict[str, Any] = {
                "id": row.get("uuid", ""),
                "sequence": _sequence(row),
                "sort_order": row.get("sort_order", ""),
                "description": row.get("description", ""),
                "action": row.get("action", ""),
                "certainty": "definite" if verdict == YES else "possible",
            }
            if guesses:
                entry["unresolved"] = guesses
            if key == our_key:
                # Equal sort order: pf's order between the two is not defined.
                entry["tie"] = True
            shadows.append(entry)

        shadows.sort(key=lambda e: _sort_key(e) or (0, 0))
        result: dict[str, Any] = {
            "ran": True,
            "sequence": _sequence(ours),
            "sort_order": ours.get("sort_order", ""),
            "shadowed": bool(shadows),
            "shadowed_by": shadows[:MAX_LISTED],
            "empty_aliases": _empty_aliases(resolver, ours),
        }
        if len(shadows) > MAX_LISTED:
            result["shadowed_by_total"] = len(shadows)
    except Exception as exc:  # noqa: BLE001 - reported as ran: False
        logger.warning("Placement check for %s failed: %s", rule_uuid, exc)
        return {"ran": False, "error": str(exc)}
    return result


def placement_warnings(placement: dict[str, Any]) -> list[str]:
    """One line per problem, for callers that read prose before fields."""
    lines = []
    for entry in placement.get("shadowed_by", []):
        lines.append(
            f"{entry['certainty']} shadow: quick {entry['action']} rule "
            f"{entry['id'] or '(automatic)'} at sort order {entry['sort_order']} "
            f"({entry['description'] or 'no description'}) matches first"
        )
    for alias in placement.get("empty_aliases", []):
        lines.append(
            f"{alias['field']} alias {alias['name']} has 0 loaded entries, so the "
            "rule matches nothing there; fw_rule action='apply' loads staged aliases"
        )
    return lines
