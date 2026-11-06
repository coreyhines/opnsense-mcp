#!/usr/bin/env python3
"""Firewall logs retrieval and analysis tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import FirewallLogsFetchError, OPNsenseClient
from opnsense_mcp.utils.firewall_log_normalize import (
    normalize_log_dict,
    normalize_logs,
    parse_int,
)

logger = logging.getLogger(__name__)

# The log endpoint pages by limit only (no offset/after), so a filtered read
# cannot ask "give me `limit` matching rows". It over-fetches a wider window,
# filters, and truncates to `limit`. The bounds keep a small `limit` from
# under-fetching (floor) without turning a large one into an unbounded read
# (cap) (#64).
FILTER_OVERFETCH_FACTOR = 10
FILTER_OVERFETCH_MIN = 200
FILTER_OVERFETCH_MAX = 2000


def _overfetch_window(limit: int | None) -> int | None:
    """Fetch window for a filtered log read; see the constants above.

    Falsy or negative limits mean "no limit" to the client and pass through
    unchanged, so an unlimited filtered read stays unlimited.
    """
    if not limit or limit < 0:
        return limit
    return min(
        max(limit * FILTER_OVERFETCH_FACTOR, FILTER_OVERFETCH_MIN),
        FILTER_OVERFETCH_MAX,
    )


class FirewallLogsTool:
    """Tool for retrieving and analyzing firewall logs."""

    def __init__(self: "FirewallLogsTool", client: OPNsenseClient | None) -> None:
        """
        Initialize tool with API client.

        Args:
        ----
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def get_firewall_logs(
        self: "FirewallLogsTool",
        limit: int = 50,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | None = None,
        action: str | None = None,
        src_port: int | str | None = None,
        dst_port: int | str | None = None,
        interface: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve firewall logs with optional filtering.

        Args:
        ----
            limit: Maximum number of log entries to return. When any filter
                is active this counts *matching* entries: the endpoint can
                only page by limit, so a wider window is fetched and the
                filtered result truncated back to `limit` (#64).
            src_ip: Filter by source IP address.
            dst_ip: Filter by destination IP address.
            protocol: Filter by protocol (tcp, udp, icmp, etc.).
            action: Filter by action (block, pass, etc.).
            src_port: Filter by source port number.
            dst_port: Filter by destination port number.
            interface: Filter by network interface name.

        Returns:
        -------
            List of firewall log entries (raw rows).

        """
        try:
            if not self.client:
                logger.warning("No client available")
                raise FirewallLogsFetchError("No client available")

            filter_src_port = parse_int(src_port)
            filter_dst_port = parse_int(dst_port)
            filters_active = any(
                (
                    src_ip,
                    dst_ip,
                    protocol,
                    action,
                    filter_src_port is not None,
                    filter_dst_port is not None,
                    interface,
                )
            )
            # Limiting before filtering is what made `limit=50,
            # action=block` report only the matches inside the first 50 raw
            # rows — often far fewer than exist just past the window (#64).
            fetch_limit = _overfetch_window(limit) if filters_active else limit

            logs = await self.client.get_firewall_logs(limit=fetch_limit)
            wanted_devices = await self._devices_for(interface) if interface else set()

            def match(log: dict[str, Any]) -> bool:
                norm = normalize_log_dict(log)
                if src_ip and norm.get("src_ip") != src_ip:
                    return False
                if dst_ip and norm.get("dst_ip") != dst_ip:
                    return False
                if (
                    protocol
                    and (norm.get("protocol") or "").lower() != protocol.lower()
                ):
                    return False
                if action and (norm.get("action") or "").lower() != action.lower():
                    return False
                if (
                    filter_src_port is not None
                    and norm.get("src_port") != filter_src_port
                ):
                    return False
                if (
                    filter_dst_port is not None
                    and norm.get("dst_port") != filter_dst_port
                ):
                    return False
                return not (interface and norm.get("interface") not in wanted_devices)

        except FirewallLogsFetchError:
            raise
        except Exception as exc:
            logger.exception("Failed to get firewall logs")
            raise FirewallLogsFetchError(str(exc)) from exc
        else:
            matched = [log for log in logs if match(log)]
            if filters_active and limit and limit > 0:
                matched = matched[:limit]
            return matched

    async def _devices_for(self: "FirewallLogsTool", name: str) -> set[str]:
        """Device names a caller's interface name can mean.

        filterlog rows carry the device (`vtnet0`, `vlan01`), while callers say
        `wan`, `opt3` or a description such as `VLAN3LAB`. Comparing the two
        unchanged made `interface="wan"` match nothing. The name is kept as-is
        too, so passing a device still works; an unreadable overview degrades
        to that rather than failing the read.
        """
        devices = {name}
        try:
            overview = await self.client._make_request(
                "GET", "/api/interfaces/overview/export"
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Interface overview unavailable for log filter: %s", exc)
            return devices
        wanted = name.strip().lower()
        for entry in overview if isinstance(overview, list) else []:
            if not isinstance(entry, dict) or not entry.get("device"):
                continue
            names = {
                str(entry.get("identifier") or "").lower(),
                str(entry.get("description") or "").lower(),
            }
            if wanted in names - {""}:
                devices.add(str(entry["device"]))
        return devices

    async def get_logs(
        self: "FirewallLogsTool", *args: object, **kwargs: object
    ) -> list[dict[str, object]]:
        """
        Alias for get_firewall_logs for compatibility with tool registry/server.

        Args:
        ----
            *args: Positional arguments passed to get_firewall_logs.
            **kwargs: Keyword arguments passed to get_firewall_logs.

        Returns:
        -------
            List of firewall log entries.

        """
        return await self.get_firewall_logs(*args, **kwargs)

    async def analyze_logs(
        self: "FirewallLogsTool", logs: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Analyze firewall logs and provide statistics.

        Args:
        ----
            logs: List of log entries to analyze.

        Returns:
        -------
            Dictionary containing analysis results.

        """
        if not logs:
            return {
                "total_logs": 0,
                "actions": {},
                "protocols": {},
                "top_sources": [],
                "top_destinations": [],
                "blocked_attempts": 0,
                "src_port_counts": {},
                "dst_port_counts": {},
            }

        actions: dict[str, int] = {}
        protocols: dict[str, int] = {}
        sources: dict[str, int] = {}
        destinations: dict[str, int] = {}
        src_port_counts: dict[int, int] = {}
        dst_port_counts: dict[int, int] = {}
        blocked_count = 0

        for norm in normalize_logs(logs):
            action = norm.get("action") or "unknown"
            actions[action] = actions.get(action, 0) + 1
            if action == "block":
                blocked_count += 1

            protocol = norm.get("protocol") or "unknown"
            protocols[protocol] = protocols.get(protocol, 0) + 1

            src_ip = norm.get("src_ip") or "unknown"
            sources[src_ip] = sources.get(src_ip, 0) + 1

            dst_ip = norm.get("dst_ip") or "unknown"
            destinations[dst_ip] = destinations.get(dst_ip, 0) + 1

            sp = norm.get("src_port")
            if sp is not None:
                src_port_counts[sp] = src_port_counts.get(sp, 0) + 1

            dp = norm.get("dst_port")
            if dp is not None:
                dst_port_counts[dp] = dst_port_counts.get(dp, 0) + 1

        top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]
        top_destinations = sorted(
            destinations.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "total_logs": len(logs),
            "actions": actions,
            "protocols": protocols,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "blocked_attempts": blocked_count,
            "src_port_counts": src_port_counts,
            "dst_port_counts": dst_port_counts,
        }

    def _build_top_rules(
        self: "FirewallLogsTool",
        logs: list[dict[str, Any]],
        rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Build top rule summaries from logs with optional rule correlation.

        Args:
        ----
            logs: Firewall log entries to summarize.
            rules: Firewall rule rows for correlation (may be empty).

        Returns:
        -------
            List of rule summary dicts sorted by hit count descending.

        """
        # Correlate on the rule id only. A log line's rule_number is pf's
        # compiled rule index and MVC `sequence` is an ordering field; the two
        # are unrelated, and matching them attached an arbitrary rule.
        rule_by_uuid: dict[str, dict[str, Any]] = {}
        for rule in rules:
            uuid = rule.get("uuid") or ""
            if uuid:
                rule_by_uuid[uuid] = rule

        buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
        for log in logs:
            norm = normalize_log_dict(log)
            rule_id = norm.get("rule_id") or ""
            rule_number = str(norm.get("rule_number") or "")
            label = norm.get("label") or ""
            key = (rule_id, rule_number, label)

            if key not in buckets:
                entry: dict[str, Any] = {
                    "hit_count": 0,
                    "rule_id": rule_id or None,
                    "rule_number": rule_number or None,
                    "label": label or None,
                }
                if rule_id and rule_id in rule_by_uuid:
                    entry["matched_rule"] = rule_by_uuid[rule_id]
                    entry["match_confidence"] = "high"
                buckets[key] = entry

            buckets[key]["hit_count"] += 1

        sorted_rules = sorted(
            buckets.values(), key=lambda x: x["hit_count"], reverse=True
        )
        return sorted_rules[:10]

    async def execute(
        self: "FirewallLogsTool", params: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Execute firewall logs retrieval and analysis.

        Args:
        ----
            params: Parameters including limit, src_ip, dst_ip, protocol, action.

        Returns:
        -------
            Dictionary containing logs and analysis results.

        """
        try:
            if not self.client:
                return {
                    "logs": [],
                    "analysis": {},
                    "status": "error",
                    "error": "No client available",
                }

            # Extract parameters
            limit = params.get("limit", 50)
            src_ip = params.get("src_ip")
            dst_ip = params.get("dst_ip")
            protocol = params.get("protocol")
            action = params.get("action")
            src_port = params.get("src_port")
            dst_port = params.get("dst_port")
            interface = params.get("interface")
            include_rules = bool(params.get("include_rules", False))
            summary_only = bool(params.get("summary_only", False))

            # Get logs
            try:
                logs = await self.get_firewall_logs(
                    limit=limit,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    action=action,
                    src_port=src_port,
                    dst_port=dst_port,
                    interface=interface,
                )
            except FirewallLogsFetchError as exc:
                return {
                    "logs": [],
                    "analysis": {},
                    "status": "error",
                    "error": str(exc),
                }

            # Opt-in rule lookup — at most one call per execute, never on default path
            rules: list[dict[str, Any]] = []
            rule_lookup_status: str | None = None
            rule_lookup_error: str | None = None
            if include_rules:
                try:
                    rules = await self.client.get_firewall_rules()
                    rule_lookup_status = "ok"
                except Exception as exc:
                    rule_lookup_status = "unavailable"
                    rule_lookup_error = str(exc)
                    logger.warning("Rule lookup failed (non-fatal): %s", exc)

            # Analyze logs
            analysis = await self.analyze_logs(logs)

            # Add rule correlation keys when include_rules is active
            if include_rules:
                analysis["rule_lookup_status"] = rule_lookup_status
                if rule_lookup_error is not None:
                    analysis["rule_lookup_error"] = rule_lookup_error
                analysis["top_rules"] = self._build_top_rules(logs, rules)

            return {
                "logs": [] if summary_only else logs,
                "analysis": analysis,
                "status": "success",
                "total_retrieved": len(logs),
                "filters_applied": {
                    "limit": limit,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "action": action,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "interface": interface,
                },
            }

        except Exception as e:
            logger.exception("Failed to execute firewall logs tool")
            return {"logs": [], "analysis": {}, "status": "error", "error": str(e)}
