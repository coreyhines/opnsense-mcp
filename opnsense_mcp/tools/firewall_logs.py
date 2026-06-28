#!/usr/bin/env python3
"""Firewall logs retrieval and analysis tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.firewall_log_normalize import (
    normalize_log_dict,
    normalize_logs,
    parse_int,
)

logger = logging.getLogger(__name__)


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
            limit: Maximum number of logs to return.
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
                return []

            logs = await self.client.get_firewall_logs(limit=limit)

            filter_src_port = parse_int(src_port)
            filter_dst_port = parse_int(dst_port)

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
                return not (interface and norm.get("interface") != interface)

        except Exception:
            logger.exception("Failed to get firewall logs")
            return []
        else:
            return [log for log in logs if match(log)]

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
        rule_by_uuid: dict[str, dict[str, Any]] = {}
        rule_by_seq: dict[str, dict[str, Any]] = {}
        for rule in rules:
            uuid = rule.get("uuid") or ""
            if uuid:
                rule_by_uuid[uuid] = rule
            seq = str(rule.get("sequence") or "")
            if seq:
                rule_by_seq[seq] = rule

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
                matched_rule: dict[str, Any] | None = None
                confidence: str | None = None
                if rule_id and rule_id in rule_by_uuid:
                    matched_rule = rule_by_uuid[rule_id]
                    confidence = "high"
                elif rule_number and rule_number in rule_by_seq:
                    matched_rule = rule_by_seq[rule_number]
                    confidence = "low"
                if confidence is not None:
                    entry["match_confidence"] = confidence
                if matched_rule is not None:
                    entry["matched_rule"] = matched_rule
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
