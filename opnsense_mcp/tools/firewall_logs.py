#!/usr/bin/env python3
"""Firewall logs retrieval and analysis tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

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

        Returns:
        -------
            List of firewall log entries.

        """
        try:
            if not self.client:
                logger.warning("No client available")
                return []

            # Get logs from the API
            logs = await self.client.get_firewall_logs(
                limit=limit,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                action=action,
            )

        except Exception:
            logger.exception("Failed to get firewall logs")
            return []
        else:
            return logs if logs else []

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
            }

        # Count actions
        actions = {}
        protocols = {}
        sources = {}
        destinations = {}
        blocked_count = 0

        for log in logs:
            # Count actions
            action = log.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1

            if action == "block":
                blocked_count += 1

            # Count protocols
            protocol = log.get("protocol", "unknown")
            protocols[protocol] = protocols.get(protocol, 0) + 1

            # Count sources
            src_ip = log.get("src_ip", "unknown")
            sources[src_ip] = sources.get(src_ip, 0) + 1

            # Count destinations
            dst_ip = log.get("dst_ip", "unknown")
            destinations[dst_ip] = destinations.get(dst_ip, 0) + 1

        # Get top 10 sources and destinations
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
        }

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

            # Get logs
            logs = await self.get_firewall_logs(
                limit=limit,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                action=action,
            )

            # Analyze logs
            analysis = await self.analyze_logs(logs)

            return {
                "logs": logs,
                "analysis": analysis,
                "status": "success",
                "total_retrieved": len(logs),
                "filters_applied": {
                    "limit": limit,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "action": action,
                },
            }

        except Exception as e:
            logger.exception("Failed to execute firewall logs tool")
            return {"logs": [], "analysis": {}, "status": "error", "error": str(e)}
