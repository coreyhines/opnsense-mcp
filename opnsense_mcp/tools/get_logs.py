#!/usr/bin/env python3
"""Firewall log parsing and analysis."""

import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class FirewallLogEntry(BaseModel):
    """Model for a single firewall log entry."""

    timestamp: datetime
    interface: str
    action: str
    protocol: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    rule_id: str | None = None
    description: str | None = None


class FirewallLogSummary(BaseModel):
    """Summary statistics for firewall logs."""

    total_entries: int
    action_counts: dict[str, int]
    top_source_ips: list[tuple[str, int]]
    top_destination_ips: list[tuple[str, int]]
    top_blocked_ports: list[tuple[int, int]]
    time_range: tuple[datetime, datetime]


class GetLogsTool:
    """Tool for retrieving and analyzing firewall logs."""

    def __init__(self: "GetLogsTool", client: OPNsenseClient | None) -> None:
        """
        Initialize tool with API client.

        Args:
        ----

            client: OPNsense client instance for API communication.

        """
        self.client = client
        self._log_cache = None
        self._log_cache_time = 0
        self._log_cache_ttl = 30  # seconds

    async def get_logs(
        self: "GetLogsTool",
        limit: int = 500,
        action: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | None = None,
        filter: str | None = None,
    ) -> list[FirewallLogEntry]:
        """
        Retrieve and parse firewall logs with optional filtering.

        Args:
        ----
            limit: Maximum number of logs to return
            action: Filter by action (pass, block, reject)
            src_ip: Filter by source IP
            dst_ip: Filter by destination IP
            protocol: Filter by protocol (tcp, udp, icmp)
            filter: Generic keyword filter

        Returns:
        -------
            List of parsed firewall log entries.

        """
        logger.info(
            f"GetLogsTool: Getting logs with limit={limit}, "
            f"action={action}, src_ip={src_ip}, dst_ip={dst_ip}, "
            f"protocol={protocol}, filter={filter}"
        )

        parsed_logs = []
        try:
            # Get raw logs from OPNsense
            raw_logs = await self.client.get_firewall_logs(limit)
            log_count = len(raw_logs) if raw_logs else 0
            logger.info(f"GetLogsTool: Got {log_count} raw logs")

            if log_count > 0 and not isinstance(raw_logs[0], dict):
                logger.error(
                    f"Invalid log format - expected dict, got {type(raw_logs[0])}"
                )
                return []

            if log_count > 0:
                logger.debug(f"Sample log entry: {raw_logs[0]}")

            # Parse logs into structured format
            for i, log in enumerate(raw_logs):
                try:
                    entry = FirewallLogEntry(
                        timestamp=datetime.fromisoformat(
                            log.get("__timestamp__") or log.get("timestamp")
                        ),
                        interface=log.get("interface", "unknown"),
                        action=log.get("action", "unknown").lower(),
                        protocol=log.get(
                            "protoname", log.get("protocol", "unknown")
                        ).lower(),
                        src_ip=log.get("src", log.get("src_ip", "")),
                        src_port=(
                            int(log["srcport"])
                            if "srcport" in log and log["srcport"]
                            else None
                        ),
                        dst_ip=log.get("dst", log.get("dst_ip", "")),
                        dst_port=(
                            int(log["dstport"])
                            if "dstport" in log and log["dstport"]
                            else None
                        ),
                        description=log.get("label") or log.get("description"),
                        rule_id=log.get("rulenr") or log.get("rule_id"),
                    )
                    logger.debug(f"Successfully parsed JSON log {i}")

                    # Apply filters
                    if action and entry.action != action.lower():
                        logger.debug(
                            f"Filtered out log {i} due to action mismatch: "
                            f"{entry.action} != {action.lower()}"
                        )
                        continue
                    if src_ip and entry.src_ip != src_ip:
                        logger.debug(
                            f"Filtered out log {i} due to src_ip mismatch: "
                            f"{entry.src_ip} != {src_ip}"
                        )
                        continue
                    if dst_ip and entry.dst_ip != dst_ip:
                        logger.debug(
                            f"Filtered out log {i} due to dst_ip mismatch: "
                            f"{entry.dst_ip} != {dst_ip}"
                        )
                        continue
                    if protocol and entry.protocol != protocol.lower():
                        logger.debug(
                            f"Filtered out log {i} due to protocol mismatch: "
                            f"{entry.protocol} != {protocol.lower()}"
                        )
                        continue

                    if filter:
                        # Search in all string values of the log
                        log_values = [str(v).lower() for v in log.values()]
                        if not any(filter.lower() in value for value in log_values):
                            continue

                    parsed_logs.append(entry)
                    logger.debug(
                        f"Added log {i} to results: "
                        f"{entry.src_ip}:{entry.src_port} -> "
                        f"{entry.dst_ip}:{entry.dst_port}"
                    )

                except Exception:
                    logger.exception(f"Failed to parse log entry {i} - {log}")
                    continue

        except Exception:
            logger.exception("Failed to get firewall logs")
            return []

        filtered_count = len(parsed_logs)
        logger.info(f"GetLogsTool: Returning {filtered_count} parsed logs")
        return parsed_logs

    def _parse_log_line(self: "GetLogsTool", line: str) -> FirewallLogEntry | None:
        """Parse a single firewall log line into a structured format."""
        # Example log line format:
        # 2025-05-22T10:15:30 WAN block in tcp 192.168.1.100:12345 ->
        # 8.8.8.8:53 "DNS request blocked"
        try:
            # This is a basic pattern - enhance based on actual log format
            pattern = (
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"  # timestamp
                r"(\w+)\s+"  # interface
                r"(\w+)\s+"  # action
                r"(\w+)\s+"  # direction
                r"(\w+)\s+"  # protocol
                r"([0-9.:]+)\s+->\s+"  # source
                r"([0-9.:]+)"  # destination
                r'(?:\s+"([^"]*)")?'  # optional description
            )
            match = re.match(pattern, line)
            if not match:
                return None

            (
                timestamp_str,
                interface,
                action,
                direction,
                protocol,
                src,
                dst,
                description,
            ) = match.groups()

            # Parse source and destination
            src_ip, src_port = self._split_ip_port(src)
            dst_ip, dst_port = self._split_ip_port(dst)

            return FirewallLogEntry(
                timestamp=datetime.fromisoformat(timestamp_str),
                interface=interface,
                action=action.lower(),
                protocol=protocol.lower(),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                description=description,
            )
        except Exception:
            return None

    def _split_ip_port(self: "GetLogsTool", address: str) -> tuple[str, int | None]:
        """Split an address:port string into separate values."""
        if ":" in address:
            ip, port = address.rsplit(":", 1)
            return ip, int(port)
        return address, None

    async def get_log_summary(
        self: "GetLogsTool", logs: list[FirewallLogEntry]
    ) -> FirewallLogSummary:
        """Generate a summary of firewall log activity."""
        if not logs:
            return FirewallLogSummary(
                total_entries=0,
                action_counts={},
                top_source_ips=[],
                top_destination_ips=[],
                top_blocked_ports=[],
                time_range=(datetime.now(), datetime.now()),
            )

        # Count actions
        action_counts = Counter(entry.action for entry in logs)

        # Count source and destination IPs
        src_ips = Counter(entry.src_ip for entry in logs)
        dst_ips = Counter(entry.dst_ip for entry in logs)

        # Count blocked ports (only for 'block' actions)
        blocked_ports = Counter(
            entry.dst_port
            for entry in logs
            if entry.action == "block" and entry.dst_port is not None
        )

        # Get time range
        timestamps = [entry.timestamp for entry in logs]
        time_range = (min(timestamps), max(timestamps))

        return FirewallLogSummary(
            total_entries=len(logs),
            action_counts=dict(action_counts),
            top_source_ips=src_ips.most_common(10),
            top_destination_ips=dst_ips.most_common(10),
            top_blocked_ports=blocked_ports.most_common(10),
            time_range=time_range,
        )

    async def execute(
        self: "GetLogsTool", params: dict[str, Any] = None
    ) -> dict[str, Any]:
        """
        Execute the firewall logs tool with optional parameters.

        Args:
        ----
            params: Optional parameters for filtering logs
                - limit: Maximum number of logs to return
                - action: Filter by action (pass, block, reject)
                - src_ip: Filter by source IP
                - dst_ip: Filter by destination IP
                - protocol: Filter by protocol (tcp, udp, icmp)
                - filter: Generic keyword filter

        Returns:
        -------
            A dictionary containing the parsed logs and a summary.

        """
        if params is None:
            params = {}

        try:
            # Get logs with specified filters
            logs = await self.get_logs(
                limit=params.get("limit", 500),
                action=params.get("action"),
                src_ip=params.get("src_ip"),
                dst_ip=params.get("dst_ip"),
                protocol=params.get("protocol"),
                filter=params.get("filter"),
            )

            # Get a summary of the logs
            summary = await self.get_log_summary(logs)

            return {
                "logs": [log.model_dump() for log in logs],
                "summary": summary.model_dump(),
                "status": "success",
            }

        except Exception as e:
            logger.exception("Failed to execute firewall logs tool")
            return {"error": f"Failed to execute tool: {e}", "status": "error"}


# Alias for test compatibility
FirewallLogsTool = GetLogsTool
