#!/usr/bin/env python3
"""Firewall log parsing and analysis."""

import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class FirewallLogEntry(BaseModel):
    """Model for a single firewall log entry"""

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
    """Summary statistics for firewall logs"""

    total_entries: int
    action_counts: dict[str, int]
    top_source_ips: list[tuple[str, int]]
    top_destination_ips: list[tuple[str, int]]
    top_blocked_ports: list[tuple[int, int]]
    time_range: tuple[datetime, datetime]


class FirewallLogsTool:
    """Tool for retrieving and analyzing firewall logs"""

    def __init__(self, client):
        """Initialize tool with API client."""
        self.client = client
        self._log_cache = None
        self._log_cache_time = 0
        self._log_cache_ttl = 30  # seconds

    async def get_logs(
        self,
        limit: int = 500,
        action: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | None = None,
    ) -> list[FirewallLogEntry]:
        """Retrieve and parse firewall logs with optional filtering"""
        logger.info(
            f"FirewallLogsTool: Getting logs with limit={limit}, "
            f"action={action}, src_ip={src_ip}, dst_ip={dst_ip}, "
            f"protocol={protocol}"
        )

        parsed_logs = []
        try:
            # Get raw logs from OPNsense
            raw_logs = await self.client.get_firewall_logs(limit)
            log_count = len(raw_logs) if raw_logs else 0
            logger.info(f"FirewallLogsTool: Got {log_count} raw logs")

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
                        timestamp=datetime.fromisoformat(log["timestamp"]),
                        interface=log["interface"],
                        action=log["action"].lower(),
                        protocol=log["protocol"].lower(),
                        src_ip=log["src_ip"],
                        src_port=log.get("src_port"),
                        dst_ip=log["dst_ip"],
                        dst_port=log.get("dst_port"),
                        description=log.get("description"),
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
        logger.info(f"FirewallLogsTool: Returning {filtered_count} parsed logs")
        return parsed_logs

    def _parse_log_line(self, line: str) -> FirewallLogEntry | None:
        """Parse a single firewall log line into a structured format"""
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

    def _split_ip_port(self, address: str) -> tuple[str, int | None]:
        """Split an address:port string into separate values"""
        if ":" in address:
            ip, port = address.rsplit(":", 1)
            return ip, int(port)
        return address, None

    async def get_log_summary(self, logs: list[FirewallLogEntry]) -> FirewallLogSummary:
        """Generate a summary of firewall log activity"""
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

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Execute the firewall logs tool with optional parameters.

        Args:
            params: Optional parameters for filtering logs
                - limit: Maximum number of logs to return
                - action: Filter by action (pass, block, reject)
                - src_ip: Filter by source IP
                - dst_ip: Filter by destination IP
                - protocol: Filter by protocol (tcp, udp, icmp)

        Returns:
            Dictionary containing log entries and summary information

        """
        if params is None:
            params = {}

        try:
            # Get firewall logs with optional filters
            logs = await self.get_logs(
                limit=params.get("limit"),
                action=params.get("action"),
                src_ip=params.get("src_ip"),
                dst_ip=params.get("dst_ip"),
                protocol=params.get("protocol"),
            )

            # Generate summary
            summary = await self.get_log_summary(logs)

            # Convert logs to dict format for JSON serialization
            log_entries = []
            for log in logs:
                log_dict = {
                    "timestamp": log.timestamp.isoformat(),
                    "interface": log.interface,
                    "action": log.action,
                    "protocol": log.protocol,
                    "src_ip": log.src_ip,
                    "src_port": log.src_port,
                    "dst_ip": log.dst_ip,
                    "dst_port": log.dst_port,
                    "rule_id": log.rule_id,
                    "description": log.description,
                }
                log_entries.append(log_dict)

            # Convert summary to dict format
            summary_dict = {
                "total_entries": summary.total_entries,
                "action_counts": summary.action_counts,
                "top_source_ips": summary.top_source_ips,
                "top_destination_ips": summary.top_destination_ips,
                "top_blocked_ports": summary.top_blocked_ports,
                "time_range": [
                    summary.time_range[0].isoformat(),
                    summary.time_range[1].isoformat(),
                ],
            }

            return {
                "status": "success",
                "log_entries": log_entries,
                "summary": summary_dict,
                "total_logs": len(log_entries),
            }

        except Exception as e:
            logger.exception("Error executing firewall logs tool")
            return {
                "status": "error",
                "message": str(e),
                "log_entries": [],
                "summary": None,
                "total_logs": 0,
            }
