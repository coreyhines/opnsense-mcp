#!/usr/bin/env python3
"""
Firewall tool for OPNsense MCP server.

This module provides firewall management capabilities including
rule retrieval, log filtering, and network analysis.
"""

import ipaddress
import sys
import time
from typing import Any

from pydantic import BaseModel


class FirewallEndpoint(BaseModel):
    """Model for firewall rule endpoint (source/destination)."""

    net: str
    port: str


class FirewallRule(BaseModel):
    """Model for firewall rule data."""

    id: str
    sequence: int
    description: str
    interface: str
    protocol: str
    source: FirewallEndpoint
    destination: FirewallEndpoint
    action: str
    enabled: bool
    gateway: str = ""
    direction: str = "in"
    ipprotocol: str = "inet"


class FirewallTool:
    """Tool for managing OPNsense firewall rules and logs."""

    def __init__(self, client: Any) -> None:
        """Initialize the FirewallTool with an OPNsense client."""
        self.client = client
        self._log_cache = None
        self._log_cache_time = 0
        self._log_cache_ttl = 90  # seconds

    async def _resolve_interface_name(self, iface_query: str) -> str:
        """
        Recursively resolve any user-supplied interface name.

        Resolve any user-supplied interface name, alias, or
        display name to the real interface name.
        """
        try:
            iface_map = await self.client.get_interfaces()
            if not isinstance(iface_map, dict):
                return iface_query
            # Direct match to real name
            if iface_query in iface_map:
                return iface_query
            # Direct match to display/alias name
            for real, display in iface_map.items():
                if iface_query == display:
                    # Recurse in case display is itself an alias for another real name
                    return await self._resolve_interface_name(real)
        except Exception:
            return iface_query
        else:
            # No match found, return as is
            return iface_query

    async def _get_cached_logs(self, refresh: bool = False) -> list[dict[str, Any]]:
        """Get cached firewall logs with optional refresh."""
        now = time.time()
        if (
            not refresh
            and self._log_cache is not None
            and (now - self._log_cache_time) < self._log_cache_ttl
        ):
            return self._log_cache
        logs = await self.client.get_firewall_logs()
        self._log_cache = logs
        self._log_cache_time = now
        return logs

    async def execute(self, params: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        """
        Filter firewall logs by criteria.

        Production: Filter firewall logs by IP, MAC, hostname, subnet,
        interface (with recursion), rule UUID, or label.
        """
        try:
            refresh = params.get("refresh", False)
            # If logs requested (no filters), return the first 500 logs
            # for inspection
            if params and params.get("logs") is True and len(params) == 1:
                logs = await self._get_cached_logs(refresh=refresh)
                return {"logs": logs[:500], "status": "success"}
            # Log filtering by criteria
            if params:
                log_filters = [
                    "log_search_ip",
                    "log_search_mac",
                    "log_search_hostname",
                    "log_search_subnet",
                    "log_search_interface",
                    "log_search_rid",
                    "log_search_label",
                ]
                if any(k in params for k in log_filters):
                    logs = await self._get_cached_logs(refresh=refresh)
                    iface_real = None
                    if params.get("log_search_interface"):
                        iface_query = params["log_search_interface"]
                        iface_real = await self._resolve_interface_name(iface_query)
                    filtered = []
                    for log in logs:
                        match = False
                        # IP match
                        if params.get("log_search_ip"):
                            if params["log_search_ip"] in (
                                log.get("src", ""),
                                log.get("dst", ""),
                            ):
                                match = True
                        # MAC match
                        if params.get("log_search_mac"):
                            if params["log_search_mac"] in (
                                log.get("src_mac", ""),
                                log.get("dst_mac", ""),
                            ):
                                match = True
                        # Hostname match
                        if params.get("log_search_hostname"):
                            if params["log_search_hostname"] in (
                                log.get("src_hostname", ""),
                                log.get("dst_hostname", ""),
                            ):
                                match = True
                        # Subnet (CIDR) match
                        if params.get("log_search_subnet"):
                            try:
                                net = ipaddress.ip_network(
                                    params["log_search_subnet"], strict=False
                                )
                                src_ip = log.get("src", "")
                                dst_ip = log.get("dst", "")
                                src_match = False
                                dst_match = False
                                try:
                                    if src_ip:
                                        src_match = ipaddress.ip_address(src_ip) in net
                                except Exception as e:
                                    print(
                                        f"[DEBUG] Subnet filter: src_ip parse error: "
                                        f"{src_ip} ({e})",
                                        file=sys.stderr,
                                    )
                                try:
                                    if dst_ip:
                                        dst_match = ipaddress.ip_address(dst_ip) in net
                                except Exception as e:
                                    print(
                                        f"[DEBUG] Subnet filter: dst_ip parse "
                                        f"error: {dst_ip} ({e})",
                                        file=sys.stderr,
                                    )
                                if src_match or dst_match:
                                    match = True
                                print(
                                    f"[DEBUG] Subnet filter: src={src_ip}, "
                                    f"dst={dst_ip}, subnet={net}, "
                                    f"src_match={src_match}, "
                                    f"dst_match={dst_match}, match={match}",
                                    file=sys.stderr,
                                )
                            except Exception as e:
                                print(
                                    f"[DEBUG] Subnet filter: net parse error: "
                                    f"{params['log_search_subnet']} ({e})",
                                    file=sys.stderr,
                                )
                        # Interface match (resolved)
                        if iface_real and log.get("interface") == iface_real:
                            match = True
                        # Rule UUID match
                        if (
                            params.get("log_search_rid")
                            and log.get("rid") == params["log_search_rid"]
                        ):
                            match = True
                        # Label/description match
                        if params.get("log_search_label") and params[
                            "log_search_label"
                        ] in log.get("label", ""):
                            match = True
                        if match:
                            filtered.append(log)
                    return {"logs": filtered, "status": "success"}
            if params and "log_search_ip" in params:
                logs = await self.client.search_firewall_logs(params["log_search_ip"])
                return {"logs": logs, "status": "success"}
            # Default: get rules
            rules = await self.client.get_firewall_rules()
            return {
                "rules": [FirewallRule(**rule).model_dump() for rule in rules],
                "status": "success",
            }
        except Exception as e:
            raise RuntimeError(f"Failed to get firewall rules or logs: {e}") from e
