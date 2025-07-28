"""Interface list management tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class InterfaceListTool:
    """Tool for getting available firewall interface names."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the interface list tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def resolve_logical_name(
        self, logical_name: str, interfaces: dict
    ) -> str | None:
        """
        Resolve a logical interface name (e.g., 'WAN') to the real device name (e.g., 'ax1').
        Matches against 'identifier' and 'description' fields (case-insensitive), preferring enabled interfaces.
        Returns the device name or None if not found.
        """
        import logging

        logical_lc = logical_name.lower()
        logger = logging.getLogger(__name__)
        debug_lines = []
        debug_lines.append(
            f"[DEBUG] Resolving logical name '{logical_name}' (lower: '{logical_lc}') against interfaces:"
        )
        for k, v in interfaces.items():
            debug_lines.append(
                f"[DEBUG] Interface key: {k}, identifier: {v.get('identifier')}, description: {v.get('description')}, enabled: {v.get('enabled')}, device: {v.get('device')}, name: {v.get('name')}"
            )
        print("\n".join(debug_lines))
        logger.warning("\n".join(debug_lines))
        # Prefer enabled interfaces
        candidates = [v for v in interfaces.values() if v.get("enabled")]
        # Match identifier
        for iface in candidates:
            if iface.get("identifier", "").lower() == logical_lc:
                print(f"[DEBUG] Matched by identifier: {iface}")
                logger.warning(f"[DEBUG] Matched by identifier: {iface}")
                return iface.get("device") or iface.get("name")
        # Match description
        for iface in candidates:
            if iface.get("description", "").lower() == logical_lc:
                print(f"[DEBUG] Matched by description: {iface}")
                logger.warning(f"[DEBUG] Matched by description: {iface}")
                return iface.get("device") or iface.get("name")
        # Fallback: match in all interfaces
        for iface in interfaces.values():
            if iface.get("identifier", "").lower() == logical_lc:
                print(f"[DEBUG] Fallback matched by identifier: {iface}")
                logger.warning(f"[DEBUG] Fallback matched by identifier: {iface}")
                return iface.get("device") or iface.get("name")
            if iface.get("description", "").lower() == logical_lc:
                print(f"[DEBUG] Fallback matched by description: {iface}")
                logger.warning(f"[DEBUG] Fallback matched by description: {iface}")
                return iface.get("device") or iface.get("name")
        print(f"[DEBUG] No match found for logical name '{logical_name}'")
        logger.warning(f"[DEBUG] No match found for logical name '{logical_name}'")
        return None

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Get available interface names for firewall rules.

        Args:
            params: Optional execution parameters. If 'resolve' is set, resolve that logical name.

        Returns:
            Dictionary containing interface names and descriptions, and resolved device if requested.

        Note:
            Uses /api/interfaces/overview/export as the primary source. See issue #2 for long-term refactor plan.

        """
        import json
        import os

        try:
            if not self.client:
                return {
                    "interfaces": {},
                    "status": "error",
                    "error": "No client available",
                }
            merged = {}
            try:
                aliases_raw = await self.client._make_request(
                    "GET", "/api/interfaces/overview/export"
                )
                if isinstance(aliases_raw, list):
                    # If the API returns a list, convert to dict by device or identifier
                    for entry in aliases_raw:
                        key = (
                            entry.get("device")
                            or entry.get("identifier")
                            or entry.get("name")
                        )
                        if key:
                            merged[key] = entry
                elif isinstance(aliases_raw, dict):
                    for key, value in aliases_raw.items():
                        merged[key] = value
            except Exception as e:
                logger.error(f"Failed to fetch /api/interfaces/overview/export: {e}")
            # Optionally supplement with ARP/NDP
            try:
                interfaces = await self.client.get_interfaces()
                for entry in interfaces:
                    if entry.get("name") and entry["name"] not in merged:
                        merged[entry["name"]] = entry
            except Exception as e:
                logger.warning(f"Failed to supplement with ARP/NDP: {e}")
            if not merged:
                # Fallback to mock data
                mock_path = os.path.join(
                    os.path.dirname(__file__),
                    "../../examples/mock_data/interfaces.json",
                )
                try:
                    with open(os.path.abspath(mock_path)) as f:
                        data = json.load(f)
                        merged = {
                            e.get("name", ""): e for e in data.get("interfaces", [])
                        }
                except Exception as e:
                    logger.error(f"Failed to load mock data: {e}")
                    merged = {}
            result = {
                "interfaces": merged,
                "total": len(merged),
                "status": "success" if merged else "error",
                "error": None if merged else "No interfaces found",
            }
            # If 'resolve' param is set, resolve logical name
            if params and "resolve" in params:
                resolved = await self.resolve_logical_name(params["resolve"], merged)
                result["resolved_device"] = resolved
            return result
        except Exception as e:
            logger.exception("Failed to get interface list")
            return {"interfaces": {}, "status": "error", "error": str(e)}
