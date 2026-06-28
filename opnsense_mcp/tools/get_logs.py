"""Compatibility shim for the canonical firewall logs tool."""

from __future__ import annotations

from typing import Any

from opnsense_mcp.tools.firewall_logs import FirewallLogsTool as _FirewallLogsTool


class GetLogsTool(_FirewallLogsTool):
    """Backward-compatible name for :class:`FirewallLogsTool`."""

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute canonical log retrieval and add the legacy summary key."""
        result = await super().execute(params or {})
        analysis = result.get("analysis") if isinstance(result, dict) else None
        if isinstance(analysis, dict) and "summary" not in result:
            result["summary"] = {
                "total_entries": analysis.get("total_logs", 0),
                "action_counts": analysis.get("actions", {}),
                "top_source_ips": analysis.get("top_sources", []),
                "top_destination_ips": analysis.get("top_destinations", []),
                "top_blocked_ports": analysis.get("dst_port_counts", {}),
            }
        return result


FirewallLogsTool = GetLogsTool
