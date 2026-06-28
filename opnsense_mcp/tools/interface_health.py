"""Interface health summary tool for OPNsense."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.utils.interface_health import (
    classify_interface,
    sort_interface_health,
    summarize_interfaces,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient


class InterfaceHealthTool:
    """Summarize interface status, counters, and relationships."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return compact interface health rows."""
        params = params or {}
        if not self.client:
            return {
                "status": "error",
                "error": "No client available",
                "interfaces": [],
                "summary": {},
            }

        source = await InterfaceListTool(self.client).execute({})
        if source.get("status") != "success":
            return {
                "status": "error",
                "error": source.get("error") or "interface_list failed",
                "interfaces": [],
                "summary": {},
            }

        interfaces = source.get("interfaces") or {}
        interface_filter = params.get("interface")
        include_down = bool(params.get("include_down", True))
        include_raw = bool(params.get("include_raw", False))
        warnings_only = bool(params.get("warnings_only", False))
        sort_by = str(params.get("sort_by") or "severity")
        requested_max = int(params.get("max_results", 50) or 50)
        max_results = max(1, min(requested_max, 200))

        rows = [
            classify_interface(name, data, interfaces)
            for name, data in interfaces.items()
            if isinstance(data, dict)
        ]

        if interface_filter:
            needle = str(interface_filter).lower()
            rows = [
                row
                for row in rows
                if needle
                in " ".join(
                    str(row.get(key) or "")
                    for key in ("name", "identifier", "description")
                ).lower()
            ]
        if not include_down:
            rows = [row for row in rows if row.get("oper_state") == "up"]
        if warnings_only:
            rows = [row for row in rows if row.get("health") in {"warning", "critical"}]

        rows = sort_interface_health(rows, sort_by)
        total_after_filter = len(rows)
        returned = rows[:max_results]
        truncated = total_after_filter > len(returned)

        if include_raw:
            for row in returned:
                name = row.get("name")
                row["raw"] = interfaces.get(name) if isinstance(name, str) else None

        return {
            "status": "success",
            "summary": summarize_interfaces(rows),
            "interfaces": returned,
            "total": total_after_filter,
            "truncated": truncated,
            "max_results": max_results,
            "filters_applied": {
                "interface": interface_filter,
                "include_down": include_down,
                "include_raw": include_raw,
                "warnings_only": warnings_only,
                "sort_by": sort_by,
                "max_results": max_results,
            },
        }
