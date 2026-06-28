"""PF state table and statistics diagnostic tools for OPNsense."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.pf_diagnostics import (
    filter_pf_states,
    normalize_pf_state,
    normalize_pf_states_payload,
    normalize_pf_statistics,
    parse_int,
    summarize_pf_states,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)

_LIMIT_MAX = 5000

_EMPTY_STATES_ENVELOPE: dict[str, Any] = {
    "status": "error",
    "states": [],
    "summary": {},
    "source_shape": None,
    "truncated": False,
    "warnings": [],
    "filters_applied": {},
    "raw_included": False,
}


def _error_envelope(error: str, warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        **_EMPTY_STATES_ENVELOPE,
        "status": "error",
        "error": error,
        "warnings": list(warnings or []),
    }


class PfStatesTool:
    """Retrieve, filter, and summarize active PF connection states."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return filtered PF states with optional summary."""
        params = params or {}

        if not self.client:
            return _error_envelope("No client available")

        raw_limit = params.get("limit", 100)
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return _error_envelope(f"invalid limit: {raw_limit!r}")

        if limit < 1:
            return _error_envelope(f"limit must be >= 1, got {limit}")

        warnings: list[str] = []
        limit_capped = False
        if limit > _LIMIT_MAX:
            limit_capped = True
            warnings.append(f"limit clamped from {limit} to {_LIMIT_MAX}")
            limit = _LIMIT_MAX

        src_ip: str | None = params.get("src_ip") or None
        dst_ip: str | None = params.get("dst_ip") or None
        ip: str | None = params.get("ip") or None
        protocol: str | None = params.get("protocol") or None
        interface: str | None = params.get("interface") or None
        state: str | None = params.get("state") or None
        include_summary = bool(params.get("summary", True))

        src_port_raw = params.get("src_port")
        dst_port_raw = params.get("dst_port")
        src_port = int(src_port_raw) if src_port_raw is not None else None
        dst_port = int(dst_port_raw) if dst_port_raw is not None else None

        try:
            payload = await self.client.get_pf_states(limit)
        except Exception as exc:
            logger.exception("get_pf_states failed")
            return _error_envelope(str(exc), warnings)

        rows, source_shape = normalize_pf_states_payload(payload)
        total_from_api: int | None = None
        if isinstance(payload, dict):
            total_from_api = parse_int(payload.get("total"))

        normalized = [normalize_pf_state(row) for row in rows]

        any_filter = any(
            v is not None
            for v in (
                src_ip,
                dst_ip,
                ip,
                protocol,
                src_port,
                dst_port,
                interface,
                state,
            )
        )
        filtered = (
            filter_pf_states(
                normalized,
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip=ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                interface=interface,
                state=state,
            )
            if any_filter
            else normalized
        )

        output_states = [{k: v for k, v in s.items() if k != "raw"} for s in filtered]

        summary: dict[str, Any] = {}
        if include_summary:
            meta: dict[str, Any] = {}
            try:
                meta = await self.client.get_pf_state_table_meta()
            except Exception:
                warnings.append("state table metadata unavailable")
            table_limit = parse_int(meta.get("limit")) if meta else None
            summary = summarize_pf_states(
                filtered,
                total_states=total_from_api,
                limit=table_limit,
                requested_limit=limit,
            )

        filters_applied: dict[str, Any] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip": ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "interface": interface,
            "state": state,
            "limit": limit,
            "summary": include_summary,
        }
        if limit_capped:
            filters_applied["limit_capped"] = True

        return {
            "status": "success",
            "states": output_states,
            "summary": summary,
            "source_shape": source_shape,
            "truncated": bool(total_from_api is not None and total_from_api > limit),
            "warnings": warnings,
            "filters_applied": filters_applied,
            "raw_included": False,
        }


class PfStatisticsTool:
    """Retrieve and normalize PF firewall statistics and state table pressure."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return PF statistics with state table health."""
        params = params or {}
        include_raw = bool(params.get("include_raw", False))

        if not self.client:
            return {
                "status": "error",
                "error": "No client available",
                "state_table": {},
                "counters": {},
                "health": {},
                "warnings": [],
            }

        try:
            stats_payload = await self.client.get_pf_statistics()
            meta = await self.client.get_pf_state_table_meta()
        except Exception as exc:
            logger.exception("pf statistics fetch failed")
            return {
                "status": "error",
                "error": str(exc),
                "state_table": {},
                "counters": {},
                "health": {},
                "warnings": [],
            }

        normalized = normalize_pf_statistics(stats_payload, state_table_meta=meta)

        result: dict[str, Any] = {
            "status": "success",
            "state_table": normalized["state_table"],
            "counters": normalized["counters"],
            "health": normalized["health"],
            "warnings": normalized["warnings"],
        }
        if include_raw:
            result["raw"] = normalized["raw"]

        return result
