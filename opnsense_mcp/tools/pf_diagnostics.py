"""PF state table and statistics diagnostic tools for OPNsense."""

from __future__ import annotations

import inspect
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

    name = "pf_states"
    description = "List active PF state table entries with filters and summary"
    input_schema = {
        "properties": {
            "dst_ip": {"optional": True, "type": "string"},
            "dst_port": {"optional": True, "type": "number"},
            "interface": {"optional": True, "type": "string"},
            "ip": {"optional": True, "type": "string"},
            "limit": {"optional": True, "type": "number"},
            "protocol": {"optional": True, "type": "string"},
            "src_ip": {"optional": True, "type": "string"},
            "src_port": {"optional": True, "type": "number"},
            "state": {"optional": True, "type": "string"},
            "summary": {"optional": True, "type": "boolean"},
        },
        "required": [],
        "type": "object",
    }

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
        src_port = parse_int(src_port_raw) if src_port_raw is not None else None
        dst_port = parse_int(dst_port_raw) if dst_port_raw is not None else None
        if src_port_raw is not None and src_port is None:
            return _error_envelope(f"invalid src_port: {src_port_raw!r}")
        if dst_port_raw is not None and dst_port is None:
            return _error_envelope(f"invalid dst_port: {dst_port_raw!r}")

        # Push the most selective literal to the API. `searchPhrase` is a
        # substring match across every column, so it can only ever over-match
        # and the precise filter below still runs. Ports and protocol are not
        # pushed: "80" or "udp" as a substring matches far too much to narrow
        # anything usefully.
        search_phrase = next((v for v in (ip, src_ip, dst_ip, interface) if v), "")

        # Asked rather than discovered by catching TypeError: a TypeError from
        # inside the client is a bug and must surface as itself, and an except
        # handler that re-called the client would sit outside the generic
        # handler below.
        try:
            accepts_phrase = (
                "search_phrase"
                in inspect.signature(self.client.get_pf_states).parameters
            )
        except (TypeError, ValueError):
            accepts_phrase = False

        try:
            payload = (
                await self.client.get_pf_states(limit, search_phrase=search_phrase)
                if accepts_phrase
                else await self.client.get_pf_states(limit)
            )
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

        # Against the rows actually returned, not against the requested limit:
        # what matters is whether the whole result set was examined.
        truncated = bool(total_from_api is not None and total_from_api > len(rows))
        if any_filter and not output_states and truncated:
            # The failure this exists to prevent: an empty list that reads as
            # "no such states" when it means "only part of the table was
            # searched". The plausible answer is the dangerous one.
            warnings.append(
                f"no states matched, but only {len(rows)} of {total_from_api} "
                f"were examined: this is a partial view, not an empty result. "
                f"Raise limit, or narrow the filter so the firewall can apply it."
            )

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
            "truncated": truncated,
            "warnings": warnings,
            "filters_applied": filters_applied,
            "raw_included": False,
        }


class PfStatisticsTool:
    """Retrieve and normalize PF firewall statistics and state table pressure."""

    name = "pf_statistics"
    description = "Show PF statistics and state table pressure"
    input_schema = {
        "properties": {"include_raw": {"optional": True, "type": "boolean"}},
        "required": [],
        "type": "object",
    }

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
