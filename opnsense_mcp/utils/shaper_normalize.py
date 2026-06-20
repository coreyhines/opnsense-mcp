"""Normalize OPNsense trafficshaper API payloads to flat agent-view dicts.

Handles both formats returned by the OPNsense API:
- ``search_*`` rows: flat fields (strings/ints, booleans as "0"/"1")
- ``settings/get`` ts tree: GUI enum objects ``{key: {selected: 0|1, value: "..."}}``

No I/O; no OPNsense API calls.
"""

from __future__ import annotations

from typing import Any

from opnsense_mcp.utils.shaper_types import (
    FlatShaperPipe,
    FlatShaperQueue,
    FlatShaperRule,
)


def parse_boolish(val: Any) -> bool:
    """Coerce OPNsense boolish values (``"0"``/``"1"``, bool, int) to ``bool``."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in {"1", "true"}
    return False


def selected_enum(field: dict[str, Any]) -> str:
    """Return the key whose ``selected`` value is truthy; ``""`` if none."""
    for key, meta in field.items():
        if isinstance(meta, dict) and parse_boolish(meta.get("selected")):
            return key
    return ""


def selected_bandwidth_metric(field: Any) -> str:
    """Extract bandwidth metric from GUI enum dict or return string directly."""
    if isinstance(field, str):
        return field
    return selected_enum(field)


def _parse_optional_int(val: Any) -> int | None:
    """Return ``int(val)`` when *val* is non-empty, else ``None``."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _parse_required_int(val: Any, default: int = 0) -> int:
    """Return ``int(val)`` for required numeric fields; *default* when empty/invalid."""
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _resolve_str_or_enum(val: Any) -> str:
    """Return *val* as-is when it is a string, or resolve GUI enum dict."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return selected_enum(val)
    return ""


def _resolve_optional_str(val: Any) -> str | None:
    """Return ``None`` for empty/missing strings; otherwise the string value."""
    result = _resolve_str_or_enum(val) if not isinstance(val, str) else val
    return result if result else None


def normalize_pipe(row: dict[str, Any]) -> FlatShaperPipe:
    """Normalize one pipe row (search or settings/get format) to :class:`FlatShaperPipe`."""
    return FlatShaperPipe(
        uuid=row.get("uuid", ""),
        number=str(row.get("queue", "")),
        description=row.get("description", ""),
        enabled=parse_boolish(row.get("enabled", "0")),
        bandwidth=_parse_required_int(row.get("bandwidth")),
        bandwidth_metric=selected_bandwidth_metric(row.get("bandwidthMetric", "")),
        scheduler=_resolve_str_or_enum(row.get("scheduler", "")),
        mask=_resolve_str_or_enum(row.get("mask", "")),
        codel_enable=parse_boolish(row.get("codel_enable", "0")),
        codel_target_ms=_parse_optional_int(row.get("codel_target", "")),
        codel_interval_ms=_parse_optional_int(row.get("codel_interval", "")),
        codel_ecn_enable=parse_boolish(row.get("codel_ecn_enable", "0")),
        fqcodel_quantum=_parse_optional_int(row.get("fqcodel_quantum", "")),
        fqcodel_limit=_parse_optional_int(row.get("fqcodel_limit", "")),
        fqcodel_flows=_parse_optional_int(row.get("fqcodel_flows", "")),
        pie_enable=parse_boolish(row.get("pie_enable", "0")),
    )


def normalize_queue(row: dict[str, Any]) -> FlatShaperQueue:
    """Normalize one queue row (search or settings/get format) to :class:`FlatShaperQueue`."""
    return FlatShaperQueue(
        uuid=row.get("uuid", ""),
        description=row.get("description", ""),
        enabled=parse_boolish(row.get("enabled", "0")),
        pipe_uuid=_resolve_str_or_enum(row.get("pipe", "")),
        weight=_parse_required_int(row.get("weight")),
        mask=_resolve_str_or_enum(row.get("mask", "")),
        codel_enable=parse_boolish(row.get("codel_enable", "0")),
        codel_target_ms=_parse_optional_int(row.get("codel_target", "")),
        codel_interval_ms=_parse_optional_int(row.get("codel_interval", "")),
        codel_ecn_enable=parse_boolish(row.get("codel_ecn_enable", "0")),
        pie_enable=parse_boolish(row.get("pie_enable", "0")),
    )


def normalize_rule(row: dict[str, Any]) -> FlatShaperRule:
    """Normalize one rule row (search or settings/get format) to :class:`FlatShaperRule`."""
    interface2_raw = row.get("interface2", "")
    dscp_raw = row.get("dscp", "")

    return FlatShaperRule(
        uuid=row.get("uuid", ""),
        description=row.get("description", ""),
        enabled=parse_boolish(row.get("enabled", "0")),
        interface=_resolve_str_or_enum(row.get("interface", "")),
        interface2=_resolve_optional_str(interface2_raw)
        if not isinstance(interface2_raw, dict)
        else (selected_enum(interface2_raw) or None),
        direction=_resolve_str_or_enum(row.get("direction", "")),
        proto=_resolve_str_or_enum(row.get("proto", "")),
        source=row.get("source", "any"),
        source_port=_resolve_optional_str(row.get("source_port", "")),
        destination=row.get("destination", "any"),
        destination_port=_resolve_optional_str(row.get("destination_port", "")),
        dscp=_resolve_optional_str(dscp_raw)
        if not isinstance(dscp_raw, dict)
        else (selected_enum(dscp_raw) or None),
        target_uuid=_resolve_str_or_enum(row.get("target", "")),
        sequence=_parse_required_int(row.get("sequence")),
    )


def pipes_from_settings_get(ts: dict[str, Any]) -> list[FlatShaperPipe]:
    """Extract and normalize all pipes from a ``settings/get`` ts tree."""
    return [
        normalize_pipe({"uuid": uuid, **fields})
        for uuid, fields in ts.get("pipes", {}).items()
    ]


def queues_from_settings_get(ts: dict[str, Any]) -> list[FlatShaperQueue]:
    """Extract and normalize all queues from a ``settings/get`` ts tree."""
    return [
        normalize_queue({"uuid": uuid, **fields})
        for uuid, fields in ts.get("queues", {}).items()
    ]


def rules_from_settings_get(ts: dict[str, Any]) -> list[FlatShaperRule]:
    """Extract and normalize all rules from a ``settings/get`` ts tree."""
    return [
        normalize_rule({"uuid": uuid, **fields})
        for uuid, fields in ts.get("rules", {}).items()
    ]
