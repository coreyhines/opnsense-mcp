"""Normalize and summarize OPNsense PF diagnostics payloads."""

from __future__ import annotations

from collections import Counter
from typing import Any


def parse_int(value: Any) -> int | None:
    """Parse integer-like API values without raising."""
    if value in (None, "") or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def normalize_pf_states_payload(
    payload: dict[str, Any] | list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    """Extract state rows from known OPNsense response envelopes."""
    if isinstance(payload, list):
        return payload, "list"
    if not isinstance(payload, dict):
        return [], "unknown"
    for key in ("rows", "states", "items", "pf_states"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return rows, key
    return [], "metadata" if {"current", "limit"} & set(payload) else "unknown"


def _sum_pair(value: Any) -> int | None:
    if isinstance(value, list):
        parsed = [parse_int(item) for item in value]
        known = [item for item in parsed if item is not None]
        return sum(known) if known else None
    return parse_int(value)


def normalize_pf_state(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize one PF state row to stable endpoint/counter fields."""
    return {
        "interface": row.get("interface") or row.get("iface"),
        "protocol": str(row.get("proto") or row.get("protocol") or "").lower() or None,
        "ip_protocol": row.get("ipproto"),
        "src": row.get("src_addr") or row.get("src"),
        "src_port": parse_int(row.get("src_port")),
        "dst": row.get("dst_addr") or row.get("dst"),
        "dst_port": parse_int(row.get("dst_port")),
        "direction": row.get("direction"),
        "state": row.get("state"),
        "age": row.get("age"),
        "expires": row.get("expires"),
        "packets": _sum_pair(row.get("pkts") or row.get("packets")),
        "bytes": _sum_pair(row.get("bytes")),
        "rule": row.get("rule"),
        "id": row.get("id"),
        "label": row.get("label"),
        "description": row.get("descr") or row.get("description"),
        "nat": {
            "address": row.get("nat_addr"),
            "port": parse_int(row.get("nat_port")),
        },
        "raw": dict(row),
    }


def filter_pf_states(
    states: list[dict[str, Any]],
    *,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    ip: str | None = None,
    protocol: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    interface: str | None = None,
    state: str | None = None,
) -> list[dict[str, Any]]:
    """Filter normalized PF states with exact endpoint matches."""

    def matches(row: dict[str, Any]) -> bool:
        if src_ip and row.get("src") != src_ip:
            return False
        if dst_ip and row.get("dst") != dst_ip:
            return False
        if ip and row.get("src") != ip and row.get("dst") != ip:
            return False
        if protocol and str(row.get("protocol") or "").lower() != protocol.lower():
            return False
        if src_port is not None and row.get("src_port") != src_port:
            return False
        if dst_port is not None and row.get("dst_port") != dst_port:
            return False
        if interface and str(row.get("interface") or "").lower() != interface.lower():
            return False
        return not (state and state.lower() not in str(row.get("state") or "").lower())

    return [row for row in states if matches(row)]


def summarize_pf_states(
    states: list[dict[str, Any]],
    *,
    total_states: int | None = None,
    limit: int | None = None,
    requested_limit: int | None = None,
) -> dict[str, Any]:
    """Build aggregate counters for normalized PF state rows."""
    total = total_states if total_states is not None else len(states)
    return {
        "total_states": total,
        "returned_states": len(states),
        "truncated": bool(requested_limit and total > requested_limit),
        "by_protocol": dict(
            Counter(row.get("protocol") for row in states if row.get("protocol"))
        ),
        "by_interface": dict(
            Counter(row.get("interface") for row in states if row.get("interface"))
        ),
        "top_sources": Counter(
            row.get("src") for row in states if row.get("src")
        ).most_common(10),
        "top_destinations": Counter(
            row.get("dst") for row in states if row.get("dst")
        ).most_common(10),
        "top_destination_ports": Counter(
            row.get("dst_port") for row in states if row.get("dst_port") is not None
        ).most_common(10),
        "state_table": state_table_health({"current": total, "limit": limit}),
    }


def state_table_health(meta: dict[str, Any]) -> dict[str, Any]:
    """Calculate PF state table health from current/limit metadata."""
    current = parse_int(meta.get("current"))
    limit = parse_int(meta.get("limit"))
    warnings: list[str] = []
    if current is None or not limit:
        return {
            "current": current,
            "limit": limit,
            "usage_percent": None,
            "health": {
                "level": "unknown",
                "warnings": ["state table limit unavailable"],
            },
        }
    usage = current / limit * 100
    level = "critical" if usage >= 95 else "warning" if usage >= 80 else "ok"
    if level != "ok":
        warnings.append(f"state table usage is {usage:.1f}%")
    return {
        "current": current,
        "limit": limit,
        "usage_percent": usage,
        "health": {"level": level, "warnings": warnings},
    }


def normalize_pf_statistics(
    payload: dict[str, Any] | list[Any],
    *,
    state_table_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize PF statistics, falling back to state-table metadata when empty."""
    state_table = state_table_health(state_table_meta or {})
    if payload == []:
        return {
            "state_table": state_table,
            "counters": {},
            "health": state_table["health"],
            "warnings": ["pf_statistics endpoint returned no counter rows"],
            "raw": payload,
        }
    if isinstance(payload, dict):
        return {
            "state_table": state_table,
            "counters": payload.get("counters")
            if isinstance(payload.get("counters"), dict)
            else {},
            "health": state_table["health"],
            "warnings": [],
            "raw": payload,
        }
    return {
        "state_table": state_table,
        "counters": {},
        "health": {
            "level": "unknown",
            "warnings": ["unsupported pf_statistics payload"],
        },
        "warnings": ["unsupported pf_statistics payload"],
        "raw": payload,
    }
