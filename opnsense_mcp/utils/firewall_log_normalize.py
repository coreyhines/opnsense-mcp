"""Normalize OPNsense firewall log rows into stable analysis fields."""

from __future__ import annotations

from typing import Any

NORMALIZED_LOG_FIELDS = {
    "timestamp",
    "interface",
    "action",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "rule_id",
    "rule_number",
    "label",
    "raw",
}


def parse_int(value: Any) -> int | None:
    """Parse an integer from API values without raising on blanks or junk."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def first_present(row: dict[str, Any], *keys: str) -> Any:
    """Return the first non-empty value for the requested keys."""
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def normalize_log_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize one OPNsense firewall log row while preserving raw data."""
    protocol = first_present(row, "protocol", "protoname")
    action = first_present(row, "action")
    return {
        "timestamp": first_present(row, "timestamp", "__timestamp__"),
        "interface": first_present(row, "interface", "if", "iface"),
        "action": str(action).lower() if action is not None else None,
        "protocol": str(protocol).lower() if protocol is not None else None,
        "src_ip": first_present(row, "src_ip", "src"),
        "dst_ip": first_present(row, "dst_ip", "dst"),
        "src_port": parse_int(first_present(row, "src_port", "srcport")),
        "dst_port": parse_int(first_present(row, "dst_port", "dstport")),
        "rule_id": first_present(row, "rule_id", "rid"),
        "rule_number": first_present(row, "rule_number", "rulenr"),
        "label": first_present(row, "label", "description", "descr"),
        "raw": dict(row),
    }


def normalize_logs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize a list of firewall log rows."""
    return [normalize_log_dict(row) for row in rows]
