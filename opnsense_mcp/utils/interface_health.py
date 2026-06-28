"""Health classification helpers for OPNsense interface rows."""

from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = {"ok": 0, "info": 1, "warning": 2, "critical": 3}
COUNTER_ANOMALY_THRESHOLD = 2**63
ERROR_COUNTER_KEYS = (
    "input errors",
    "output errors",
    "collisions",
    "input queue drops",
    "packets for unknown protocol",
)


def _finding(severity: str, code: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message}


def max_severity(findings: list[dict[str, str]]) -> str:
    """Return highest severity from findings."""
    level = "ok"
    for finding in findings:
        severity = finding.get("severity", "ok")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[level]:
            level = severity
    return level


def parse_counter(value: Any) -> tuple[int | None, list[dict[str, str]]]:
    """Parse an interface counter and flag rollover-like uint64 artifacts."""
    if value in (None, ""):
        return None, [_finding("info", "data_missing", "Counter value is missing")]
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None, [
            _finding("warning", "counter_parse_error", f"Invalid counter: {value}")
        ]
    if parsed < 0:
        return None, [
            _finding("critical", "counter_negative", f"Negative counter: {value}")
        ]
    if parsed >= COUNTER_ANOMALY_THRESHOLD:
        return None, [
            _finding(
                "warning",
                "counter_anomaly",
                f"Rollover-looking counter artifact: {value}",
            )
        ]
    return parsed, []


def parse_link_speed(value: Any) -> int | None:
    """Parse common link-speed values into bits per second."""
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower().replace(" ", "")
    match = re.search(r"(\d+(?:\.\d+)?)([kmgt]?)(?:bit/s|bits/s|b/s|be|b)?", text)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2)
    multiplier = {
        "": 1,
        "k": 1_000,
        "m": 1_000_000,
        "g": 1_000_000_000,
        "t": 1_000_000_000_000,
    }[unit]
    return int(amount * multiplier)


def _is_enabled(row: dict[str, Any]) -> bool:
    enabled = row.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    config = row.get("config")
    if isinstance(config, dict):
        return config.get("enable") == "1"
    return bool(row.get("identifier"))


def _has_ip(row: dict[str, Any]) -> bool:
    return bool(
        row.get("addr4") or row.get("addr6") or row.get("ipv4") or row.get("ipv6")
    )


def classify_interface(
    name: str,
    data: dict[str, Any],
    all_interfaces: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Classify one interface row into a compact health result."""
    findings: list[dict[str, str]] = []
    groups = set(data.get("groups") or [])
    stats = data.get("statistics") if isinstance(data.get("statistics"), dict) else {}
    enabled = _is_enabled(data)
    oper_state = str(data.get("status") or "unknown").lower()
    is_unassigned = not data.get("identifier")
    is_physical = bool(data.get("is_physical"))
    is_l2 = bool(groups & {"bridge", "vlan", "wg", "wireguard", "lagg", "lo"})

    if not enabled or is_unassigned:
        findings.append(
            _finding(
                "info",
                "administratively_inactive",
                "Interface is disabled or unassigned",
            )
        )
    elif oper_state not in {"up", "associated"}:
        findings.append(
            _finding(
                "critical",
                "enabled_interface_down",
                f"Enabled interface is operationally {oper_state}",
            )
        )

    line_rate = parse_link_speed(stats.get("line rate"))
    if enabled and is_physical and line_rate == 0:
        findings.append(
            _finding(
                "critical", "link_speed_zero", "Enabled physical link speed is zero"
            )
        )

    key_counters: dict[str, int | None] = {}
    for key in ERROR_COUNTER_KEYS:
        parsed, counter_findings = parse_counter(stats.get(key))
        key_counters[key.replace(" ", "_")] = parsed
        findings.extend(counter_findings)
        if parsed and parsed > 0:
            findings.append(
                _finding("warning", "counter_nonzero", f"{key} is non-zero: {parsed}")
            )

    vlan = data.get("vlan") if isinstance(data.get("vlan"), dict) else {}
    parent = vlan.get("parent")
    if parent and parent not in all_interfaces:
        findings.append(
            _finding(
                "warning", "vlan_parent_missing", f"VLAN parent {parent} is missing"
            )
        )

    members = data.get("members") if isinstance(data.get("members"), dict) else {}
    down_members = [
        member
        for member in members
        if str(all_interfaces.get(member, {}).get("status", "")).lower() not in {"up"}
    ]
    for member in down_members:
        findings.append(
            _finding("warning", "bridge_member_down", f"Bridge member {member} is down")
        )

    if enabled and not _has_ip(data) and not is_l2 and not is_physical:
        findings.append(
            _finding(
                "warning", "enabled_no_address", "Enabled interface has no IP address"
            )
        )

    if data.get("sfp"):
        findings.append(_finding("info", "sfp_present", "SFP metadata is present"))
    for group in sorted(groups & {"bridge", "vlan", "wireguard", "wg", "lagg", "lo"}):
        findings.append(_finding("info", "notable_group", f"Interface group: {group}"))

    health = max_severity(findings)
    return {
        "name": name,
        "identifier": data.get("identifier"),
        "description": data.get("description"),
        "admin_state": "enabled" if enabled else "disabled",
        "oper_state": oper_state,
        "health": health,
        "health_flags": [finding["code"] for finding in findings],
        "line_rate_bps": line_rate,
        "key_counters": key_counters,
        "relationships": {
            "vlan_parent": parent,
            "vlan_tag": data.get("vlan_tag") or vlan.get("tag"),
            "bridge_members": list(members),
        },
        "findings": findings,
    }


def summarize_interfaces(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize interface health rows by severity."""
    summary = {"total": len(rows), "ok": 0, "info": 0, "warning": 0, "critical": 0}
    for row in rows:
        summary[row.get("health", "ok")] += 1
    return summary


def sort_interface_health(
    rows: list[dict[str, Any]], sort_by: str = "severity"
) -> list[dict[str, Any]]:
    """Sort interface rows using a stable operator-friendly order."""
    if sort_by == "name":
        return sorted(rows, key=lambda row: str(row.get("name") or ""))
    if sort_by == "errors":
        return sorted(
            rows,
            key=lambda row: sum(v or 0 for v in row.get("key_counters", {}).values()),
            reverse=True,
        )
    if sort_by == "traffic":
        return sorted(rows, key=lambda row: row.get("line_rate_bps") or 0, reverse=True)
    return sorted(
        rows,
        key=lambda row: (
            -SEVERITY_ORDER.get(str(row.get("health")), 0),
            str(row.get("name") or ""),
        ),
    )
