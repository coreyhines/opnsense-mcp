"""Classify which daemon actually serves IPv6 router advertisements per interface.

Pure logic: no HTTP, no client, no I/O. Callers (bucket B4) fetch radvd
``search_entry`` rows, dnsmasq ``search_range`` rows, and optional interface
admin-up maps, then pass them here.

On OPNsense, either **radvd** or **dnsmasq** (v6 range with ``constructor``)
can advertise. Tools that write radvd unconditionally can report success while
changing config nothing reads — this classifier is the guard against that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RaDaemon = Literal["dnsmasq", "radvd", "both", "none"]
RaSeverity = Literal["ok", "warning", "info"]

DAEMON_DNSMASQ: RaDaemon = "dnsmasq"
DAEMON_RADVD: RaDaemon = "radvd"
DAEMON_BOTH: RaDaemon = "both"
DAEMON_NONE: RaDaemon = "none"

# Machine-readable reason codes — assert on these, not on ``reason`` wording.
REASON_DNSMASQ_SERVING = "dnsmasq_serving"
REASON_RADVD_SERVING = "radvd_serving"
REASON_BOTH_SERVING = "both_serving"
REASON_NEITHER = "neither_serving"
REASON_RADVD_DISABLED = "radvd_disabled"
REASON_RADVD_INTERFACE_DOWN = "radvd_interface_down"
REASON_RADVD_INTERFACE_STATE_UNKNOWN = "radvd_interface_state_unknown"
REASON_DNSMASQ_NOT_SERVING = "dnsmasq_not_serving"

# ``False`` is handled via ``is False`` in ``_radvd_enabled`` (``0 == False``).
_RADVD_DISABLED_VALUES: tuple[Any, ...] = (None, "", "0", 0)
_OFF_LINK = "off-link"

_REASON_MESSAGES: dict[str, str] = {
    REASON_DNSMASQ_SERVING: (
        "dnsmasq serves RA (v6 range with constructor and ra_mode not off-link)"
    ),
    REASON_RADVD_SERVING: "radvd is enabled and the interface is administratively up",
    REASON_BOTH_SERVING: (
        "both radvd and dnsmasq appear to serve RA; refuse writes until one is disabled"
    ),
    REASON_NEITHER: "neither radvd nor dnsmasq is serving RA on this interface",
    REASON_RADVD_DISABLED: "radvd entry is disabled or unset",
    REASON_RADVD_INTERFACE_DOWN: (
        "radvd is enabled but the interface is administratively down"
    ),
    REASON_RADVD_INTERFACE_STATE_UNKNOWN: (
        "radvd is enabled but interface admin state was not provided; "
        "not treating radvd as serving"
    ),
    REASON_DNSMASQ_NOT_SERVING: (
        "no dnsmasq v6 range with non-empty constructor and ra_mode not off-link"
    ),
}


@dataclass(frozen=True)
class RaVerdict:
    """Per-interface verdict for which RA daemon is actually serving.

    Severity and daemon live in the payload so callers can refuse a write
    without raising. ``reason_codes`` are for tests and structured callers;
    ``reason`` is the human-readable join of those codes.
    """

    daemon: RaDaemon
    reason_codes: tuple[str, ...]
    reason: str
    radvd_serving: bool
    dnsmasq_serving: bool
    interface_up: bool | None
    severity: RaSeverity


def _iface_id(value: Any) -> str:
    """Normalize an interface id from a row field."""
    if value is None:
        return ""
    return str(value).strip()


def _radvd_enabled(row: dict[str, Any]) -> bool:
    """Return whether a radvd search row is enabled and therefore eligible."""
    enabled = row.get("enabled")
    # ``is False`` keeps the bool case explicit; ``0`` is in the disabled tuple.
    return not (enabled is False or enabled in _RADVD_DISABLED_VALUES)


def _is_v6_range(row: dict[str, Any]) -> bool:
    """Identify a v6 range solely by ``start_addr`` beginning with ``::``."""
    start = row.get("start_addr")
    if start is None:
        return False
    return str(start).startswith("::")


def _dnsmasq_serves_ra(row: dict[str, Any]) -> bool:
    """Return whether a dnsmasq range row is actively serving RA."""
    if not _is_v6_range(row):
        return False
    constructor = _iface_id(row.get("constructor"))
    if not constructor:
        return False
    ra_mode = str(row.get("ra_mode") or "").strip()
    return ra_mode != _OFF_LINK


def _dnsmasq_interface(row: dict[str, Any]) -> str:
    """Interface id the range advertises on (constructor names the prefix source).

    Prefer the range ``interface`` field; fall back to ``constructor`` when the
    interface column is empty so constructor-only rows still classify.
    """
    iface = _iface_id(row.get("interface"))
    if iface:
        return iface
    return _iface_id(row.get("constructor"))


def _interface_up(
    iface: str,
    interface_states: dict[str, bool] | None,
) -> bool | None:
    """Resolve admin-up for ``iface``.

    ``None`` means state was not provided (whole map missing or key absent) —
    callers must not treat that as up.
    """
    if interface_states is None:
        return None
    if iface not in interface_states:
        return None
    return bool(interface_states[iface])


def _radvd_serving(
    enabled: bool,
    interface_up: bool | None,
) -> tuple[bool, list[str]]:
    """Decide whether radvd counts as serving; return serving flag and codes."""
    if not enabled:
        return False, [REASON_RADVD_DISABLED]
    if interface_up is None:
        return False, [REASON_RADVD_INTERFACE_STATE_UNKNOWN]
    if interface_up is False:
        return False, [REASON_RADVD_INTERFACE_DOWN]
    return True, [REASON_RADVD_SERVING]


def _compose_reason(codes: tuple[str, ...]) -> str:
    """Join human messages for the given reason codes."""
    parts = [_REASON_MESSAGES.get(code, code) for code in codes]
    return "; ".join(parts)


def _verdict_for(
    *,
    radvd_enabled: bool,
    dnsmasq_serving: bool,
    interface_up: bool | None,
) -> RaVerdict:
    """Build one interface verdict from the serving flags."""
    radvd_ok, radvd_codes = _radvd_serving(radvd_enabled, interface_up)
    codes: list[str] = list(radvd_codes)

    if dnsmasq_serving:
        codes.append(REASON_DNSMASQ_SERVING)
    else:
        codes.append(REASON_DNSMASQ_NOT_SERVING)

    if radvd_ok and dnsmasq_serving:
        daemon: RaDaemon = DAEMON_BOTH
        severity: RaSeverity = "warning"
        codes.append(REASON_BOTH_SERVING)
    elif radvd_ok:
        daemon = DAEMON_RADVD
        severity = "ok"
    elif dnsmasq_serving:
        daemon = DAEMON_DNSMASQ
        severity = "ok"
    else:
        daemon = DAEMON_NONE
        severity = "ok"
        codes.append(REASON_NEITHER)

    code_tuple = tuple(codes)
    return RaVerdict(
        daemon=daemon,
        reason_codes=code_tuple,
        reason=_compose_reason(code_tuple),
        radvd_serving=radvd_ok,
        dnsmasq_serving=dnsmasq_serving,
        interface_up=interface_up,
        severity=severity,
    )


def classify_ra_daemons(
    radvd_rows: list[dict],
    dnsmasq_range_rows: list[dict],
    interface_states: dict[str, bool] | None = None,
) -> dict[str, RaVerdict]:
    """Classify which RA daemon serves each interface.

    Parameters
    ----------
    radvd_rows:
        Flat rows from ``/api/radvd/settings/search_entry`` (``rows`` list).
    dnsmasq_range_rows:
        Flat rows from ``/api/dnsmasq/settings/search_range`` (``rows`` list).
    interface_states:
        Map of interface id → administratively up. When ``None``, enabled
        radvd entries are **not** treated as serving (state unknown).

    Returns
    -------
    dict[str, RaVerdict]
        One verdict per interface id seen in either input. ``daemon`` is
        ``dnsmasq``, ``radvd``, ``both``, or ``none``. ``both`` is a
        misconfiguration — callers must refuse writes.
    """
    radvd_enabled_by_iface: dict[str, bool] = {}
    for row in radvd_rows:
        iface = _iface_id(row.get("interface"))
        if not iface:
            continue
        # Any enabled entry wins; multiple disabled stay disabled.
        previously = radvd_enabled_by_iface.get(iface, False)
        radvd_enabled_by_iface[iface] = previously or _radvd_enabled(row)

    dnsmasq_serving_by_iface: dict[str, bool] = {}
    for row in dnsmasq_range_rows:
        iface = _dnsmasq_interface(row)
        if not iface:
            continue
        previously = dnsmasq_serving_by_iface.get(iface, False)
        dnsmasq_serving_by_iface[iface] = previously or _dnsmasq_serves_ra(row)

    interfaces = sorted(set(radvd_enabled_by_iface) | set(dnsmasq_serving_by_iface))
    result: dict[str, RaVerdict] = {}
    for iface in interfaces:
        result[iface] = _verdict_for(
            radvd_enabled=radvd_enabled_by_iface.get(iface, False),
            dnsmasq_serving=dnsmasq_serving_by_iface.get(iface, False),
            interface_up=_interface_up(iface, interface_states),
        )
    return result
