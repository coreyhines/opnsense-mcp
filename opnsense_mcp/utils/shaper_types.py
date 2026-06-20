"""Shared types, constants, and helpers for the traffic shaper feature.

All buckets (normalize, serialize, audit, MCP tools) import from here.
No I/O; no OPNsense API calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------

TOOL_STATUS_SUCCESS = "success"
TOOL_STATUS_ERROR = "error"
TOOL_STATUS_WARNING = "warning"
TOOL_STATUS_CRITICAL = "critical"

_VALID_STATUSES: frozenset[str] = frozenset(
    {TOOL_STATUS_SUCCESS, TOOL_STATUS_ERROR, TOOL_STATUS_WARNING, TOOL_STATUS_CRITICAL}
)

AUDIT_FINDING_SEVERITIES: frozenset[str] = frozenset({"error", "warning", "info"})

AUDIT_RESULT_STATUSES: frozenset[str] = _VALID_STATUSES

INTERPRETATION_VERDICTS: frozenset[str] = _VALID_STATUSES

# ---------------------------------------------------------------------------
# Scheduler constants
# ---------------------------------------------------------------------------

PIPE_SCHEDULERS: frozenset[str] = frozenset(
    {"fq_codel", "fifo", "fq_pie", "qfq", "rr", "drr", "wfq", "codel", "pie", ""}
)

# ---------------------------------------------------------------------------
# Interface constants
# ---------------------------------------------------------------------------

DEFAULT_WAN_INTERFACES: frozenset[str] = frozenset({"wan"})

# ---------------------------------------------------------------------------
# Audit code constants
# ---------------------------------------------------------------------------

AUDIT_CODES: dict[str, str] = {
    "PIPES_MISSING": "Download or upload pipe missing or disabled",
    "SCHEDULER_NOT_FQCODEL": "WAN pipe scheduler is not FQ-CoDel",
    "SCHEDULER_DRIFT": "Config scheduler does not match runtime statistics scheduler",
    "IPV6_MISSING": "Missing paired IPv6 shaper rules for WAN in/out",
    "BW_ISP_RATE": "Pipe bandwidth exceeds 85–95% of reference ISP rate",
    "BW_EXCEEDS_LINE_RATE": "Pipe bandwidth exceeds WAN interface physical line rate",
    "ECN_DISABLED": "ECN not enabled on FQ-CoDel pipe",
    "LAN_SHAPING": "Shaper rule targets a LAN interface (discouraged)",
    "QUEUE_WRONG_PIPE": "Queue linked to unexpected or missing pipe",
    "RULE_TARGETS_PIPE": "Rule targets a pipe directly instead of a queue",
    "GLOBAL_DISABLED": "Global traffic shaper is disabled",
    "RULE_PKTS_ZERO": "Rule has zero packets while WAN traffic is expected",
}

# ---------------------------------------------------------------------------
# Flat agent-view TypedDicts
# ---------------------------------------------------------------------------

# TypedDicts are intentionally not imported via typing_extensions — Python
# 3.12 stdlib typing is sufficient.

from typing import TypedDict  # noqa: E402


class FlatShaperPipe(TypedDict, total=False):
    """Flat representation of one OPNsense traffic shaper pipe."""

    uuid: str
    number: str
    description: str
    enabled: bool
    bandwidth: int
    bandwidth_metric: str  # bit|Kbit|Mbit|Gbit
    scheduler: str  # fq_codel|fifo|fq_pie|qfq|rr|""
    mask: str
    codel_enable: bool
    codel_target_ms: int | None
    codel_interval_ms: int | None
    codel_ecn_enable: bool
    fqcodel_quantum: int | None
    fqcodel_limit: int | None
    fqcodel_flows: int | None
    pie_enable: bool


class FlatShaperQueue(TypedDict, total=False):
    """Flat representation of one OPNsense traffic shaper queue."""

    uuid: str
    description: str
    enabled: bool
    pipe_uuid: str
    weight: int
    mask: str
    codel_enable: bool
    codel_target_ms: int | None
    codel_interval_ms: int | None
    codel_ecn_enable: bool
    pie_enable: bool


class FlatShaperRule(TypedDict, total=False):
    """Flat representation of one OPNsense traffic shaper rule."""

    uuid: str
    description: str
    enabled: bool
    interface: str
    interface2: str | None
    direction: str  # in|out|both
    proto: str  # ip|ip6|tcp|udp|…
    source: str
    source_port: str | None
    destination: str
    destination_port: str | None
    dscp: str | None
    target_uuid: str
    sequence: int


# ---------------------------------------------------------------------------
# Tool response contract
# ---------------------------------------------------------------------------


class ShaperToolResponse(TypedDict, total=False):
    """Standard envelope returned by every shaper MCP tool."""

    status: str
    structured: dict[str, Any]
    summary: str
    hints: list[str]
    snapshot_id: str
    baseline_id: str


def make_tool_response(
    *,
    status: str,
    structured: dict[str, Any],
    summary: str,
    hints: list[str] | None = None,
    snapshot_id: str | None = None,
    baseline_id: str | None = None,
) -> ShaperToolResponse:
    """Build a validated :class:`ShaperToolResponse` dict.

    Raises :exc:`ValueError` when *status* is not one of the allowed values.
    """
    if status not in _VALID_STATUSES:
        msg = f"Invalid status {status!r}; must be one of {sorted(_VALID_STATUSES)}"
        raise ValueError(msg)

    resp: ShaperToolResponse = {
        "status": status,
        "structured": structured,
        "summary": summary,
        "hints": hints if hints is not None else [],
    }
    if snapshot_id is not None:
        resp["snapshot_id"] = snapshot_id
    if baseline_id is not None:
        resp["baseline_id"] = baseline_id
    return resp


# ---------------------------------------------------------------------------
# Audit types
# ---------------------------------------------------------------------------


@dataclass
class AuditFinding:
    """A single finding from an audit check."""

    severity: str  # error|warning|info
    code: str
    message: str


@dataclass
class AuditResult:
    """Aggregated result of running the full audit checklist."""

    findings: list[AuditFinding]
    score: int
    status: str  # success|warning|error|critical
    summary_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Interpretation types
# ---------------------------------------------------------------------------


@dataclass
class InterpretationResult:
    """Structured output from parsing shaper statistics."""

    verdict: str  # success|warning|error|critical
    hints: list[str]
    rule_stats: dict[str, Any]
    baseline_delta: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def is_valid_scheduler(name: str) -> bool:
    """Return True if *name* is a recognised pipe scheduler key (including ``""``)."""
    return name in PIPE_SCHEDULERS


def is_valid_audit_severity(severity: str) -> bool:
    """Return True if *severity* is a recognised audit finding level."""
    return severity in AUDIT_FINDING_SEVERITIES


def is_valid_audit_status(status: str) -> bool:
    """Return True if *status* is a recognised aggregated audit result status."""
    return status in AUDIT_RESULT_STATUSES


def is_valid_interpretation_verdict(verdict: str) -> bool:
    """Return True if *verdict* is a recognised statistics interpretation verdict."""
    return verdict in INTERPRETATION_VERDICTS
