"""Best-practice audit checklist and explain helpers for traffic shaper (bucket 2b).

Pure functions — no I/O, no OPNsense API calls.
"""

from __future__ import annotations

from typing import Any

from opnsense_mcp.utils.shaper_interpret import (
    fqcodel_statistics_layout_ok,
    scheduler_matches,
)
from opnsense_mcp.utils.shaper_types import (
    AUDIT_CODES,
    DEFAULT_WAN_INTERFACES,
    TOOL_STATUS_CRITICAL,
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    AuditFinding,
    AuditResult,
    FlatShaperPipe,
    FlatShaperQueue,
    FlatShaperRule,
)

_SEVERITY_DEDUCTIONS: dict[str, int] = {"error": 15, "warning": 5, "info": 1}

_METRIC_TO_MBIT: dict[str, float] = {
    "bit": 1 / 1_000_000,
    "kbit": 1 / 1_000,
    "mbit": 1.0,
    "gbit": 1_000.0,
}

_ISP_WARN_FRACTION = 0.95
_ISP_INFO_FRACTION = 0.85


def _bandwidth_to_mbit(pipe: FlatShaperPipe) -> float:
    """Convert a flat pipe's bandwidth + metric to Mbit/s."""
    raw = float(pipe.get("bandwidth", 0) or 0)
    metric = (pipe.get("bandwidth_metric") or "Mbit").lower()
    return raw * _METRIC_TO_MBIT.get(metric, 1.0)


def _object_by_description_hint[T: FlatShaperPipe | FlatShaperQueue](
    items: list[T],
    hint: str,
) -> T | None:
    needle = hint.lower()
    for item in items:
        desc = (item.get("description") or "").lower()
        if needle in desc:
            return item
    return None


def _pipe_by_description_hint(
    pipes: list[FlatShaperPipe],
    hint: str,
) -> FlatShaperPipe | None:
    return _object_by_description_hint(pipes, hint)


def _queue_uuid_for_direction(
    rules: list[FlatShaperRule],
    queues: list[FlatShaperQueue],
    *,
    direction: str,
    wan_interfaces: frozenset[str],
) -> str | None:
    """Return a queue uuid referenced by a WAN rule with *direction*."""
    queue_uuids = {q.get("uuid", "") for q in queues}
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        iface = (rule.get("interface") or "").lower()
        if iface not in wan_interfaces:
            continue
        if (rule.get("direction") or "").lower() != direction:
            continue
        target = rule.get("target_uuid", "")
        if target in queue_uuids:
            return target
    return None


def _pipe_uuid_from_queue(
    queues: list[FlatShaperQueue],
    queue_uuid: str | None,
) -> str | None:
    if not queue_uuid:
        return None
    for queue in queues:
        if queue.get("uuid") == queue_uuid:
            return queue.get("pipe_uuid") or None
    return None


def _identify_download_upload_pipes(
    pipes: list[FlatShaperPipe],
    queues: list[FlatShaperQueue],
    rules: list[FlatShaperRule],
    wan_interfaces: frozenset[str],
) -> tuple[FlatShaperPipe | None, FlatShaperPipe | None]:
    """Return (download_pipe, upload_pipe) using description heuristics or rule attachment."""
    download = _pipe_by_description_hint(pipes, "download")
    upload = _pipe_by_description_hint(pipes, "upload")

    if download is None:
        in_queue = _queue_uuid_for_direction(
            rules, queues, direction="in", wan_interfaces=wan_interfaces
        )
        in_pipe_uuid = _pipe_uuid_from_queue(queues, in_queue)
        if in_pipe_uuid:
            download = next((p for p in pipes if p.get("uuid") == in_pipe_uuid), None)

    if upload is None:
        out_queue = _queue_uuid_for_direction(
            rules, queues, direction="out", wan_interfaces=wan_interfaces
        )
        out_pipe_uuid = _pipe_uuid_from_queue(queues, out_queue)
        if out_pipe_uuid:
            upload = next((p for p in pipes if p.get("uuid") == out_pipe_uuid), None)

    return download, upload


def _identify_download_upload_queues(
    queues: list[FlatShaperQueue],
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
) -> tuple[FlatShaperQueue | None, FlatShaperQueue | None]:
    download_q = _object_by_description_hint(queues, "download")
    upload_q = _object_by_description_hint(queues, "upload")

    if download_q is None and download_pipe is not None:
        dl_uuid = download_pipe.get("uuid", "")
        download_q = next((q for q in queues if q.get("pipe_uuid") == dl_uuid), None)

    if upload_q is None and upload_pipe is not None:
        ul_uuid = upload_pipe.get("uuid", "")
        upload_q = next((q for q in queues if q.get("pipe_uuid") == ul_uuid), None)

    return download_q, upload_q


def _finding(
    severity: str,
    code: str,
    *,
    detail: str = "",
) -> AuditFinding:
    base = AUDIT_CODES.get(code, code)
    message = f"{base}: {detail}" if detail else base
    return AuditFinding(severity=severity, code=code, message=message)


def _aggregate_status(findings: list[AuditFinding]) -> str:
    codes = {f.code for f in findings}
    if "SCHEDULER_DRIFT" in codes:
        return TOOL_STATUS_CRITICAL
    if any(f.severity == "error" for f in findings):
        return TOOL_STATUS_ERROR
    if any(f.severity == "warning" for f in findings):
        return TOOL_STATUS_WARNING
    return TOOL_STATUS_SUCCESS


def _compute_score(findings: list[AuditFinding]) -> int:
    total = sum(_SEVERITY_DEDUCTIONS.get(f.severity, 0) for f in findings)
    return max(0, 100 - total)


def _runtime_pipes_by_uuid(statistics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = statistics.get("items", [])
    return {
        item["uuid"]: item
        for item in items
        if item.get("type") == "pipe" and item.get("uuid")
    }


def _check_pipes_missing(
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
) -> AuditFinding | None:
    missing: list[str] = []
    if download_pipe is None or not download_pipe.get("enabled", False):
        missing.append("download")
    if upload_pipe is None or not upload_pipe.get("enabled", False):
        missing.append("upload")
    if missing:
        return _finding("error", "PIPES_MISSING", detail=", ".join(missing))
    return None


def _check_scheduler_fqcodel(
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for pipe in (download_pipe, upload_pipe):
        if pipe is None:
            continue
        sched = (pipe.get("scheduler") or "").lower()
        if sched != "fq_codel":
            desc = pipe.get("description", pipe.get("uuid", "pipe"))
            findings.append(
                _finding(
                    "warning",
                    "SCHEDULER_NOT_FQCODEL",
                    detail=f"{desc} uses {sched or 'unknown'}",
                )
            )
    return findings


def _check_scheduler_drift(
    pipes: list[FlatShaperPipe],
    statistics: dict[str, Any] | None,
) -> list[AuditFinding]:
    if statistics is None:
        return []
    runtime_by_uuid = _runtime_pipes_by_uuid(statistics)
    findings: list[AuditFinding] = []
    for pipe in pipes:
        uuid = pipe.get("uuid", "")
        if not uuid or uuid not in runtime_by_uuid:
            continue
        config_sched = pipe.get("scheduler", "")
        runtime_pipe = runtime_by_uuid[uuid]
        runtime_sched = runtime_pipe.get("scheduler", {}).get("sched_type", "")
        if config_sched and not scheduler_matches(config_sched, runtime_sched):
            if fqcodel_statistics_layout_ok(runtime_pipe, config_sched):
                continue
            desc = pipe.get("description", uuid)
            findings.append(
                _finding(
                    "error",
                    "SCHEDULER_DRIFT",
                    detail=(
                        f"{desc}: config={config_sched!r}, runtime={runtime_sched!r}"
                    ),
                )
            )
    return findings


def _wan_rules_for(
    rules: list[FlatShaperRule],
    *,
    direction: str,
    proto: str,
    wan_interfaces: frozenset[str],
) -> list[FlatShaperRule]:
    matched: list[FlatShaperRule] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        iface = (rule.get("interface") or "").lower()
        if iface not in wan_interfaces:
            continue
        if (rule.get("direction") or "").lower() != direction:
            continue
        if (rule.get("proto") or "").lower() == proto:
            matched.append(rule)
    return matched


def _check_ipv6_missing(
    rules: list[FlatShaperRule],
    wan_interfaces: frozenset[str],
) -> AuditFinding | None:
    gaps: list[str] = []
    for direction, label in (("in", "download/WAN in"), ("out", "upload/WAN out")):
        has_v4 = bool(
            _wan_rules_for(
                rules, direction=direction, proto="ip", wan_interfaces=wan_interfaces
            )
        )
        has_v6 = bool(
            _wan_rules_for(
                rules, direction=direction, proto="ip6", wan_interfaces=wan_interfaces
            )
        )
        if has_v4 and not has_v6:
            gaps.append(label)
    if gaps:
        return _finding("warning", "IPV6_MISSING", detail="; ".join(gaps))
    return None


def _check_bw_isp_rate(
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
    *,
    isp_download_mbit: float | None,
    isp_upload_mbit: float | None,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    pairs: list[tuple[FlatShaperPipe | None, float | None, str]] = [
        (download_pipe, isp_download_mbit, "download"),
        (upload_pipe, isp_upload_mbit, "upload"),
    ]
    for pipe, isp_rate, label in pairs:
        if pipe is None or isp_rate is None or isp_rate <= 0:
            continue
        bw = _bandwidth_to_mbit(pipe)
        fraction = bw / isp_rate
        if fraction > _ISP_WARN_FRACTION:
            findings.append(
                _finding(
                    "warning",
                    "BW_ISP_RATE",
                    detail=(
                        f"{label} pipe {bw:.0f} Mbit/s exceeds "
                        f"{_ISP_WARN_FRACTION:.0%} of ISP {isp_rate:.0f} Mbit/s"
                    ),
                )
            )
        elif fraction > _ISP_INFO_FRACTION:
            findings.append(
                _finding(
                    "info",
                    "BW_ISP_RATE",
                    detail=(
                        f"{label} pipe {bw:.0f} Mbit/s above "
                        f"{_ISP_INFO_FRACTION:.0%} of ISP {isp_rate:.0f} Mbit/s"
                    ),
                )
            )
    return findings


def _check_bw_line_rate(
    pipes: list[FlatShaperPipe],
    wan_line_rate_mbit: float | None,
) -> list[AuditFinding]:
    if wan_line_rate_mbit is None or wan_line_rate_mbit <= 0:
        return []
    findings: list[AuditFinding] = []
    for pipe in pipes:
        if not pipe.get("enabled", True):
            continue
        bw = _bandwidth_to_mbit(pipe)
        if bw > wan_line_rate_mbit:
            desc = pipe.get("description", pipe.get("uuid", "pipe"))
            findings.append(
                _finding(
                    "error",
                    "BW_EXCEEDS_LINE_RATE",
                    detail=(
                        f"{desc} {bw:.0f} Mbit/s exceeds WAN line rate "
                        f"{wan_line_rate_mbit:.0f} Mbit/s"
                    ),
                )
            )
    return findings


def _check_ecn_disabled(
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for pipe in (download_pipe, upload_pipe):
        if pipe is None:
            continue
        sched = (pipe.get("scheduler") or "").lower()
        if sched != "fq_codel":
            continue
        if not pipe.get("codel_ecn_enable", False):
            desc = pipe.get("description", pipe.get("uuid", "pipe"))
            findings.append(_finding("info", "ECN_DISABLED", detail=desc))
    return findings


def _check_lan_shaping(
    rules: list[FlatShaperRule],
    wan_interfaces: frozenset[str],
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        iface = (rule.get("interface") or "").lower()
        if iface and iface not in wan_interfaces:
            desc = rule.get("description", rule.get("uuid", "rule"))
            findings.append(
                _finding(
                    "warning",
                    "LAN_SHAPING",
                    detail=f"{desc} on interface {iface}",
                )
            )
    return findings


def _check_queue_wrong_pipe(
    pipes: list[FlatShaperPipe],
    queues: list[FlatShaperQueue],
    download_pipe: FlatShaperPipe | None,
    upload_pipe: FlatShaperPipe | None,
    download_queue: FlatShaperQueue | None,
    upload_queue: FlatShaperQueue | None,
) -> list[AuditFinding]:
    pipe_uuids = {p.get("uuid", "") for p in pipes}
    findings: list[AuditFinding] = []

    expected: list[tuple[FlatShaperQueue | None, FlatShaperPipe | None, str]] = [
        (download_queue, download_pipe, "download"),
        (upload_queue, upload_pipe, "upload"),
    ]
    for queue, expected_pipe, label in expected:
        if queue is None:
            continue
        pipe_uuid = queue.get("pipe_uuid", "")
        if not pipe_uuid or pipe_uuid not in pipe_uuids:
            desc = queue.get("description", queue.get("uuid", "queue"))
            findings.append(
                _finding(
                    "error",
                    "QUEUE_WRONG_PIPE",
                    detail=f"{desc} ({label}) links to missing pipe {pipe_uuid!r}",
                )
            )
        elif expected_pipe is not None and pipe_uuid != expected_pipe.get("uuid"):
            desc = queue.get("description", queue.get("uuid", "queue"))
            findings.append(
                _finding(
                    "error",
                    "QUEUE_WRONG_PIPE",
                    detail=f"{desc} ({label}) linked to unexpected pipe",
                )
            )

    return findings


def _check_rule_targets_pipe(
    rules: list[FlatShaperRule],
    pipes: list[FlatShaperPipe],
    queues: list[FlatShaperQueue],
) -> list[AuditFinding]:
    pipe_uuids = {p.get("uuid", "") for p in pipes}
    queue_uuids = {q.get("uuid", "") for q in queues}
    findings: list[AuditFinding] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        target = rule.get("target_uuid", "")
        if target in pipe_uuids and target not in queue_uuids:
            desc = rule.get("description", rule.get("uuid", "rule"))
            findings.append(
                _finding(
                    "warning",
                    "RULE_TARGETS_PIPE",
                    detail=f"{desc} targets pipe directly",
                )
            )
    return findings


def run_audit(
    *,
    pipes: list[FlatShaperPipe],
    queues: list[FlatShaperQueue],
    rules: list[FlatShaperRule],
    statistics: dict[str, Any] | None = None,
    wan_line_rate_mbit: float | None = None,
    isp_download_mbit: float | None = None,
    isp_upload_mbit: float | None = None,
    wan_interfaces: frozenset[str] | None = None,
) -> AuditResult:
    """Run full best-practice checklist from spec."""
    wan_ifaces = (
        wan_interfaces if wan_interfaces is not None else DEFAULT_WAN_INTERFACES
    )

    download_pipe, upload_pipe = _identify_download_upload_pipes(
        pipes, queues, rules, wan_ifaces
    )
    download_queue, upload_queue = _identify_download_upload_queues(
        queues, download_pipe, upload_pipe
    )

    findings: list[AuditFinding] = []

    if missing := _check_pipes_missing(download_pipe, upload_pipe):
        findings.append(missing)

    findings.extend(_check_scheduler_fqcodel(download_pipe, upload_pipe))
    findings.extend(_check_scheduler_drift(pipes, statistics))
    if ipv6 := _check_ipv6_missing(rules, wan_ifaces):
        findings.append(ipv6)
    findings.extend(
        _check_bw_isp_rate(
            download_pipe,
            upload_pipe,
            isp_download_mbit=isp_download_mbit,
            isp_upload_mbit=isp_upload_mbit,
        )
    )
    findings.extend(_check_bw_line_rate(pipes, wan_line_rate_mbit))
    findings.extend(_check_ecn_disabled(download_pipe, upload_pipe))
    findings.extend(_check_lan_shaping(rules, wan_ifaces))
    findings.extend(
        _check_queue_wrong_pipe(
            pipes,
            queues,
            download_pipe,
            upload_pipe,
            download_queue,
            upload_queue,
        )
    )
    findings.extend(_check_rule_targets_pipe(rules, pipes, queues))

    score = _compute_score(findings)
    status = _aggregate_status(findings)
    summary_lines = [
        f"Audit score: {score}/100 ({status})",
        f"{len(findings)} finding(s)",
    ]

    return AuditResult(
        findings=findings,
        score=score,
        status=status,
        summary_lines=summary_lines,
    )


def format_audit_summary(audit: AuditResult) -> str:
    """Markdown summary for tool ``summary`` field."""
    lines: list[str] = [
        f"**Traffic Shaper Audit** — score **{audit.score}/100** ({audit.status})",
    ]

    if not audit.findings:
        lines.append("")
        lines.append("No issues found. Configuration matches best practices.")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Severity | Code | Message |")
    lines.append("|----------|------|---------|")
    for finding in audit.findings:
        msg = finding.message.replace("|", "\\|")
        lines.append(f"| {finding.severity} | {finding.code} | {msg} |")

    return "\n".join(lines)


def explain_shaper_config(
    *,
    pipes: list[FlatShaperPipe],
    queues: list[FlatShaperQueue],
    rules: list[FlatShaperRule],
    audit: AuditResult | None = None,
) -> str:
    """Plain-language narrative for non-technical users."""
    wan_ifaces = DEFAULT_WAN_INTERFACES
    download_pipe, upload_pipe = _identify_download_upload_pipes(
        pipes, queues, rules, wan_ifaces
    )

    paragraphs: list[str] = []

    if download_pipe and upload_pipe:
        dl_bw = _bandwidth_to_mbit(download_pipe)
        ul_bw = _bandwidth_to_mbit(upload_pipe)
        paragraphs.append(
            "Your firewall limits internet speed using two virtual pipes: one for "
            f"downloads ({dl_bw:.0f} Mbit/s) and one for uploads ({ul_bw:.0f} Mbit/s). "
            "Traffic on your WAN connection is steered into matching queues, then "
            "through those pipes so bursts are smoothed and latency stays low."
        )
    elif download_pipe or upload_pipe:
        paragraphs.append(
            "Your firewall has partial traffic shaping configured — only a download "
            "or upload pipe is set up, not both."
        )
    else:
        paragraphs.append(
            "Traffic shaping is not fully configured: download and upload pipes "
            "were not identified."
        )

    enabled_rules = [r for r in rules if r.get("enabled", True)]
    wan_rules = [
        r for r in enabled_rules if (r.get("interface") or "").lower() in wan_ifaces
    ]
    if wan_rules:
        protos = sorted({(r.get("proto") or "ip").upper() for r in wan_rules})
        paragraphs.append(
            f"There are {len(wan_rules)} active shaper rule(s) on the WAN for "
            f"{' and '.join(protos)} traffic."
        )

    if audit is not None:
        if audit.status == TOOL_STATUS_SUCCESS:
            paragraphs.append(
                "An automated check found no significant problems with this setup."
            )
        elif audit.status == TOOL_STATUS_CRITICAL:
            drift = [f for f in audit.findings if f.code == "SCHEDULER_DRIFT"]
            if drift:
                paragraphs.append(
                    "Important: the scheduler running on the firewall does not match "
                    "what is saved in configuration. Shaping may not be working as "
                    "intended until you apply changes or recreate the pipes."
                )
        elif audit.findings:
            top = audit.findings[0]
            paragraphs.append(
                f"The audit reported {len(audit.findings)} item(s) to review. "
                f"The most notable: {top.message}"
            )

    return "\n\n".join(paragraphs)
