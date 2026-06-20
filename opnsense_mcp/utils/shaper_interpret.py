"""Statistics interpretation for the traffic shaper feature (bucket 2a).

Pure functions — no I/O, no OPNsense API calls.
"""

from __future__ import annotations

import re
from typing import Any

from opnsense_mcp.utils.shaper_types import (
    AUDIT_CODES,
    TOOL_STATUS_CRITICAL,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    InterpretationResult,
)

# ---------------------------------------------------------------------------
# Scheduler alias map: config key → canonical normalised runtime string
#
# OPNsense service/statistics reports sched_type in various casings
# (e.g. "FIFO", "FQ_CODEL").  We normalise both sides to lowercase+underscore
# before comparing, so the map values just reflect the expected normalised form.
# ---------------------------------------------------------------------------

_HIGH_LOAD_PKTS = 100_000
_QUEUE_FLOWS_WARN = 1
_BW_MISMATCH_RATIO = 0.05

RUNTIME_SCHEDULER_ALIASES: dict[str, str] = {
    "fq_codel": "fq_codel",
    "fifo": "fifo",
    "fq_pie": "fq_pie",
    "qfq": "qfq",
    "rr": "rr",
    "drr": "drr",
    "wfq": "wfq",
    "codel": "codel",
    "pie": "pie",
}

# ---------------------------------------------------------------------------
# Module-level baseline store (session-scoped; not thread-safe by design)
# ---------------------------------------------------------------------------

_BASELINE_STORE: dict[str, Any] = {}


def store_baseline(baseline_id: str, statistics: dict[str, Any]) -> None:
    """Persist a statistics snapshot under *baseline_id* for later delta compare."""
    _BASELINE_STORE[baseline_id] = statistics


def get_baseline(baseline_id: str) -> dict[str, Any] | None:
    """Return the stored statistics for *baseline_id*, or None if not found."""
    return _BASELINE_STORE.get(baseline_id)


def clear_baselines() -> None:
    """Remove all stored baselines (use in test teardown)."""
    _BASELINE_STORE.clear()


# ---------------------------------------------------------------------------
# Scheduler matching
# ---------------------------------------------------------------------------


def _normalise_sched(s: str) -> str:
    """Lowercase + replace hyphens with underscores for scheduler comparison."""
    return s.lower().replace("-", "_").strip()


def scheduler_matches(config: str, runtime: str) -> bool:
    """Return True when *runtime* scheduler type matches the *config* key.

    Both sides are normalised to lowercase/underscore before comparison so
    OPNsense capitalisation differences (FIFO vs fifo, FQ_CODEL vs fq_codel)
    are handled transparently.
    """
    if not config or not runtime:
        return False
    expected = RUNTIME_SCHEDULER_ALIASES.get(
        _normalise_sched(config), _normalise_sched(config)
    )
    return _normalise_sched(runtime) == expected


# ---------------------------------------------------------------------------
# Statistics parsing helpers
# ---------------------------------------------------------------------------


def _extract_pipes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [i for i in items if i.get("type") == "pipe"]


def _extract_queues(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [i for i in items if i.get("type") == "queue"]


def _extract_rules(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [i for i in items if i.get("type") == "rule"]


def _metric_to_mbit(value: float, metric: str) -> float:
    """Convert a bandwidth scalar to Mbit/s using OPNsense metric suffix."""
    key = metric.lower().replace("/s", "").strip()
    if key.startswith("g"):
        return value * 1000.0
    if key.startswith("k"):
        return value / 1000.0
    return value


def _parse_bandwidth_mbit(value: Any) -> float | None:
    """Parse runtime statistics ``bw`` values (int or human-readable string)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    match = re.match(r"^([\d.]+)\s*(Kbit|Mbit|Gbit)", text, flags=re.IGNORECASE)
    if match:
        amount = float(match.group(1))
        return _metric_to_mbit(amount, match.group(2))
    try:
        return float(text)
    except ValueError:
        return None


def _config_bandwidth_mbit(pipe: dict[str, Any]) -> float | None:
    """Return configured pipe bandwidth in Mbit/s."""
    bandwidth = pipe.get("bandwidth")
    if bandwidth is None:
        return None
    metric = str(pipe.get("bandwidth_metric") or "Mbit")
    return _metric_to_mbit(float(bandwidth), metric)


def _flowset_drop_total(pipe_item: dict[str, Any]) -> int:
    """Sum drop counters reported under a pipe's ``flowset`` entries."""
    total = 0
    for entry in pipe_item.get("flowset") or []:
        if not isinstance(entry, dict):
            continue
        for key in ("drops", "drop_pkts", "drop", "drop_bytes"):
            value = entry.get(key)
            if isinstance(value, (int, float)) and value > 0:
                total += int(value)
    return total


def _scheduler_queue_params(scheduler: dict[str, Any]) -> str:
    """Return lowercase queue_params string from a runtime scheduler dict."""
    return str(scheduler.get("queue_params") or "").lower()


def _runtime_ecn_enabled(scheduler: dict[str, Any]) -> bool | None:
    """Return runtime ECN flag when explicitly present on statistics scheduler."""
    for key in ("codel_ecn_enable", "ecn", "ecn_enable", "codel_ecn"):
        if key not in scheduler:
            continue
        value = scheduler[key]
        if isinstance(value, bool):
            return value
        lowered = str(value).lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _build_rule_stats(rules: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for r in rules:
        uuid = r.get("rule_uuid", "")
        if uuid:
            result[uuid] = {
                "pkts": r.get("pkts", 0),
                "bytes": r.get("bytes", 0),
                "description": r.get("description", ""),
                "accessed": r.get("accessed", ""),
            }
    return result


def _compute_baseline_delta(
    rule_stats: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    prior_rules = _extract_rules(baseline.get("items", []))
    prior_by_uuid = {r["rule_uuid"]: r for r in prior_rules if "rule_uuid" in r}
    delta: dict[str, Any] = {}
    for uuid, current in rule_stats.items():
        if uuid in prior_by_uuid:
            prior = prior_by_uuid[uuid]
            delta[uuid] = {
                "pkts_delta": current["pkts"] - prior.get("pkts", 0),
                "bytes_delta": current["bytes"] - prior.get("bytes", 0),
            }
    return delta


# ---------------------------------------------------------------------------
# Main interpretation function
# ---------------------------------------------------------------------------


def interpret_statistics(
    statistics: dict[str, Any],
    *,
    pipes: list[dict[str, Any]] | None = None,
    baseline_id: str | None = None,
) -> InterpretationResult:
    """Parse *statistics* from OPNsense service/statistics and return structured hints.

    Args:
        statistics: Raw API response ``{"status": "ok", "items": [...]}``.
        pipes: Optional list of flat pipe dicts (each with ``uuid`` and
               ``scheduler`` keys) used to detect config/runtime scheduler drift.
        baseline_id: If provided, look up a prior baseline snapshot and compute
                     per-rule pkts/bytes deltas.

    Returns:
        :class:`~opnsense_mcp.utils.shaper_types.InterpretationResult` with
        verdict, hints, rule_stats, and optional baseline_delta.
    """
    items: list[dict[str, Any]] = statistics.get("items", [])
    runtime_pipes = _extract_pipes(items)
    rules = _extract_rules(items)
    rule_stats = _build_rule_stats(rules)

    hints: list[str] = []
    has_critical = False
    has_warning = False
    config_by_uuid: dict[str, dict[str, Any]] = {}
    if pipes is not None:
        config_by_uuid = {p["uuid"]: p for p in pipes if "uuid" in p}

    total_rule_pkts = sum(int(r.get("pkts") or 0) for r in rules)

    # --- Scheduler drift check ---
    if pipes is not None:
        for rp in runtime_pipes:
            uuid = rp.get("uuid", "")
            config_pipe = config_by_uuid.get(uuid)
            if config_pipe is None:
                continue
            config_sched = config_pipe.get("scheduler", "")
            runtime_sched = rp.get("scheduler", {}).get("sched_type", "")
            if config_sched and not scheduler_matches(config_sched, runtime_sched):
                desc = config_pipe.get("description", uuid)
                hints.append(
                    f"[SCHEDULER_DRIFT] {desc}: "
                    f"config={config_sched!r} but runtime sched_type={runtime_sched!r} — "
                    "reconfigure or rewrite the pipe to apply the configured scheduler."
                )
                has_critical = True

    # --- Flowset drop counters ---
    for rp in runtime_pipes:
        drops = _flowset_drop_total(rp)
        if drops <= 0:
            continue
        desc = rp.get("description", rp.get("uuid", "unknown"))
        hints.append(
            f"[PIPE_FLOWSET_DROPS] {desc}: {drops} drop(s) in flowset — "
            "investigate congestion or tune bandwidth."
        )
        has_warning = True

    # --- Droptail scheduler under load ---
    if total_rule_pkts >= _HIGH_LOAD_PKTS:
        for rp in runtime_pipes:
            scheduler = rp.get("scheduler") or {}
            if "droptail" not in _scheduler_queue_params(scheduler):
                continue
            desc = rp.get("description", rp.get("uuid", "unknown"))
            hints.append(
                f"[PIPE_DROPTAIL_LOAD] {desc}: droptail queue with "
                f"{total_rule_pkts:,} rule pkts — run a bufferbloat test or "
                "reduce the bandwidth target."
            )
            has_warning = True

    # --- Active queue flows (utilization signal) ---
    for queue in _extract_queues(items):
        flows = queue.get("flows", 0)
        if not isinstance(flows, (int, float)) or flows < _QUEUE_FLOWS_WARN:
            continue
        desc = queue.get("description", queue.get("uuid", "unknown"))
        hints.append(
            f"[QUEUE_FLOWS_ACTIVE] {desc}: {int(flows)} active flow(s) — "
            "queue may be near capacity."
        )
        has_warning = True

    # --- ECN runtime vs config ---
    if pipes is not None:
        for rp in runtime_pipes:
            uuid = rp.get("uuid", "")
            config_pipe = config_by_uuid.get(uuid)
            if config_pipe is None or not config_pipe.get("codel_ecn_enable"):
                continue
            config_sched = config_pipe.get("scheduler", "")
            if _normalise_sched(config_sched) != "fq_codel":
                continue
            runtime_scheduler = rp.get("scheduler") or {}
            runtime_sched_type = runtime_scheduler.get("sched_type", "")
            desc = config_pipe.get("description", uuid)
            if config_sched and not scheduler_matches(config_sched, runtime_sched_type):
                hints.append(
                    f"[ECN_INEFFECTIVE] {desc}: ECN enabled in config but runtime "
                    f"scheduler is {runtime_sched_type!r} — ECN requires active FQ-CoDel."
                )
                has_warning = True
                continue
            runtime_ecn = _runtime_ecn_enabled(runtime_scheduler)
            if runtime_ecn is False:
                hints.append(
                    f"[ECN_RUNTIME_OFF] {desc}: ECN enabled in config but runtime "
                    "statistics report ECN disabled."
                )
                has_warning = True

    # --- Config bandwidth vs statistics display ---
    if pipes is not None:
        for rp in runtime_pipes:
            uuid = rp.get("uuid", "")
            config_pipe = config_by_uuid.get(uuid)
            if config_pipe is None:
                continue
            config_mbit = _config_bandwidth_mbit(config_pipe)
            stats_mbit = _parse_bandwidth_mbit(rp.get("bw"))
            if config_mbit is None or stats_mbit is None or config_mbit <= 0:
                continue
            if abs(config_mbit - stats_mbit) / config_mbit <= _BW_MISMATCH_RATIO:
                continue
            desc = config_pipe.get("description", uuid)
            hints.append(
                f"[PIPE_BW_MISMATCH] {desc}: config bandwidth "
                f"{config_mbit:g} Mbit/s vs statistics {stats_mbit:g} Mbit/s — "
                "verify apply/reconfigure or pipe rewrite."
            )
            has_warning = True

    # --- Zero-pkts rules check ---
    for r in rules:
        if r.get("pkts", 0) == 0:
            desc = r.get("description", r.get("rule_uuid", "unknown"))
            hints.append(
                f"[RULE_PKTS_ZERO] '{desc}': zero pkts — "
                "rule may not match traffic (check proto/direction/interface)."
            )
            has_warning = True

    # --- Verdict ---
    if has_critical:
        verdict = TOOL_STATUS_CRITICAL
    elif has_warning:
        verdict = TOOL_STATUS_WARNING
    else:
        verdict = TOOL_STATUS_SUCCESS

    # --- Baseline delta ---
    baseline_delta: dict[str, Any] | None = None
    if baseline_id is not None:
        prior = get_baseline(baseline_id)
        if prior is not None:
            baseline_delta = _compute_baseline_delta(rule_stats, prior)

    return InterpretationResult(
        verdict=verdict,
        hints=hints,
        rule_stats=rule_stats,
        baseline_delta=baseline_delta,
    )


# ---------------------------------------------------------------------------
# Summary formatter
# ---------------------------------------------------------------------------


def format_statistics_summary(
    statistics: dict[str, Any],
    interpretation: InterpretationResult,
) -> str:
    """Return a human-readable Markdown summary of *statistics* + *interpretation*.

    Intended for the ``summary`` field of a :class:`ShaperToolResponse`.
    """
    lines: list[str] = []
    verdict = interpretation.verdict.upper()
    lines.append(f"**Shaper Statistics** — verdict: {verdict}")

    # Rule traffic table
    rules = _extract_rules(statistics.get("items", []))
    if rules:
        lines.append("")
        lines.append("| Rule | Pkts | Bytes |")
        lines.append("|------|------|-------|")
        for r in rules:
            desc = r.get("description", r.get("rule_uuid", "?"))
            pkts = r.get("pkts", 0)
            byt = r.get("bytes", 0)
            lines.append(f"| {desc} | {pkts:,} | {byt:,} |")

    # Hints / findings
    if interpretation.hints:
        lines.append("")
        lines.append("**Findings:**")
        for hint in interpretation.hints:
            lines.append(f"- {hint}")

    return "\n".join(lines)
