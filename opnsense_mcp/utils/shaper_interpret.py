"""Statistics interpretation for the traffic shaper feature (bucket 2a).

Pure functions — no I/O, no OPNsense API calls.
"""

from __future__ import annotations

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


def _extract_rules(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [i for i in items if i.get("type") == "rule"]


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

    # --- Scheduler drift check ---
    if pipes is not None:
        config_by_uuid = {p["uuid"]: p for p in pipes if "uuid" in p}
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
