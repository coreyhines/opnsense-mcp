#!/usr/bin/env python3
"""Parse flent summary output and enforce FQ-CoDel baseline latency gates."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class FlentMetrics:
    """Key metrics extracted from a flent summary file."""

    icmp_mean_ms: float | None
    tcp_down_mbit: float | None
    tcp_up_mbit: float | None
    tcp_total_mbit: float | None


@dataclass(frozen=True)
class GateResult:
    """Outcome of comparing metrics against CI thresholds."""

    passed: bool
    icmp_mean_ms: float | None
    icmp_max_ms: float
    messages: list[str]


_ICMP_COL_RE = re.compile(
    r"Ping\s*\(ms\)\s*ICMP\s*:\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_ICMP_MEAN_RE = re.compile(
    r"Ping\s*\(?ms?\)?\s*ICMP[^\n]*?mean\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_ICMP_ALT_RE = re.compile(
    r"ICMP[^\n]*?mean\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_DOWN_COL_RE = re.compile(
    r"TCP\s+download\s+sum\s*:\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_UP_COL_RE = re.compile(
    r"TCP\s+upload\s+sum\s*:\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_TOTAL_COL_RE = re.compile(
    r"TCP\s+totals\s*:\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_DOWN_RE = re.compile(
    r"TCP\s+download[^\n]*?mean\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_UP_RE = re.compile(
    r"TCP\s+upload[^\n]*?mean\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_TCP_TOTAL_RE = re.compile(
    r"TCP\s+totals[^\n]*?mean\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)


def _first_float(*patterns: re.Pattern[str], text: str) -> float | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return float(match.group(1))
    return None


def parse_flent_summary(text: str) -> FlentMetrics:
    """Extract loaded-latency and throughput means from flent summary text."""
    icmp = _first_float(_ICMP_COL_RE, _ICMP_MEAN_RE, _ICMP_ALT_RE, text=text)
    return FlentMetrics(
        icmp_mean_ms=icmp,
        tcp_down_mbit=_first_float(_TCP_DOWN_COL_RE, _TCP_DOWN_RE, text=text),
        tcp_up_mbit=_first_float(_TCP_UP_COL_RE, _TCP_UP_RE, text=text),
        tcp_total_mbit=_first_float(_TCP_TOTAL_COL_RE, _TCP_TOTAL_RE, text=text),
    )


def evaluate_gate(metrics: FlentMetrics, icmp_max_ms: float) -> GateResult:
    """Return pass/fail for the loaded ICMP latency gate."""
    messages: list[str] = []
    if metrics.icmp_mean_ms is None:
        return GateResult(
            passed=False,
            icmp_mean_ms=None,
            icmp_max_ms=icmp_max_ms,
            messages=["Could not parse ICMP mean from flent summary"],
        )

    messages.append(
        f"Loaded ICMP mean: {metrics.icmp_mean_ms:.2f} ms (gate < {icmp_max_ms:.2f} ms)"
    )
    if metrics.icmp_mean_ms >= icmp_max_ms:
        messages.append(
            f"FAIL: loaded latency {metrics.icmp_mean_ms:.2f} ms "
            f">= gate {icmp_max_ms:.2f} ms"
        )
        passed = False
    else:
        messages.append("PASS: loaded latency within gate")
        passed = True

    if metrics.tcp_total_mbit is not None:
        messages.append(f"TCP totals mean: {metrics.tcp_total_mbit:.2f} Mbit/s")
    if metrics.tcp_down_mbit is not None:
        messages.append(f"TCP download mean: {metrics.tcp_down_mbit:.2f} Mbit/s")
    if metrics.tcp_up_mbit is not None:
        messages.append(f"TCP upload mean: {metrics.tcp_up_mbit:.2f} Mbit/s")

    return GateResult(
        passed=passed,
        icmp_mean_ms=metrics.icmp_mean_ms,
        icmp_max_ms=icmp_max_ms,
        messages=messages,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "summary_file",
        type=Path,
        help="Path to flent *_summary.txt (or full flent log)",
    )
    parser.add_argument(
        "--icmp-max-ms",
        type=float,
        default=float(os.environ.get("FLENT_ICMP_MAX_MS", "145")),
        help="Fail when loaded ICMP mean is >= this value (default: 145)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write structured metrics + gate result",
    )
    args = parser.parse_args(argv)

    text = args.summary_file.read_text(encoding="utf-8", errors="replace")
    metrics = parse_flent_summary(text)
    gate = evaluate_gate(metrics, args.icmp_max_ms)

    payload = {
        "metrics": asdict(metrics),
        "gate": {
            "passed": gate.passed,
            "icmp_max_ms": gate.icmp_max_ms,
            "icmp_mean_ms": gate.icmp_mean_ms,
            "messages": gate.messages,
        },
    }
    if args.json_out:
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    for line in gate.messages:
        print(line)

    if not gate.passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
