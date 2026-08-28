#!/usr/bin/env python3
"""Rank source files by how likely they are to harbour defects, from git history.

This finds no bugs. It finds where bugs concentrate, so an expensive review — an
LLM scrub, a careful human pass — reads the risky files first and can stop early.
The economy is the point: bug-hunting cost scales with surface area, and this
shrinks the surface you pay to look at.

The signal is deliberately simple and deterministic, because a risk map nobody
trusts gets ignored:

* **churn** — how many commits touched the file. Code that changes often has
  more chances to be wrong, and is where change will keep landing.
* **fix density** — what fraction of those commits were fixes (message starts
  with `fix`, or says bug/defect/regression). A file changed for features is
  less risky than one changed to correct itself.

Fix density dominates: a doc edited twenty times for content is not risky, a
small module fixed five times out of six touches is. This repository proved the
point in a single session — the files reworked fix after fix (`bgp.py`,
`interface_address.py`, `mvc_merge.py`, `api.py`) are exactly the ones three
independent reviewers converged on. A script would have named them for free.

Usage:
    python3 scripts/risk_map.py                 # ranked table for the tree
    python3 scripts/risk_map.py --top 10        # just the top 10
    python3 scripts/risk_map.py --format md     # markdown, for a CI comment
    python3 scripts/risk_map.py --since 2026-01-01
"""

from __future__ import annotations

import argparse
import math
import subprocess
import sys
from dataclasses import dataclass

# A commit is a fix when its subject begins with one of these, or contains one
# of the words. Conventional-commit `fix:` and `fix(scope):` both start with
# "fix".
_FIX_PREFIXES = ("fix", "bug", "hotfix", "revert")
_FIX_WORDS = ("bugfix", "regression", "defect", "broken", "crash")

# Only rank real source. Tests and docs churn for their own reasons and would
# drown the signal.
_SOURCE_PREFIXES = ("opnsense_mcp/", "scripts/", "deploy/")
_SOURCE_SUFFIXES = (".py", ".sh")

# Test doubles and generated data churn like production but ship to no one, so
# they would crowd out the files a review should actually read.
_NOT_SHIPPING = ("mock_api.py", "risk_map.py")


@dataclass(frozen=True)
class FileRisk:
    """One file's risk row, keeping the inputs so the report can justify itself."""

    path: str
    commits: int
    fixes: int
    lines: int
    score: float

    @property
    def fix_ratio(self) -> float:
        """Fraction of touching commits that were fixes."""
        return self.fixes / self.commits if self.commits else 0.0


def score(stats: dict[str, int]) -> float:
    """Risk score for one file's history.

    churn contributes on a log scale — the difference between 2 and 4 commits
    matters more than between 40 and 42 — and fix density multiplies it, so a
    file that only ever gained features scores near zero however often it
    changed. Size is a mild tie-breaker: a larger risky file is worse than a
    small one, but size alone is not risk.
    """
    commits = stats.get("commits", 0)
    if commits <= 0:
        return 0.0
    fixes = stats.get("fixes", 0)
    lines = stats.get("lines", 0)

    churn = math.log2(commits + 1)
    # (fixes + a little) so a heavily-fixed file always outranks a never-fixed
    # one of the same churn, without a zero collapsing the product entirely.
    fix_weight = (fixes + 0.1) / commits
    size_factor = 1.0 + math.log10(max(lines, 1)) / 10.0

    return round(churn * fix_weight * size_factor * 100, 2)


def rank_files(history: dict[str, dict[str, int]]) -> list[FileRisk]:
    """Score and sort every file, most risky first.

    Ties break by path so the ordering is stable across runs — a report that
    reshuffles run to run is one nobody reads twice.
    """
    rows = [
        FileRisk(
            path=path,
            commits=stats.get("commits", 0),
            fixes=stats.get("fixes", 0),
            lines=stats.get("lines", 0),
            score=score(stats),
        )
        for path, stats in history.items()
    ]
    rows.sort(key=lambda r: (-r.score, r.path))
    return rows


def _is_fix(subject: str) -> bool:
    lowered = subject.strip().lower()
    if lowered.startswith(_FIX_PREFIXES):
        return True
    return any(word in lowered for word in _FIX_WORDS)


def _is_source(path: str) -> bool:
    if any(path.endswith(name) for name in _NOT_SHIPPING):
        return False
    return path.startswith(_SOURCE_PREFIXES) and path.endswith(_SOURCE_SUFFIXES)


def collect_history(since: str | None = None) -> dict[str, dict[str, int]]:
    """Walk git log and count commits and fix-commits per source file.

    No I/O beyond git; safe to run anywhere the repository is checked out.
    """
    args = ["git", "log", "--no-merges", "--format=%x00%s", "--name-only"]
    if since:
        args.append(f"--since={since}")
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout

    history: dict[str, dict[str, int]] = {}
    is_fix = False
    for line in out.splitlines():
        if line.startswith("\x00"):
            is_fix = _is_fix(line[1:])
            continue
        path = line.strip()
        if not path or not _is_source(path):
            continue
        row = history.setdefault(path, {"commits": 0, "fixes": 0, "lines": 0})
        row["commits"] += 1
        if is_fix:
            row["fixes"] += 1

    for path, row in history.items():
        row["lines"] = _line_count(path)
    return history


def _line_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:  # noqa: PTH123
            return sum(1 for _ in handle)
    except OSError:
        return 0  # deleted or moved since; no longer a review target


def _render_table(rows: list[FileRisk], top: int) -> str:
    shown = rows[:top]
    width = max((len(r.path) for r in shown), default=4)
    lines = [f"{'file'.ljust(width)}  score  commits  fixes  fix%"]
    for r in shown:
        lines.append(
            f"{r.path.ljust(width)}  {r.score:5.0f}  {r.commits:7d}  "
            f"{r.fixes:5d}  {r.fix_ratio * 100:3.0f}%"
        )
    return "\n".join(lines)


def _render_markdown(rows: list[FileRisk], top: int) -> str:
    lines = [
        "### Defect-risk map",
        "",
        "Where defects concentrate, from git churn and fix density. Review the "
        "top rows first; this ranks likelihood, it does not find bugs.",
        "",
        "| file | score | commits | fixes | fix % |",
        "|---|--:|--:|--:|--:|",
    ]
    for r in rows[:top]:
        lines.append(
            f"| `{r.path}` | {r.score:.0f} | {r.commits} | {r.fixes} | "
            f"{r.fix_ratio * 100:.0f}% |"
        )
    return "\n".join(lines)


def main() -> int:
    """Print the ranked risk map."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--top", type=int, default=20, help="rows to show")
    parser.add_argument("--since", help="only count commits after this date")
    parser.add_argument("--format", choices=("table", "md"), default="table")
    args = parser.parse_args()

    rows = rank_files(collect_history(since=args.since))
    if not rows:
        print("no source history found", file=sys.stderr)
        return 0
    render = _render_markdown if args.format == "md" else _render_table
    print(render(rows, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
