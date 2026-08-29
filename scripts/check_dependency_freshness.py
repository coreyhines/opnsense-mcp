#!/usr/bin/env python3
"""Report declared dependencies that are behind their latest stable release.

Run by `.forgejo/workflows/dependency-freshness.yml` on a schedule. Exits 1 when
something is behind, so the workflow can raise it; exits 0 when everything is
current.

Prereleases are only acceptable when the declared floor names one, which is how
fastmcp 4 is pinned. Anything else on a prerelease is drift, not a decision.

Usage:
    uv run python scripts/check_dependency_freshness.py
    uv run python scripts/check_dependency_freshness.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

REPO = Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"
PYPI = "https://pypi.org/pypi/{}/json"


def _declared() -> dict[str, str]:
    """Every runtime and dev dependency with its declared specifier."""
    data = tomllib.loads(PYPROJECT.read_text())
    specs: list[str] = list(data["project"].get("dependencies", []))
    for group in data.get("dependency-groups", {}).values():
        specs.extend(s for s in group if isinstance(s, str))

    out: dict[str, str] = {}
    for spec in specs:
        match = re.match(r"^([A-Za-z][A-Za-z0-9._-]*)\s*(.*)$", spec)
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _latest_stable(name: str) -> str | None:
    """The newest non-prerelease release on PyPI, or None when unreachable."""
    try:
        with urllib.request.urlopen(PYPI.format(name), timeout=20) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    best: Version | None = None
    for raw, files in data.get("releases", {}).items():
        if not files:
            continue
        try:
            candidate = Version(raw)
        except InvalidVersion:
            continue
        if candidate.is_prerelease or candidate.is_devrelease:
            continue
        if best is None or candidate > best:
            best = candidate
    return str(best) if best else None


def _installed(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def survey() -> list[dict[str, Any]]:
    """One row per declared dependency, newest first among the stale ones."""
    rows: list[dict[str, Any]] = []
    for name, spec in sorted(_declared().items()):
        have = _installed(name)
        latest = _latest_stable(name)
        deliberate_pre = bool(re.search(r"\d+\.\d+\.\d+(a|b|rc)\d+", spec))

        state = "current"
        if have is None:
            state = "not installed"
        elif latest is None:
            state = "unknown"
        else:
            try:
                have_v, latest_v = Version(have), Version(latest)
            except InvalidVersion:
                state = "unknown"
            else:
                if have_v.is_prerelease or have_v.is_devrelease:
                    state = "prerelease (declared)" if deliberate_pre else "prerelease"
                elif have_v < latest_v:
                    state = "behind"
        rows.append(
            {
                "name": name,
                "specifier": spec,
                "installed": have,
                "latest_stable": latest,
                "state": state,
            }
        )
    return rows


def main() -> int:
    """Print the survey and signal whether anything needs attention."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    rows = survey()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        width = max(len(r["name"]) for r in rows)
        for row in rows:
            mark = "" if row["state"] == "current" else f"  <- {row['state']}"
            print(
                f"{row['name']:{width}}  {str(row['installed']):14}"
                f"{str(row['latest_stable']):14}{mark}"
            )

    needs_attention = [r for r in rows if r["state"] in ("behind", "prerelease")]
    if needs_attention:
        print(
            "\n"
            + "\n".join(
                f"{r['name']}: {r['installed']} -> {r['latest_stable']} ({r['state']})"
                for r in needs_attention
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
