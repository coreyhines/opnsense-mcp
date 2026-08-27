#!/usr/bin/env python3
"""Pick the newest commit on main that passed every gate, for publishing.

The public copy of this repository is a publication, not a mirror: a commit
appears there only once CI and the security scanners have passed on it. A
Forgejo push mirror cannot express that, because it replicates refs without
knowing anything about CI, so this makes the decision instead.

What the guarantee actually is: **the published branch always points at a commit
that passed every gate**. It is not that every commit in the published history
passed, because pushing a tip brings its ancestors along, red ones included.

Reading the results rather than chaining onto the pipeline is deliberate.
`needs:` cannot cross workflow files, and the gates are split across `ci.yml`
and `security.yml` on purpose, so a publish job appended to either one would see
only half of them.

This makes no network calls. The caller fetches the runs listing and passes the
file, which keeps the decision pure and testable, and keeps a URL built from an
argument away from urllib, which honours file:// and would happily read a local
path.

Usage:
    python3 scripts/select_publishable_commit.py \
        --candidates <file> --runs <file> [--published <sha>]

Prints the chosen SHA, or nothing and exits 3 when no commit qualifies.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Both must have run and passed. Checking only "nothing failed" would publish a
# commit whose CI never triggered at all, which fails open in exactly the way a
# stale allowlist does.
REQUIRED_WORKFLOWS = ("ci.yml", "security.yml")

SUCCESS = "success"

NOTHING_PUBLISHABLE = 3


def select_publishable(
    candidates: list[str],
    runs_by_sha: dict[str, list[dict]],
    required: tuple[str, ...] = REQUIRED_WORKFLOWS,
) -> str | None:
    """Return the newest qualifying SHA, or None.

    `candidates` is in history order, oldest first. A SHA qualifies when every
    required workflow ran on it and every run recorded for it succeeded, so a
    scanner added later counts from the moment it exists.
    """
    for sha in reversed(candidates):
        runs = runs_by_sha.get(sha) or []
        if not runs:
            continue
        if any(run.get("status") != SUCCESS for run in runs):
            continue
        ran = {run.get("workflow_id") for run in runs}
        if not set(required).issubset(ran):
            continue
        return sha
    return None


def group_runs_by_commit(payload: dict) -> dict[str, list[dict]]:
    """Group a Forgejo actions/runs response by the commit each run ran on."""
    grouped: dict[str, list[dict]] = {}
    for run in payload.get("workflow_runs", []):
        sha = run.get("commit_sha") or run.get("head_sha") or ""
        if sha:
            grouped.setdefault(sha, []).append(run)
    return grouped


def main() -> int:
    """Resolve the publishable commit and print it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidates",
        required=True,
        help="file of candidate SHAs, oldest first (git rev-list --reverse)",
    )
    parser.add_argument(
        "--runs",
        required=True,
        help="file holding a Forgejo actions/runs response, fetched by the caller",
    )
    parser.add_argument(
        "--published",
        default="",
        help="SHA already published, so an unchanged result can be reported",
    )
    args = parser.parse_args()

    candidates = [
        line.strip()
        for line in pathlib.Path(args.candidates)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if not candidates:
        print("Nothing new to consider; published copy is up to date.", file=sys.stderr)
        return NOTHING_PUBLISHABLE

    payload = json.loads(pathlib.Path(args.runs).read_text(encoding="utf-8"))
    chosen = select_publishable(candidates, group_runs_by_commit(payload))

    if chosen is None:
        # Loud on purpose. A publisher that quietly does nothing looks identical
        # to one that is working, which is how CI stayed red for 68 runs without
        # anyone noticing.
        print(
            f"No publishable commit among the {len(candidates)} newer than "
            f"{args.published or '(nothing)'}. Every one either failed a gate, "
            f"is still running, or has no runs recorded. Nothing published.",
            file=sys.stderr,
        )
        return NOTHING_PUBLISHABLE

    print(chosen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
