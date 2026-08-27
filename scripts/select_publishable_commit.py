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

Usage:
    python3 scripts/select_publishable_commit.py --published <sha> --candidates <file>
    python3 scripts/select_publishable_commit.py --api-base <url> --repo owner/name ...

Prints the chosen SHA, or nothing and exits 3 when no commit qualifies.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

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


def fetch_runs(api_base: str, repo: str, limit: int = 100) -> dict[str, list[dict]]:
    """Group recent workflow runs by the commit they ran on.

    Unauthenticated: the repository is public, and the publisher should need
    only the one credential that writes to the published copy.
    """
    url = f"{api_base.rstrip('/')}/repos/{repo}/actions/runs?limit={limit}"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        payload = json.load(response)

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
    parser.add_argument("--api-base", required=True, help="Forgejo API base URL")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument(
        "--published",
        default="",
        help="SHA already published, so an unchanged result can be reported",
    )
    args = parser.parse_args()

    candidates = [
        line.strip()
        for line in open(args.candidates, encoding="utf-8")  # noqa: SIM115, PTH123
        if line.strip()
    ]
    if not candidates:
        print("Nothing new to consider; published copy is up to date.", file=sys.stderr)
        return NOTHING_PUBLISHABLE

    runs = fetch_runs(args.api_base, args.repo)
    chosen = select_publishable(candidates, runs)

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
