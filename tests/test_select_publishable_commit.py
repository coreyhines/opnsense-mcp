"""Choosing which commit is safe to publish.

The publisher pushes one commit to the public copy and nothing else decides for
it, so this is the whole gate. Two failure modes matter more than the happy
path: publishing something that did not pass, and never publishing at all while
appearing to work.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from select_publishable_commit import (  # noqa: E402
    REQUIRED_WORKFLOWS,
    group_runs_by_commit,
    select_publishable,
)

OLD, MID, NEW = "aaa1111", "bbb2222", "ccc3333"


def _green(*workflows: str) -> list[dict]:
    return [{"workflow_id": w, "status": "success"} for w in workflows]


def _all_green() -> list[dict]:
    return _green(*REQUIRED_WORKFLOWS)


def test_picks_the_newest_commit_that_passed_everything() -> None:
    runs = {OLD: _all_green(), MID: _all_green(), NEW: _all_green()}

    assert select_publishable([OLD, MID, NEW], runs) == NEW


def test_skips_a_red_tip_and_takes_the_newest_green_commit_below_it() -> None:
    """Main going red must not block publishing what already passed."""
    runs = {
        OLD: _all_green(),
        MID: _all_green(),
        NEW: _green("security.yml") + [{"workflow_id": "ci.yml", "status": "failure"}],
    }

    assert select_publishable([OLD, MID, NEW], runs) == MID


def test_a_commit_with_no_runs_is_not_publishable() -> None:
    """Absence of a failure is not evidence of a pass."""
    assert select_publishable([OLD], {OLD: []}) is None
    assert select_publishable([OLD], {}) is None


def test_a_missing_required_workflow_is_not_publishable() -> None:
    """Otherwise the gate opens whenever a workflow fails to trigger at all.

    Requiring only "no run failed" passes a commit where CI never ran, which is
    the same fail-open shape as an allowlist that nobody updated.
    """
    runs = {NEW: _green("security.yml")}

    assert select_publishable([NEW], runs) is None


def test_an_unfinished_run_is_not_publishable() -> None:
    """A verdict that has not arrived is not a pass."""
    for state in ("running", "waiting", ""):
        runs = {
            NEW: _green("ci.yml") + [{"workflow_id": "security.yml", "status": state}]
        }
        assert select_publishable([NEW], runs) is None, state


def test_returns_nothing_when_no_commit_qualifies() -> None:
    runs = {OLD: [{"workflow_id": w, "status": "failure"} for w in REQUIRED_WORKFLOWS]}

    assert select_publishable([OLD], runs) is None


def test_extra_workflows_must_also_be_green() -> None:
    """A new scanner counts the moment it exists, with no list to update."""
    runs = {NEW: _all_green() + [{"workflow_id": "nightly.yml", "status": "failure"}]}

    assert select_publishable([NEW], runs) is None


def test_candidate_order_is_oldest_first() -> None:
    """The caller passes history order; reversing it would publish the oldest."""
    runs = {OLD: _all_green(), NEW: _all_green()}

    assert select_publishable([OLD, NEW], runs) == NEW
    assert select_publishable([NEW, OLD], runs) == OLD


def test_runs_are_grouped_by_the_commit_they_ran_on() -> None:
    """The API keys this `commit_sha`; grouping is the only parsing step left."""
    payload = {
        "workflow_runs": [
            {"commit_sha": NEW, "workflow_id": "ci.yml", "status": "success"},
            {"commit_sha": NEW, "workflow_id": "security.yml", "status": "success"},
            {"commit_sha": OLD, "workflow_id": "ci.yml", "status": "failure"},
        ]
    }

    grouped = group_runs_by_commit(payload)

    assert set(grouped) == {NEW, OLD}
    assert len(grouped[NEW]) == 2
    assert select_publishable([OLD, NEW], grouped) == NEW


def test_a_run_with_no_commit_is_dropped() -> None:
    """A run that names no commit cannot vouch for one."""
    grouped = group_runs_by_commit({"workflow_runs": [{"workflow_id": "ci.yml"}]})

    assert grouped == {}
