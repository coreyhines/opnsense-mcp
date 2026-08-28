"""The defect-risk map: rank files by how likely they are to harbour bugs.

This finds no bugs. It finds where bugs concentrate, from git history alone, so
an expensive review reads the risky 15% rather than the whole tree. The signal
is the one the research consistently backs and this project demonstrated
repeatedly: files that change often, and especially files whose changes are
fixes, are where the next fix will be.
"""

from __future__ import annotations

from scripts.risk_map import FileRisk, rank_files, score


def test_a_file_touched_by_more_fixes_ranks_above_a_quiet_one() -> None:
    history = {
        "opnsense_mcp/tools/bgp.py": {"commits": 12, "fixes": 8, "lines": 600},
        "opnsense_mcp/tools/arp.py": {"commits": 2, "fixes": 0, "lines": 60},
    }

    ranked = rank_files(history)

    assert ranked[0].path == "opnsense_mcp/tools/bgp.py"
    assert ranked[0].score > ranked[1].score


def test_fix_density_outweighs_raw_churn() -> None:
    """A file changed often for features is less risky than one changed for fixes.

    A doc file edited 20 times, never to fix a defect, must not outrank a small
    module fixed 5 times out of 6 touches.
    """
    churny_but_clean = score({"commits": 20, "fixes": 0, "lines": 400})
    small_but_fixy = score({"commits": 6, "fixes": 5, "lines": 120})

    assert small_but_fixy > churny_but_clean


def test_a_never_fixed_file_scores_low_even_when_large() -> None:
    assert score({"commits": 3, "fixes": 0, "lines": 5000}) < score(
        {"commits": 3, "fixes": 3, "lines": 100}
    )


def test_score_is_stable_and_ordered() -> None:
    """Ranking must be deterministic — a report that reshuffles is not trusted."""
    history = {
        "a.py": {"commits": 5, "fixes": 2, "lines": 100},
        "b.py": {"commits": 5, "fixes": 2, "lines": 100},
        "c.py": {"commits": 10, "fixes": 5, "lines": 100},
    }

    first = [f.path for f in rank_files(history)]
    second = [f.path for f in rank_files(history)]

    assert first == second
    assert first[0] == "c.py"


def test_zero_commits_does_not_divide_by_zero() -> None:
    assert score({"commits": 0, "fixes": 0, "lines": 0}) == 0.0


def test_rank_returns_typed_rows_with_the_inputs_kept() -> None:
    """The report shows why a file ranks where it does, so the row keeps them."""
    ranked = rank_files({"x.py": {"commits": 4, "fixes": 3, "lines": 200}})

    row = ranked[0]
    assert isinstance(row, FileRisk)
    assert row.commits == 4
    assert row.fixes == 3
    assert row.fix_ratio == 0.75
