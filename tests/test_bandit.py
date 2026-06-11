"""Test that Bandit reports no unacknowledged security issues."""

import json
import subprocess


def _load_bandit_report(stdout: str) -> dict:
    """Parse Bandit JSON output, ignoring optional progress-bar prefix lines."""
    start = stdout.find("{")
    if start == -1:
        msg = f"Bandit produced no JSON output:\n{stdout}"
        raise AssertionError(msg)
    return json.loads(stdout[start:])


def test_bandit_clean():
    """Run Bandit and assert zero findings (nosec-suppressed lines are excluded)."""
    result = subprocess.run(
        [
            "python",
            "-m",
            "bandit",
            "-r",
            "opnsense_mcp/",
            "-f",
            "json",
            "-q",
            "-c",
            "pyproject.toml",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return  # No issues found

    report = _load_bandit_report(result.stdout)
    results = report.get("results", [])
    if results:
        messages = []
        for r in results:
            messages.append(
                f"  {r['filename']}:{r['line_number']} {r['test_id']} {r['issue_text']}"
            )
        raise AssertionError(
            f"Bandit found {len(results)} issue(s):\n" + "\n".join(messages)
        )
