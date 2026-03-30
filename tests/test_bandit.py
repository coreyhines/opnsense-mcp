"""Test that Bandit reports no unacknowledged security issues."""

import json
import subprocess


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
            "-c",
            "pyproject.toml",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return  # No issues found

    report = json.loads(result.stdout)
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
