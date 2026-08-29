"""The image installs from requirements.txt, not from pyproject.

`deploy/Containerfile` runs `pip install -r requirements.txt`, so a dependency
bumped only in `pyproject.toml` ships the old version to production while every
local test passes. That happened: pyproject moved to the fastmcp 4 beta for MCP
2026-07-28 while requirements.txt still pinned `fastmcp>=3.2.4,<4`, which can
never reach the new spec.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"
REQUIREMENTS = REPO / "requirements.txt"

# Packages whose version choice decides what the deployed server can speak.
# A mismatch here is a production defect, not a style issue.
PINNED_IN_BOTH = ("fastmcp",)


def _specifier(text: str, package: str) -> str | None:
    """The version specifier for a package, ignoring comments and extras."""
    pattern = re.compile(
        rf'^\s*"?{re.escape(package)}(?P<spec>[<>=!~][^"#\n]*)', re.MULTILINE
    )
    match = pattern.search(text)
    return match.group("spec").strip().rstrip(",").strip() if match else None


def test_the_deployed_pins_match_the_developed_ones() -> None:
    """requirements.txt is what production gets; it must not lag pyproject."""
    pyproject = PYPROJECT.read_text()
    requirements = REQUIREMENTS.read_text()

    for package in PINNED_IN_BOTH:
        developed = _specifier(pyproject, package)
        deployed = _specifier(requirements, package)
        assert developed, f"{package} not pinned in pyproject.toml"
        assert deployed, f"{package} not pinned in requirements.txt"
        assert developed == deployed, (
            f"{package} is {developed} in pyproject.toml but {deployed} in "
            f"requirements.txt; the image installs the latter"
        )


def test_a_prerelease_pin_is_explicit_enough_for_pip() -> None:
    """pip only installs a prerelease when the specifier names one.

    `fastmcp>=4,<5` would silently resolve to nothing installable while
    `fastmcp>=4.0.0b5,<5` works, so the beta digits are load-bearing.
    """
    deployed = _specifier(REQUIREMENTS.read_text(), "fastmcp")
    assert deployed

    if "4." in deployed:
        assert re.search(r"\d+\.\d+\.\d+(a|b|rc)\d+", deployed), (
            "the fastmcp 4 line is a prerelease; the pin must spell out the "
            f"prerelease version or pip will refuse it: {deployed}"
        )
