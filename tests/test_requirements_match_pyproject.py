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

REQUIREMENTS_DEV = REPO / "requirements-dev.txt"


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


def _pins(text: str) -> dict[str, str]:
    """Every `name>=version` pin in a requirements file or dependency list."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip().strip('",')
        if stripped.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9._-]*)\s*([<>=!~].*)$", stripped)
        if match:
            found[match.group(1).lower()] = match.group(2).split("#")[0].strip()
    return found


def _dev_group() -> dict[str, str]:
    """The `dev` entries from pyproject's [dependency-groups]."""
    text = PYPROJECT.read_text()
    start = text.index("dev = [") + len("dev = [")
    return _pins(text[start : text.index("]", start)])


def test_the_dev_tools_match_between_ci_and_uv() -> None:
    """CI installs requirements-dev.txt; `uv sync` installs the group.

    When they disagree, a check can pass locally and skip in CI, or the other
    way round, and nothing says so.
    """
    in_file = _pins(REQUIREMENTS_DEV.read_text())
    in_group = _dev_group()

    only_file = sorted(set(in_file) - set(in_group))
    only_group = sorted(set(in_group) - set(in_file))
    assert not only_file, f"in requirements-dev.txt but not the dev group: {only_file}"
    assert not only_group, (
        f"in the dev group but not requirements-dev.txt: {only_group}"
    )

    differing = sorted(k for k in in_file if in_file[k] != in_group[k])
    assert not differing, f"dev pins differ between the two files: {differing}"


def test_no_second_formatter_is_declared() -> None:
    """ruff format is the formatter. black would fight it over the same files."""
    for path in (REQUIREMENTS_DEV, PYPROJECT):
        assert "black" not in _pins(path.read_text()), (
            f"{path.name} declares black; ruff format already owns formatting"
        )


def test_the_server_bootstrap_holds_no_hand_written_pin_list() -> None:
    """A third copy of the dependencies drifts, and the last one did.

    `_ensure_runtime_deps` used to carry its own list, which had rotted to
    `fastmcp>=0.1.0` while the project moved to fastmcp 4. It reads the
    package metadata now, so there is nothing left to drift.
    """
    source = (REPO / "opnsense_mcp" / "server.py").read_text()
    body = source[source.index("def _ensure_runtime_deps") :]
    body = body[: body.index("\ndef ")]

    # Only quoted requirement strings count. Bare `name = value` lines are
    # ordinary Python assignments, and comments may quote the old pin in prose.
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )
    # A real pin has a version after the operator; `extra == "x"` does not.
    quoted = [
        spec
        for spec in re.findall(r'"([A-Za-z][A-Za-z0-9._-]*\s*[<>=!~]=?[^"]*)"', code)
        if re.search(r"[<>=!~]=?\s*\d", spec)
    ]
    assert not quoted, f"bootstrap re-grew a hand-written pin list: {sorted(quoted)}"
