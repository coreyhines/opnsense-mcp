"""Every apply must read what the service answered.

`opnsense_mcp/utils/apply.py` was written after adversarial review found two
defects, and its docstring names both: nothing read the reconfigure's response
document, and the reconfigure sat inside the write's `try` so an apply failure
was reported as the write failing.

That fix was available, correct, and shared -- and twenty call sites across nine
files never adopted it, including three added during the very wave that wrote
two more uses of it. One of those three was in a file the coordinator had just
finished editing by hand.

So the rule is not "remember to use run_apply". The rule is this test.

A call is an apply when it passes ``call_class="apply"``. Every one must reach
the service through :func:`opnsense_mcp.utils.apply.run_apply`, which reads the
``{"status": ...}`` document a service controller returns -- the client raises
only on ``{"result": "failed"}``, so a configd refusal arrives as HTTP 200 and
is otherwise invisible.
"""

from __future__ import annotations

import ast
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "opnsense_mcp"

# The one module allowed to issue a raw apply: it is the wrapper itself.
_APPLY_MODULE = PACKAGE / "utils" / "apply.py"

# Sites that must stay raw, each with the reason. Grow this only for a call
# that genuinely cannot go through run_apply -- not for one that has not been
# converted yet. An unconverted site is a failing test, which is the point.
ALLOWED_RAW_APPLIES: dict[tuple[str, str], str] = {}


def _raw_apply_sites() -> list[tuple[str, int, str]]:
    """Every `call_class="apply"` call that is not a run_apply call.

    Matched on the keyword argument rather than on an endpoint name, because
    the endpoints are inconsistent (`service/reconfigure`, `filter/apply`,
    `vip_settings/reconfigure`) while the call class is what the client keys
    its rate limiting and semantics off.
    """
    sites: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path == _APPLY_MODULE:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            applies = any(
                kw.arg == "call_class"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == "apply"
                for kw in node.keywords
            )
            if applies:
                sites.append(
                    (
                        str(path.relative_to(REPO_ROOT)),
                        node.lineno,
                        ast.unparse(node.func),
                    )
                )
    return sites


def test_every_apply_goes_through_run_apply() -> None:
    """A raw apply cannot tell a reloaded service from one that refused."""
    offenders = [
        (path, line, func)
        for path, line, func in _raw_apply_sites()
        if (path, func) not in ALLOWED_RAW_APPLIES
    ]

    assert not offenders, (
        "these calls apply without reading what the service answered; route "
        "them through opnsense_mcp.utils.apply.run_apply, or add the site to "
        "ALLOWED_RAW_APPLIES with the reason it cannot: "
        + ", ".join(f"{p}:{line} ({func})" for p, line, func in offenders)
    )


def test_run_apply_is_actually_imported_where_applies_happen() -> None:
    """A module that applies must import the wrapper, not shadow it locally."""
    missing: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path == _APPLY_MODULE:
            continue
        source = path.read_text()
        if "run_apply(" not in source:
            continue
        tree = ast.parse(source, filename=str(path))
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "opnsense_mcp.utils.apply"
            and any(alias.name == "run_apply" for alias in node.names)
            for node in ast.walk(tree)
        )
        if not imported:
            missing.append(str(path.relative_to(REPO_ROOT)))

    assert not missing, (
        "these modules call run_apply without importing it from "
        "opnsense_mcp.utils.apply: " + ", ".join(missing)
    )


def test_the_allowlist_does_not_name_a_site_that_no_longer_exists() -> None:
    """A stale exemption hides the next real one behind a name nobody reads."""
    live = {(path, func) for path, _line, func in _raw_apply_sites()}
    stale = sorted(set(ALLOWED_RAW_APPLIES) - live)

    assert not stale, f"allowlist entries with no matching call site: {stale}"
