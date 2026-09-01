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

import pytest

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


# --- what counts as a successful apply -------------------------------------
#
# OPNsense does not answer with one shape. The base service controller returns
# {"status": "ok"}, WireGuard's controller overrides it and returns
# {"result": "ok"}, and unbound's restart answers {"response": "OK"}. Reading
# only "status" made the second and third read as failures, which is the
# direction that trains a caller to ignore `applied: false` — and that flag is
# the whole signal reconcile_npt and apply_ula depend on.


class _ApplyClient:
    """Returns one canned payload from _make_request, recording the call."""

    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str]] = []

    async def _make_request(self, method: str, endpoint: str, **kwargs: object):
        self.calls.append((method, endpoint))
        return self.payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "why"),
    [
        ({"status": "ok"}, "the base service controller"),
        ({"result": "ok"}, "WireGuard's controller override"),
        ({"response": "OK"}, "unbound's restart, uppercase and under `response`"),
        ({"status": "  OK\n"}, "whitespace and case around a known-good value"),
    ],
)
async def test_a_successful_apply_is_recognised_whatever_key_it_uses(
    payload: dict, why: str
) -> None:
    from opnsense_mcp.utils.apply import run_apply

    result = await run_apply(_ApplyClient(payload), "/api/x/service/reconfigure")

    assert result == payload, why


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"status": "failed"},
        {"result": "failed"},
        {"response": "error"},
        # A mixed signal must not be cherry-picked into a success.
        {"status": "ok", "result": "failed"},
    ],
)
async def test_a_refused_apply_is_still_refused(payload: dict) -> None:
    from opnsense_mcp.utils.apply import ApplyError, run_apply

    with pytest.raises(ApplyError):
        await run_apply(_ApplyClient(payload), "/api/x/service/reconfigure")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [{}, {"unrelated": "value"}, [], "OK", {"result": "saved"}]
)
async def test_an_apply_that_says_nothing_is_not_a_success(payload: object) -> None:
    """Silence is not consent: a payload carrying no status at all must refuse
    rather than fall through to success."""
    from opnsense_mcp.utils.apply import ApplyError, run_apply

    with pytest.raises(ApplyError):
        await run_apply(_ApplyClient(payload), "/api/x/service/reconfigure")


@pytest.mark.asyncio
async def test_the_refusal_names_what_came_back() -> None:
    """The message that made #41 legible said what it actually received."""
    from opnsense_mcp.utils.apply import ApplyError, run_apply

    with pytest.raises(ApplyError) as caught:
        await run_apply(_ApplyClient({"status": "wat"}), "/api/x/service/reconfigure")

    assert "wat" in str(caught.value)


@pytest.mark.asyncio
async def test_flush_dns_reports_the_applied_flag_it_was_given() -> None:
    """`restart_unbound` returns `applied: False` on a refused restart and its
    docstring says the caller must read the flag. flush_dns hardcoded
    `applied: True`, so the tool claimed an apply its own payload denied."""
    from opnsense_mcp.tools.flush_dns import FlushDnsTool

    class _RefusingClient:
        async def restart_unbound(self) -> dict:
            return {
                "status": "failed",
                "applied": False,
                "apply_error": "service refused",
            }

    result = await FlushDnsTool(_RefusingClient()).execute({"mode": "restart"})

    assert result["applied"] is False
    assert result.get("apply_error")


@pytest.mark.asyncio
async def test_flush_dns_still_reports_a_real_restart_as_applied() -> None:
    from opnsense_mcp.tools.flush_dns import FlushDnsTool

    class _WorkingClient:
        async def restart_unbound(self) -> dict:
            return {"response": "OK", "applied": True}

    result = await FlushDnsTool(_WorkingClient()).execute({"mode": "restart"})

    assert result["status"] == "success"
    assert result["applied"] is True
