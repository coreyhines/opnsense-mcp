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

A call is an apply when it passes ``call_class="apply"``, or when it POSTs to an
endpoint ending in ``/reconfigure``, ``/apply``, or ``/restart``. Every one must
reach the service through :func:`opnsense_mcp.utils.apply.run_apply`, which reads
the ``{"status": ...}`` document a service controller returns -- the client raises
only on ``{"result": "failed"}``, so a configd refusal arrives as HTTP 200 and
is otherwise invisible.

The endpoint-suffix scan exists because DHCP providers issued raw
``_request("POST", ".../reconfigure")`` with no ``call_class`` keyword, so the
keyword-only check passed vacuously while refused applies still read as success
(issue #98).
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

# Endpoint path suffixes that always mean "apply the staged config".
_APPLY_ENDPOINT_SUFFIXES = ("/reconfigure", "/apply", "/restart")


def _func_name(func: ast.AST) -> str:
    """Best-effort callable name for an AST Call node."""
    return ast.unparse(func)


def _is_run_apply_call(node: ast.Call) -> bool:
    """True when the Call is ``run_apply(...)`` (bare or attribute)."""
    name = _func_name(node.func)
    return name == "run_apply" or name.endswith(".run_apply")


def _literal_str(node: ast.AST | None) -> str | None:
    """Return a string Constant's value, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_string_bindings(tree: ast.AST) -> dict[str, str]:
    """Map simple names / Class.attr / dict[key] to string endpoint constants."""
    bindings: dict[str, str] = {}

    def _bind_target(target: ast.AST, value: str) -> None:
        if isinstance(target, ast.Name):
            bindings[target.id] = value
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            # self.RECONFIGURE_ENDPOINT inside methods resolves via Class.attr
            bindings[f"{target.value.id}.{target.attr}"] = value
            bindings[target.attr] = value

    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            literal = _literal_str(node.value)
            if literal is not None:
                _bind_target(node.targets[0], literal)
            elif isinstance(node.value, ast.Dict):
                dict_name = (
                    node.targets[0].id
                    if isinstance(node.targets[0], ast.Name)
                    else None
                )
                for key_node, val_node in zip(
                    node.value.keys, node.value.values, strict=False
                ):
                    key = _literal_str(key_node)
                    val = _literal_str(val_node)
                    if key is not None and val is not None:
                        bindings[f"{dict_name}[{key!r}]"] = val
                        if dict_name:
                            bindings[f"{dict_name}[{key}]"] = val
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.Assign) and len(item.targets) == 1:
                    literal = _literal_str(item.value)
                    if literal is None:
                        continue
                    target = item.targets[0]
                    if isinstance(target, ast.Name):
                        bindings[target.id] = literal
                        bindings[f"{node.name}.{target.id}"] = literal
                        bindings[f"self.{target.id}"] = literal
                elif isinstance(item, ast.AnnAssign) and item.value is not None:
                    literal = _literal_str(item.value)
                    if literal is None or not isinstance(item.target, ast.Name):
                        continue
                    bindings[item.target.id] = literal
                    bindings[f"{node.name}.{item.target.id}"] = literal
                    bindings[f"self.{item.target.id}"] = literal
    return bindings


def _resolve_endpoint(node: ast.AST, bindings: dict[str, str]) -> str | None:
    """Resolve a Call argument to an endpoint string when possible."""
    literal = _literal_str(node)
    if literal is not None:
        return literal
    if isinstance(node, ast.Name) and node.id in bindings:
        return bindings[node.id]
    if isinstance(node, ast.Attribute):
        key = ast.unparse(node)
        if key in bindings:
            return bindings[key]
        if isinstance(node.value, ast.Name) and node.attr in bindings:
            return bindings[node.attr]
    if isinstance(node, ast.Subscript):
        key = ast.unparse(node)
        if key in bindings:
            return bindings[key]
        # DNSMASQ["reconfigure"] with Name slice as Constant
        if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant):
            alt = f"{node.value.id}[{node.slice.value!r}]"
            if alt in bindings:
                return bindings[alt]
    return None


def _is_apply_endpoint(endpoint: str) -> bool:
    """True when the path is a service apply/reconfigure/restart."""
    path = endpoint.split("?", 1)[0].rstrip("/")
    return any(path.endswith(suffix) for suffix in _APPLY_ENDPOINT_SUFFIXES)


def _call_is_post(node: ast.Call) -> bool:
    """True when the first positional arg is the HTTP method POST."""
    if not node.args:
        return False
    method = _literal_str(node.args[0])
    return method is not None and method.upper() == "POST"


def _raw_apply_sites() -> list[tuple[str, int, str]]:
    """Every raw apply that is not a ``run_apply`` call.

    Two shapes:

    1. ``call_class="apply"`` on any Call outside ``apply.py``.
    2. ``POST`` to an endpoint ending in ``/reconfigure``, ``/apply``, or
       ``/restart`` that is not itself a ``run_apply`` call.
    """
    sites: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path == _APPLY_MODULE:
            continue
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        bindings = _collect_string_bindings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_run_apply_call(node):
                continue

            applies_kw = any(
                kw.arg == "call_class"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == "apply"
                for kw in node.keywords
            )
            endpoint: str | None = None
            if len(node.args) >= 2 and _call_is_post(node):
                endpoint = _resolve_endpoint(node.args[1], bindings)
            endpoint_apply = bool(endpoint and _is_apply_endpoint(endpoint))

            if applies_kw or endpoint_apply:
                sites.append(
                    (
                        str(path.relative_to(REPO_ROOT)),
                        node.lineno,
                        _func_name(node.func),
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


def test_endpoint_scan_sees_a_raw_reconfigure_post() -> None:
    """Falsify: a bare ``_request`` to ``.../reconfigure`` must be an offender.

    Before #98 the keyword-only scan returned an empty list while DHCP providers
    discarded reconfigure responses. This pins the suffix scan itself.
    """
    source = """
class P:
    RECONFIGURE_ENDPOINT = "/api/dnsmasq/service/reconfigure"

    async def _reconfigure(self):
        await self._request("POST", self.RECONFIGURE_ENDPOINT)
"""
    tree = ast.parse(source)
    bindings = _collect_string_bindings(tree)
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _is_run_apply_call(node):
            continue
        if len(node.args) >= 2 and _call_is_post(node):
            endpoint = _resolve_endpoint(node.args[1], bindings)
            if endpoint and _is_apply_endpoint(endpoint):
                hits.append(_func_name(node.func))
    assert hits == ["self._request"]


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


# --- DHCP provider apply phase (#98) ---------------------------------------


@pytest.mark.asyncio
async def test_dnsmasq_delete_host_refused_apply_is_not_a_failed_write() -> None:
    """A configd refusal must leave the delete as success with applied=false."""
    from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider

    calls: list[tuple[str, str]] = []

    async def fake_request(method: str, endpoint: str, **kwargs: object) -> dict:
        calls.append((method, endpoint))
        if "search_host" in endpoint:
            return {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "h1",
                        "ip": "172.20.2.4,::4",
                        "hwaddr": "52:54:00:b3:02:20",
                    }
                ],
                "total": 1,
            }
        if "del_host" in endpoint:
            return {"result": "deleted"}
        if "reconfigure" in endpoint:
            return {"status": "failed"}
        return {}

    result = await DnsmasqProvider(fake_request).delete_host(
        identifier="h1", dry_run=False
    )

    assert result["status"] == "success"
    assert result["deleted"]["host"] == "h1"
    assert result["applied"] is False
    assert "apply_error" in result
    assert any("del_host" in endpoint for _method, endpoint in calls)
    assert any("reconfigure" in endpoint for _method, endpoint in calls)


@pytest.mark.asyncio
async def test_dnsmasq_delete_host_apply_uses_call_class_apply() -> None:
    """Providers must not ride the short-session read lock for reconfigure."""
    from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider

    seen: list[dict] = []

    async def fake_request(method: str, endpoint: str, **kwargs: object) -> dict:
        seen.append({"method": method, "endpoint": endpoint, **kwargs})
        if "search_host" in endpoint:
            return {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "h1",
                        "ip": "172.20.2.4",
                        "hwaddr": "aa:bb:cc:dd:ee:ff",
                    }
                ]
            }
        if "del_host" in endpoint:
            return {"result": "deleted"}
        if "reconfigure" in endpoint:
            return {"status": "ok"}
        return {}

    result = await DnsmasqProvider(fake_request).delete_host(
        identifier="h1", dry_run=False
    )

    assert result["status"] == "success"
    assert result["applied"] is True
    reconfigure = next(c for c in seen if "reconfigure" in c["endpoint"])
    assert reconfigure["method"] == "POST"
    assert reconfigure.get("call_class") == "apply"


@pytest.mark.asyncio
async def test_kea_subnet_dns_refused_apply_keeps_the_write() -> None:
    """Kea must not report a refused reconfigure as a failed subnet write."""
    from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider

    async def fake_request(method: str, endpoint: str, **kwargs: object) -> dict:
        if "search_subnet" in endpoint:
            return {
                "rows": [
                    {
                        "uuid": "subnet-v4",
                        "subnet": "172.20.2.0/24",
                        "interface": "opt2",
                    }
                ]
            }
        if "get_subnet" in endpoint:
            return {
                "subnet4": {
                    "uuid": "subnet-v4",
                    "subnet": "172.20.2.0/24",
                    "interface": "opt2",
                    "option_data_autocollect": "1",
                    "option_data": {
                        "domain_name_servers": {
                            "value": "172.20.10.5",
                            "selected": 1,
                        }
                    },
                }
            }
        if "set_subnet" in endpoint:
            return {"result": "saved"}
        if "reconfigure" in endpoint:
            return {"status": "failed"}
        return {}

    result = await KeaProvider(fake_request).set_subnet_dns(
        subnet="172.20.2.0/24",
        family="ipv4",
        servers=["172.20.10.4"],
    )

    assert result["status"] == "success"
    assert result["applied"] is False
    assert "apply_error" in result
