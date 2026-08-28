"""Grouped-surface inconsistencies found by live MCP testing (issue #23).

Individually minor, collectively they make the surface hard to program
against: a caller cannot tell "the operation failed" from "the operation ran
and found something", cannot assert on a delete uniformly, and reads a label
that contradicts what happened.

Assertions here are on structured fields, never on message wording.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# --- 1. A successful audit that found problems is not an error --------------


def _audit_tool_with(findings_severity: str | None) -> Any:
    """An AuditShaperConfigTool whose audit yields one finding of a severity."""
    from opnsense_mcp.tools import shaper_audit
    from opnsense_mcp.utils.shaper_audit_rules import AuditFinding, AuditResult

    class Client:
        async def _make_request(self, *a: Any, **k: Any) -> dict[str, Any]:
            return {"rows": [], "items": [], "status": "ok"}

    tool = shaper_audit.AuditShaperConfigTool(Client())
    findings = (
        []
        if findings_severity is None
        else [AuditFinding(severity=findings_severity, code="X", message="m")]
    )
    status = "success" if findings_severity is None else findings_severity
    result = AuditResult(status=status, score=75, findings=findings, summary_lines=[])

    original = shaper_audit.run_audit
    shaper_audit.run_audit = lambda **_kw: result  # type: ignore[assignment]
    tool._restore = lambda: setattr(shaper_audit, "run_audit", original)  # noqa: SLF001
    return tool


def test_an_audit_that_found_problems_still_reports_that_it_ran() -> None:
    """`status` says whether the audit ran; severity lives in the payload.

    A caller checking `status == 'success'` could not tell "the audit failed to
    run" from "the config has findings", which is the one question `status` is
    for.
    """
    tool = _audit_tool_with("error")
    try:
        result = asyncio.run(tool.execute({}))
    finally:
        tool._restore()  # noqa: SLF001

    assert result["status"] == "success"
    structured = result.get("structured") or result
    assert structured["audit_status"] == "error"
    assert structured["score"] == 75


def test_an_audit_that_cannot_run_is_still_an_error() -> None:
    """A genuine failure must not be flattened into success."""
    from opnsense_mcp.tools.shaper_audit import AuditShaperConfigTool

    class Broken:
        async def _make_request(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise RuntimeError("shaper unreachable")

    result = asyncio.run(AuditShaperConfigTool(Broken()).execute({}))

    assert result["status"] == "error"


# --- 2. Confirmation is signalled one way -----------------------------------


def test_shaper_delete_signals_confirmation_the_same_way_as_every_other_delete() -> (
    None
):
    """`status: 'confirmation_required'`, not an error carrying it in a field."""
    from opnsense_mcp.tools.shaper_pipes import DeleteShaperPipeTool

    class Client:
        async def _make_request(self, *a: Any, **k: Any) -> dict[str, Any]:
            return {"rows": [{"uuid": "u1", "description": "d"}], "rowCount": 1}

    result = asyncio.run(DeleteShaperPipeTool(Client()).execute({"uuid": "u1"}))

    assert result["status"] == "confirmation_required"


# --- 4. Every delete exposes a `deleted` boolean ----------------------------


@pytest.mark.asyncio
async def test_dns_override_delete_exposes_a_deleted_boolean() -> None:
    """`alias delete` returns `deleted`; this returned only uuid and applied."""
    from opnsense_mcp.tools.rmdns import RmdnsTool

    class Client:
        async def del_host_override(self, uuid: str) -> dict[str, Any]:
            return {"result": "deleted"}

        async def reconfigure_unbound(self) -> dict[str, Any]:
            return {"status": "ok"}

    result = await RmdnsTool(Client()).execute({"uuid": "abc"})

    assert result["deleted"] is True
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_dns_override_delete_that_failed_is_not_marked_deleted() -> None:
    """A refused delete must not report `deleted: True`."""
    from opnsense_mcp.tools.rmdns import RmdnsTool

    class Client:
        async def del_host_override(self, uuid: str) -> dict[str, Any]:
            return {"result": "not found"}

        async def reconfigure_unbound(self) -> dict[str, Any]:
            return {"status": "ok"}

    result = await RmdnsTool(Client()).execute({"uuid": "abc"})

    assert result["status"] == "error"
    assert result.get("deleted") is not True


# --- 5. An applied move is not `planned` ------------------------------------

HOST_ROW = {
    "uuid": "u1",
    "host": "printer",
    "hwaddr": "aa:bb:cc:dd:ee:ff",
    "ip": "192.0.2.10",
    "domain": "example",
    "descr": "",
    "client_id": "",
}


def _dnsmasq_provider() -> Any:
    """A DnsmasqProvider over a request stub that accepts every write."""
    from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        if "search_host" in endpoint:
            return {"rows": [HOST_ROW], "total": 1}
        if "get_host" in endpoint:
            return {"host": HOST_ROW}
        return {"result": "saved", "status": "ok"}

    return DnsmasqProvider(make_request)


@pytest.mark.asyncio
async def test_an_applied_host_move_is_labelled_moved_not_planned() -> None:
    """`create_host` uses `created` and `delete_host` uses `deleted`.

    With apply=true the move did happen, so calling the result `planned` states
    the opposite of what occurred.
    """
    result = await _dnsmasq_provider().move_host(
        identifier="printer", ipv4_target="192.0.2.11", ipv6_target=None, dry_run=False
    )

    assert result["status"] == "success"
    assert "moved" in result
    assert "planned" not in result


@pytest.mark.asyncio
async def test_a_dry_run_move_is_still_labelled_planned() -> None:
    """`planned` keeps its meaning: a change that has not happened."""
    result = await _dnsmasq_provider().move_host(
        identifier="printer", ipv4_target="192.0.2.11", ipv6_target=None, dry_run=True
    )

    assert result["status"] == "dry_run"
    assert "planned" in result
    assert "moved" not in result


# --- 7. API error bodies must reach the caller ------------------------------


def test_a_failed_api_call_surfaces_the_body_not_unknown_error() -> None:
    """Discarding the body is the habit CLAUDE.md flags.

    `del_item` returning 500 was once declared undoable; the body said
    "Interface locked, unset lock first before removal", and the fix was three
    commands. A response with no `message` key must still carry its body.
    """
    from opnsense_mcp.utils.api import _api_error_detail

    detail = _api_error_detail(
        {"result": "failed", "status": "Interface locked, unset lock first"}
    )

    assert "Interface locked" in detail
    assert detail != "Unknown API error"


def test_a_message_field_is_still_preferred_when_present() -> None:
    """A plain message is the best detail; the body dump is the fallback."""
    from opnsense_mcp.utils.api import _api_error_detail

    detail = _api_error_detail({"result": "failed", "message": "rule not found"})

    assert detail == "rule not found"


def test_validation_errors_are_still_reported_field_by_field() -> None:
    """Validation detail must not be flattened away by the new fallback."""
    from opnsense_mcp.utils.api import _api_error_detail

    detail = _api_error_detail(
        {"result": "failed", "validations": {"rule.source_net": "invalid network"}}
    )

    assert "source_net" in detail
    assert "invalid network" in detail


def test_a_body_with_nothing_usable_says_so_without_inventing_detail() -> None:
    """An genuinely empty failure body still returns a stable string."""
    from opnsense_mcp.utils.api import _api_error_detail

    detail = _api_error_detail({"result": "failed"})

    assert isinstance(detail, str)
    assert detail


# --- 3. Every `apply` states its own default --------------------------------


def test_every_apply_field_declares_its_default() -> None:
    """The grouped schema shows one shared `apply` sentence for all of them.

    Defaults genuinely differ -- fw_rule and shaper apply by default, routing
    and nat_outbound stage by default -- so a caller reading only the grouped
    schema mispredicts whether a change goes live. The fact has to be
    machine-readable per action, not prose in some descriptions and absent
    from others.
    """
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": "examples/mock_data"}}
    )
    tools = build_tools(client, extra=build_shaper_tools(client))

    undeclared = [
        name
        for name, tool in tools.items()
        if "apply"
        in ((getattr(tool, "input_schema", {}) or {}).get("properties") or {})
        and "default"
        not in (getattr(tool, "input_schema", {}) or {})["properties"]["apply"]
    ]

    assert not undeclared, (
        "these tools take `apply` without declaring its default; read the "
        "params.get('apply', X) in each and write X into the schema: "
        + ", ".join(sorted(undeclared))
    )


def test_help_reports_the_apply_default_for_each_action() -> None:
    """`help` is where a caller learns a per-action default."""
    import asyncio

    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": "examples/mock_data"}}
    )
    groups = build_groups(build_tools(client, extra=build_shaper_tools(client)))

    routing = asyncio.run(groups["routing"].execute({"action": "help"}))
    create = next(a for a in routing["actions"] if a["action"] == "create_route")
    shaper = asyncio.run(groups["shaper"].execute({"action": "help"}))
    pipe = next(a for a in shaper["actions"] if a["action"] == "create_pipe")

    assert create["defaults"]["apply"] is False
    assert pipe["defaults"]["apply"] is True


# --- 6. The same field must not come back in two shapes ---------------------


def test_settings_and_list_rules_report_source_the_same_way() -> None:
    """`settings` returned the raw enum object; `list_rules` returned a string.

    Every other enum field on the rule (interface, direction, proto, dscp) is
    already resolved on both paths; source and destination were passed through
    raw, so the same field had two shapes depending on which action you asked.
    """
    from opnsense_mcp.utils.shaper_normalize import normalize_rule

    from_search = normalize_rule(
        {"uuid": "u1", "source": "any", "destination": "any", "sequence": "1"}
    )
    from_settings = normalize_rule(
        {
            "uuid": "u1",
            "source": {"any": {"value": "any", "selected": 1}},
            "destination": {"any": {"value": "any", "selected": 1}},
            "sequence": "1",
        }
    )

    assert from_settings["source"] == from_search["source"] == "any"
    assert from_settings["destination"] == from_search["destination"] == "any"


def test_a_named_alias_source_survives_normalization() -> None:
    """Resolving the enum must not flatten a real selection to the first key."""
    from opnsense_mcp.utils.shaper_normalize import normalize_rule

    rule = normalize_rule(
        {
            "uuid": "u1",
            "source": {
                "any": {"value": "any", "selected": 0},
                "lan_hosts": {"value": "lan_hosts", "selected": 1},
            },
            "sequence": "1",
        }
    )

    assert rule["source"] == "lan_hosts"
