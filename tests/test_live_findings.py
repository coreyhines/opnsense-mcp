"""Regression tests for defects found by live MCP testing on 2026-08-28.

Each test here corresponds to a filed issue and is written to fail against the
code as it stood at 38a55ad. They assert on structured fields rather than on
message wording, per CLAUDE.md.
"""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.tools.fw_rules import _map_search_rule_row
from opnsense_mcp.tools.nat_outbound import MkNatOutboundTool
from opnsense_mcp.tools.routing_stack import MkRouteTool


class RecordingClient:
    """Client stub that records every request and replays canned responses."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        """Store canned responses keyed by endpoint substring."""
        self.calls: list[dict[str, Any]] = []
        self.responses = responses or {}

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        call_class: str | None = None,
        json: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Record the call and return the canned response for the endpoint."""
        self.calls.append(
            {
                "method": method,
                "endpoint": endpoint,
                "call_class": call_class,
                "json": json,
            }
        )
        for fragment, response in self.responses.items():
            if fragment in endpoint:
                return response
        return {"rows": [], "result": "saved", "uuid": "new-uuid"}

    def payload_for(self, fragment: str, key: str) -> dict[str, Any]:
        """The `key` sub-object of the first request whose endpoint matches."""
        for call in self.calls:
            if fragment in call["endpoint"] and (call["json"] or {}).get(key):
                return call["json"][key]
        raise AssertionError(f"no {fragment} call carrying a {key!r} payload")


# --- Issue #14: fw_rule list reports every rule as any->any ------------------


def test_search_rule_row_reads_source_and_destination_net() -> None:
    """searchRule rows key the nets as source_net/destination_net."""
    row = {
        "uuid": "6f1c0a2e-0000-0000-0000-000000000001",
        "sequence": "1",
        "interface": "lan",
        "source_net": "198.51.100.0/24",
        "source_port": "",
        "destination_net": "203.0.113.0/24",
        "destination_port": "65000",
        "action": "pass",
        "enabled": "1",
    }

    mapped = _map_search_rule_row(row)

    assert mapped["source"]["net"] == "198.51.100.0/24"
    assert mapped["destination"]["net"] == "203.0.113.0/24"
    assert mapped["destination"]["port"] == "65000"


def test_search_rule_row_keeps_nested_source_shape() -> None:
    """The mock client's nested {'net': ...} rows still map unchanged."""
    row = {
        "uuid": "abc",
        "source": {"net": "192.0.2.0/24", "port": "22"},
        "destination": {"net": "any", "port": ""},
        "action": "block",
    }

    mapped = _map_search_rule_row(row)

    assert mapped["source"]["net"] == "192.0.2.0/24"
    assert mapped["destination"]["net"] == "any"


# --- Issue #15: create paths ignore `enabled` -------------------------------


@pytest.mark.asyncio
async def test_create_route_honors_enabled_false() -> None:
    """A route asked for disabled must not be stored enabled."""
    client = RecordingClient()
    tool = MkRouteTool(client)

    result = await tool.execute(
        {
            "network": "198.51.100.0/24",
            "gateway": "wgs2s",
            "enabled": False,
            "apply": False,
        }
    )

    assert result["created"] is True
    assert client.payload_for("route", "route")["enabled"] == "0"


@pytest.mark.asyncio
async def test_create_route_defaults_to_enabled() -> None:
    """Omitting `enabled` keeps the historical enabled-by-default behaviour."""
    client = RecordingClient()
    tool = MkRouteTool(client)

    await tool.execute({"network": "198.51.100.0/24", "gateway": "wgs2s"})

    assert client.payload_for("route", "route")["enabled"] == "1"


@pytest.mark.asyncio
async def test_create_nat_outbound_honors_enabled_false() -> None:
    """An outbound NAT rule asked for disabled must not be stored enabled."""
    client = RecordingClient()
    tool = MkNatOutboundTool(client)

    result = await tool.execute(
        {
            "interface": "wan",
            "source_net": "198.51.100.0/24",
            "target": "",
            "enabled": False,
        }
    )

    assert result["created"] is True
    assert client.payload_for("source_nat", "rule")["enabled"] == "0"


@pytest.mark.asyncio
async def test_create_nat_outbound_defaults_to_enabled() -> None:
    """Omitting `enabled` keeps the historical enabled-by-default behaviour."""
    client = RecordingClient()
    tool = MkNatOutboundTool(client)

    await tool.execute({"interface": "wan", "source_net": "198.51.100.0/24"})

    assert client.payload_for("source_nat", "rule")["enabled"] == "1"


# --- Issue #17: search_host_overrides / search_aliases truncate at 100 -------


class PagingClientMixin:
    """Serves a row set one page at a time from an OPNsense bootgrid endpoint."""

    def __init__(self, total_rows: int) -> None:
        """Build `total_rows` synthetic rows and record every page request."""
        self.rows = [
            {"uuid": f"row-{i}", "hostname": f"h{i}"} for i in range(total_rows)
        ]
        self.page_requests: list[dict[str, Any]] = []

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        call_class: str | None = None,
        json: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Return the requested page plus the true total, bootgrid-style."""
        body = json or {}
        current = int(body.get("current", 1))
        row_count = int(body.get("rowCount", 100))
        self.page_requests.append({"current": current, "rowCount": row_count})
        start = (current - 1) * row_count
        page = self.rows[start : start + row_count]
        return {"rows": page, "total": len(self.rows), "rowCount": row_count}


def _client_with_rows(total_rows: int) -> Any:
    """An OPNsenseClient whose transport serves `total_rows` paged rows."""
    from opnsense_mcp.utils.api import OPNsenseClient

    client = OPNsenseClient.__new__(OPNsenseClient)
    pager = PagingClientMixin(total_rows)
    client._make_request = pager._make_request  # type: ignore[method-assign]
    client._pager = pager  # type: ignore[attr-defined]
    return client


@pytest.mark.asyncio
async def test_search_host_overrides_returns_every_row() -> None:
    """254 overrides must not come back as 100."""
    client = _client_with_rows(254)

    rows = await client.search_host_overrides()

    assert len(rows) == 254
    assert client._pager.page_requests[0]["current"] == 1


@pytest.mark.asyncio
async def test_search_aliases_returns_every_row() -> None:
    """The identical latent bug in search_aliases."""
    client = _client_with_rows(137)

    rows = await client.search_aliases()

    assert len(rows) == 137


@pytest.mark.asyncio
async def test_search_stops_on_a_single_short_page() -> None:
    """A result set smaller than a page issues exactly one request."""
    client = _client_with_rows(12)

    rows = await client.search_host_overrides()

    assert len(rows) == 12
    assert len(client._pager.page_requests) == 1


@pytest.mark.asyncio
async def test_search_pages_past_the_first_page() -> None:
    """A row set larger than one page is fetched across successive pages."""
    client = _client_with_rows(254)

    rows = await client._search_all_rows(
        "/api/unbound/settings/searchHostOverride", page_size=100
    )

    assert len(rows) == 254
    assert [req["current"] for req in client._pager.page_requests] == [1, 2, 3]


@pytest.mark.asyncio
async def test_search_stops_when_the_server_never_reaches_its_total() -> None:
    """A server returning full pages forever is bounded, not looped on."""
    from opnsense_mcp.utils import api as api_module

    class NeverEnding:
        def __init__(self) -> None:
            self.requests = 0

        async def _make_request(
            self, method, endpoint, call_class=None, json=None, **kwargs
        ):
            self.requests += 1
            page_size = int((json or {}).get("rowCount", 10))
            return {"rows": [{"uuid": "x"}] * page_size, "total": 10**9}

    client = api_module.OPNsenseClient.__new__(api_module.OPNsenseClient)
    endless = NeverEnding()
    client._make_request = endless._make_request  # type: ignore[method-assign]

    rows = await client._search_all_rows("/api/whatever", page_size=10)

    assert endless.requests == api_module.SEARCH_MAX_PAGES
    assert len(rows) == api_module.SEARCH_MAX_PAGES * 10


# --- Issue #18: DHCP subnet selector is dead on the dnsmasq backend ----------

# Verbatim key set of a GET /api/dnsmasq/settings/search_range row, captured
# live from OPNsense 26.7.3_8. There is no subnet/network/range key, and the
# bounds are start_addr/end_addr.
DNSMASQ_RANGE_ROW = {
    "%domain_type": "",
    "%interface": "",
    "%set_tag": "",
    "constructor": "",
    "description": "VLAN3LAB",
    "domain": "",
    "domain_type": "",
    "end_addr": "192.0.2.200",
    "interface": "opt3",
    "lease_time": "",
    "mode": "",
    "nosync": "0",
    "prefix_len": "24",
    "ra_interval": "",
    "ra_mode": "",
    "ra_mtu": "",
    "ra_priority": "",
    "ra_router_lifetime": "",
    "set_tag": "",
    "start_addr": "192.0.2.2",
    "subnet_mask": "255.255.255.0",
    "uuid": "b1f3d0c4-0000-0000-0000-00000000000a",
}

RANGE_ENDPOINT = "/api/dnsmasq/settings/search_range"


def _dnsmasq_make_request(rows: list[dict[str, Any]], overview: Any = None) -> Any:
    """A make_request stub serving the interface overview then the range rows."""

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "interfaces/overview" in endpoint:
            return overview if overview is not None else {}
        return {"rows": rows}

    return make_request


@pytest.mark.asyncio
async def test_subnet_selector_matches_a_dnsmasq_range_row() -> None:
    """The documented `subnet` selector must resolve against start_addr/end_addr."""
    from opnsense_mcp.utils.dhcp_scope import resolve_scope_from_selectors

    scope = await resolve_scope_from_selectors(
        _dnsmasq_make_request([DNSMASQ_RANGE_ROW]),
        subnet="192.0.2.0/24",
        interface=None,
        range_search_endpoint=RANGE_ENDPOINT,
    )

    assert scope.interface == "opt3"
    assert scope.subnet == "192.0.2.0/24"
    assert scope.description == "VLAN3LAB"


@pytest.mark.asyncio
async def test_subnet_selector_uses_the_rows_own_prefix_len() -> None:
    """A /25 range must not be matched by a /24 request that shares a base."""
    from opnsense_mcp.utils.dhcp_scope import resolve_scope_from_selectors

    row = {**DNSMASQ_RANGE_ROW, "start_addr": "192.0.2.130", "prefix_len": "25"}

    with pytest.raises(ValueError, match="No DHCP scope found"):
        await resolve_scope_from_selectors(
            _dnsmasq_make_request([row]),
            subnet="192.0.2.0/24",
            interface=None,
            range_search_endpoint=RANGE_ENDPOINT,
        )


@pytest.mark.asyncio
async def test_subnet_selector_still_rejects_an_unknown_subnet() -> None:
    """A subnet no range covers still fails closed."""
    from opnsense_mcp.utils.dhcp_scope import resolve_scope_from_selectors

    with pytest.raises(ValueError, match="No DHCP scope found"):
        await resolve_scope_from_selectors(
            _dnsmasq_make_request([DNSMASQ_RANGE_ROW]),
            subnet="198.51.100.0/24",
            interface=None,
            range_search_endpoint=RANGE_ENDPOINT,
        )


# --- Issue #22: a staged firewall change had no way to be applied -----------


@pytest.mark.asyncio
async def test_fw_rule_apply_action_applies_staged_changes() -> None:
    """`fw_rule action='apply'` loads what was staged with apply=false."""
    from opnsense_mcp.tools.apply_fw_changes import ApplyFwChangesTool

    class ApplyClient:
        def __init__(self) -> None:
            self.applied = 0

        async def apply_firewall_changes(self) -> dict[str, Any]:
            self.applied += 1
            return {"result": "success"}

    client = ApplyClient()

    result = await ApplyFwChangesTool(client).execute({})

    assert result["applied"] is True
    assert result["status"] == "success"
    assert client.applied == 1


@pytest.mark.asyncio
async def test_fw_rule_apply_reports_failure_rather_than_claiming_success() -> None:
    """An apply that raises must not come back as applied."""
    from opnsense_mcp.tools.apply_fw_changes import ApplyFwChangesTool

    class FailingClient:
        async def apply_firewall_changes(self) -> dict[str, Any]:
            raise RuntimeError("filter reload failed")

    result = await ApplyFwChangesTool(FailingClient()).execute({})

    assert result["status"] == "error"
    assert result["applied"] is False


def test_fw_rule_group_exposes_an_apply_action() -> None:
    """The guidance now points at this action, so it must exist."""
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": "examples/mock_data"}}
    )
    groups = build_groups(build_tools(client, extra=build_shaper_tools(client)))

    assert "apply" in groups["fw_rule"].members


# --- Issue #16: `action` was both the selector and a member field -----------


def _exposed_groups() -> dict[str, Any]:
    """Build the real exposed surface against the mock client."""
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": "examples/mock_data"}}
    )
    return build_groups(build_tools(client, extra=build_shaper_tools(client)))


def test_no_member_field_collides_with_the_group_selector() -> None:
    """The registry guard the collision asks for: no unaliased `action` field.

    A member field named the same as the selector can never be received. This
    fails when a new member introduces one without a FIELD_ALIASES entry.
    """
    from opnsense_mcp.utils.tool_groups import FIELD_ALIASES, GROUPS

    collisions: list[str] = []
    groups = _exposed_groups()
    for group_name in GROUPS:
        group = groups.get(group_name)
        if group is None:
            continue
        for action, tool in group.members.items():
            props = (getattr(tool, "input_schema", {}) or {}).get("properties") or {}
            tool_name = getattr(tool, "name", "")
            aliased = FIELD_ALIASES.get(tool_name, {})
            if "action" in props and "action" not in aliased:
                collisions.append(f"{group_name}.{action} ({tool_name})")

    assert not collisions, (
        "member tools declare an `action` field the group selector swallows; "
        "add a FIELD_ALIASES entry: " + ", ".join(sorted(collisions))
    )


def test_rule_action_reaches_the_create_tool() -> None:
    """You must be able to create a block rule, not only a pass rule."""

    class Spy:
        name = "mkfw_rule"
        description = "spy"
        input_schema = {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "interface": {"type": "string"},
            },
            "required": ["interface"],
        }

        def __init__(self) -> None:
            self.received: dict[str, Any] = {}

        async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
            self.received = params
            return {"status": "success"}

    from opnsense_mcp.utils.grouped_tool import GroupedTool
    from opnsense_mcp.utils.tool_groups import FIELD_ALIASES

    spy = Spy()
    group = GroupedTool(
        name="fw_rule",
        description="d",
        members={"create": spy},
        field_aliases=FIELD_ALIASES,
    )

    import asyncio

    result = asyncio.run(
        group.execute({"action": "create", "rule_action": "block", "interface": "lan"})
    )

    assert result["status"] == "success"
    assert spy.received["action"] == "block"
    assert "rule_action" not in spy.received


def test_capture_stop_and_fetch_are_reachable() -> None:
    """packet_capture could be started but never stopped or fetched."""
    groups = _exposed_groups()
    props = groups["diagnostics"].input_schema["properties"]

    assert "capture_action" in props
    assert "stop" in props["capture_action"]["description"]


def test_help_names_the_alias_a_caller_must_send() -> None:
    """`help` is the contract; it must not advertise the swallowed name."""
    import asyncio

    groups = _exposed_groups()
    help_result = asyncio.run(groups["fw_rule"].execute({"action": "help"}))

    create = next(a for a in help_result["actions"] if a["action"] == "create")

    assert "rule_action" in create["fields"]
    assert "action" not in create["fields"]
