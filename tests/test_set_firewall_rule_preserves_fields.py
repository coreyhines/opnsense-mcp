"""Wave 0: ``update_firewall_rule`` must preserve fields the caller did not restate.

The add-shaped payload helper emits 13 of the 58 real fields a ``getRule`` node
carries, so every partial edit silently reset the other 45 to model defaults.
Fixture captured from live OPNsense 26.7.2 (rule ``3e5d8614``: wan, pass,
``source_not=1``, ``log=1``, ``quick=1``). Site-identifying
values are sanitised; see the fixture README.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "opnsense-26.7.2"
    / "filter_getrule_log_quick_invert.json"
)
RULE_UUID = "3e5d8614-00e7-4a51-9123-cf8ff1dd8c33"


def _get_rule_node() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())["rule"]


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.return_value = MagicMock()
        return OPNsenseClient(config)


async def _capture_set_payload(overrides: dict[str, Any]) -> dict[str, Any]:
    """Run update_firewall_rule with a stubbed getRule; return the setRule body."""
    node = _get_rule_node()
    captured: dict[str, Any] = {}

    async def fake_make_request(
        method: str, endpoint: str, **kwargs: object
    ) -> dict[str, Any]:
        if "getRule" in endpoint:
            return {"rule": node}
        captured["endpoint"] = endpoint
        captured["json"] = kwargs.get("json")
        return {"result": "saved"}

    client = _client()
    client._make_request = AsyncMock(side_effect=fake_make_request)
    await client.update_firewall_rule(RULE_UUID, overrides)

    body = captured.get("json")
    assert isinstance(body, dict), "setRule was never POSTed"
    inner = body.get("rule")
    assert isinstance(inner, dict), "setRule body missing 'rule' key"
    return inner


@pytest.mark.asyncio
async def test_description_only_edit_preserves_source_and_destination() -> None:
    """The headline regression: editing the description opened the rule wide."""
    inner = await _capture_set_payload({"description": "renamed"})

    assert inner["description"] == "renamed"
    assert inner["source_net"] == "FrobozzRegion"
    assert inner["destination_net"] == "(self)"


@pytest.mark.asyncio
async def test_partial_edit_preserves_log_quick_and_invert_flags() -> None:
    """log, quick and source_not were never emitted, so every edit dropped them."""
    inner = await _capture_set_payload({"description": "renamed"})

    assert inner["log"] == "1"
    assert inner["quick"] == "1"
    assert inner["source_not"] == "1"
    assert inner["destination_not"] == "0"


@pytest.mark.asyncio
async def test_interface_only_edit_preserves_action() -> None:
    """An interface remap posted no action, so the model default could flip it."""
    inner = await _capture_set_payload({"interface": "opt7"})

    assert inner["interface"] == "opt7"
    assert inner["action"] == "pass"


@pytest.mark.asyncio
async def test_enum_fields_collapse_to_selected_key() -> None:
    """getRule renders enums as {key: {selected, value}}; setRule takes the key."""
    inner = await _capture_set_payload({"description": "renamed"})

    assert inner["statetype"] == "keep"
    assert inner["direction"] == "in"
    assert inner["ipprotocol"] == "inet6"


@pytest.mark.asyncio
async def test_display_only_percent_fields_are_stripped() -> None:
    """%source_net / %destination_net are resolved labels, not writable fields."""
    inner = await _capture_set_payload({"description": "renamed"})

    assert not [k for k in inner if k.startswith("%")]


@pytest.mark.asyncio
async def test_all_real_fields_are_round_tripped() -> None:
    """No silent resets: every non-display field from getRule is written back."""
    node = _get_rule_node()
    expected = {k for k in node if not k.startswith("%")}

    inner = await _capture_set_payload({"description": "renamed"})

    assert expected - set(inner) == set()


@pytest.mark.asyncio
async def test_explicit_any_still_wins() -> None:
    """Widening stays possible when the caller actually asks for it."""
    inner = await _capture_set_payload({"source_net": "any"})

    assert inner["source_net"] == "any"
