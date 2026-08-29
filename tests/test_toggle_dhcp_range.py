"""A dnsmasq DHCP range cannot be toggled, and the tool says so.

These tests used to drive the provider with hand-written rows carrying a
``disabled`` key. OPNsense never sends one: `settings/get`, `search_range` and
`get_range` all return the same 18 fields and none is an enable flag. So the
fixtures proved the toggle worked against a shape the API does not emit, which
is the failure mode this repo has already paid for twice.

What the old code actually did on the firewall:

* ``enabled=True`` read ``row["disabled"]``, found nothing, concluded the range
  was already enabled, and returned ``noop``. Always.
* ``enabled=False`` POSTed ``disabled: "1"`` into a model with no such field and
  reported ``applied: true``. Nothing changed.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"

RANGE_ROW = {
    "uuid": "r1",
    "interface": "opt10",
    "start_addr": "::2",
    "end_addr": "::ffff",
    "constructor": "opt10",
}


def _provider(posted: list[dict[str, Any]]) -> DnsmasqProvider:
    """A provider whose set_range writes are recorded rather than sent."""

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "search_range" in endpoint:
            return {"rows": [dict(RANGE_ROW)]}
        if "get_range" in endpoint:
            return {"range": dict(RANGE_ROW)}
        if "set_range" in endpoint:
            posted.append(kwargs["json"]["range"])
        return {"result": "saved"}

    return DnsmasqProvider(AsyncMock(side_effect=fake))


@pytest.mark.asyncio
@pytest.mark.parametrize("requested", [True, False])
@pytest.mark.parametrize("dry_run", [True, False])
async def test_toggle_range_refuses_in_every_direction(
    requested: bool, dry_run: bool
) -> None:
    """Neither direction, dry run or not, may report a toggle that cannot happen."""
    posted: list[dict[str, Any]] = []
    result = await _provider(posted).toggle_range(
        enabled=requested, uuid="r1", dry_run=dry_run
    )

    assert result["status"] == "error"
    assert result["error_code"] == "unsupported_by_model"
    assert result["unsupported"] is True
    assert result["applied"] is False
    assert result["requested_enabled"] is requested
    assert not posted


@pytest.mark.asyncio
async def test_toggle_range_never_claims_a_noop() -> None:
    """`noop` was the old lie for enable: absent key read as already-enabled."""
    posted: list[dict[str, Any]] = []
    result = await _provider(posted).toggle_range(
        enabled=True, uuid="r1", dry_run=False
    )

    assert result["status"] != "noop"
    assert result["status"] != "success"
    assert result["status"] != "dry_run"


@pytest.mark.asyncio
async def test_toggle_range_names_what_can_be_done_instead() -> None:
    """A refusal that does not say what else to try is a dead end."""
    posted: list[dict[str, Any]] = []
    result = await _provider(posted).toggle_range(
        enabled=False, uuid="r1", dry_run=False
    )

    assert result["alternatives"]
    assert all(isinstance(item, str) and item for item in result["alternatives"])


@pytest.mark.asyncio
async def test_toggle_range_still_reports_a_missing_range() -> None:
    """Scope resolution failure must stay distinguishable from the refusal."""

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        return {"rows": []}

    provider = DnsmasqProvider(AsyncMock(side_effect=fake))
    result = await provider.toggle_range(enabled=False, uuid="nope", dry_run=False)

    assert result["status"] == "error"
    assert "error_code" not in result
    assert "No matching DHCP range" in result["error"]


def test_the_captured_range_still_has_no_enable_field() -> None:
    """If OPNsense ever adds one, this fails and the refusal gets revisited.

    The refusal above is only correct while the model genuinely lacks the field.
    A sweep of the API today does not stay true, so it is a test.
    """
    captured = json.loads((FIXTURES / "dnsmasq_v6_range_responses.json").read_text())
    node = captured["get_range"]["range"]
    row = captured["search_range"]["rows"][0]

    for source, name in ((node, "get_range"), (row, "search_range")):
        offenders = sorted(
            key for key in source if "enable" in key.lower() or "disable" in key.lower()
        )
        assert not offenders, (
            f"{name} now carries {offenders}; dnsmasq ranges may have gained an "
            f"enable flag, so toggle_range should stop refusing and set it"
        )
