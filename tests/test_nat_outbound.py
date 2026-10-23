"""Apply-result regression tests for outbound NAT writes."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.nat_outbound import (
    MkNatOutboundTool,
    RmNatOutboundTool,
    ToggleNatOutboundTool,
)


@pytest.mark.asyncio
async def test_nat_outbound_apply_status_failed_keeps_successful_write_visible() -> (
    None
):
    client = MagicMock()

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "search_rule" in endpoint:
            return {"rows": [], "total": 0}
        if "add_rule" in endpoint:
            return {"result": "saved", "uuid": "nat-new"}
        if "filter/apply" in endpoint:
            return {"status": "failed", "message": "pf reload refused"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)

    result = await MkNatOutboundTool(client).execute(
        {"interface": "wan", "source_net": "FABRIC_INTERNAL", "apply": True}
    )

    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert "apply_error" in result


@pytest.mark.asyncio
async def test_rm_nat_outbound_not_found_is_error_not_deleted() -> None:
    """delBase returns not found at HTTP 200; must not report deleted:true."""
    client = MagicMock()

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "del_rule" in endpoint:
            return {"result": "not found"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)
    tool = RmNatOutboundTool(client)
    challenge = await tool.execute({"uuid": "nope"})
    result = await tool.execute({"uuid": "nope", "confirm": challenge["confirm_token"]})

    assert result["status"] == "error"
    assert result.get("deleted") is not True
    assert "applied" not in result


@pytest.mark.asyncio
async def test_rm_nat_outbound_reports_applied_for_both_apply_values() -> None:
    client = MagicMock()
    apply_calls: list[str] = []

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "del_rule" in endpoint:
            return {"result": "deleted"}
        if "filter/apply" in endpoint:
            apply_calls.append(endpoint)
            return {"status": "ok"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)
    tool = RmNatOutboundTool(client)

    challenge = await tool.execute({"uuid": "nat-1"})
    staged = await tool.execute(
        {"uuid": "nat-1", "confirm": challenge["confirm_token"]}
    )
    assert staged["status"] == "success"
    assert staged["deleted"] is True
    assert staged["applied"] is False
    assert apply_calls == []

    challenge = await tool.execute({"uuid": "nat-2"})
    applied = await tool.execute(
        {
            "uuid": "nat-2",
            "confirm": challenge["confirm_token"],
            "apply": True,
        }
    )
    assert applied["status"] == "success"
    assert applied["deleted"] is True
    assert applied["applied"] is True
    assert apply_calls


@pytest.mark.asyncio
async def test_toggle_nat_outbound_reports_applied_for_both_apply_values() -> None:
    client = MagicMock()
    apply_calls: list[str] = []

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "toggle_rule" in endpoint:
            return {"result": "saved"}
        if "filter/apply" in endpoint:
            apply_calls.append(endpoint)
            return {"status": "ok"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)
    tool = ToggleNatOutboundTool(client)

    staged = await tool.execute({"uuid": "nat-1", "enabled": False})
    assert staged["status"] == "success"
    assert staged["enabled"] is False
    assert staged["applied"] is False
    assert apply_calls == []

    applied = await tool.execute({"uuid": "nat-1", "enabled": True, "apply": True})
    assert applied["status"] == "success"
    assert applied["enabled"] is True
    assert applied["applied"] is True
    assert apply_calls


@pytest.mark.asyncio
async def test_rm_nat_outbound_apply_failure_keeps_deleted_true() -> None:
    """Delete succeeded; apply failure must not invert deleted."""
    client = MagicMock()

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "del_rule" in endpoint:
            return {"result": "deleted"}
        if "filter/apply" in endpoint:
            return {"status": "failed", "message": "pf reload refused"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)
    tool = RmNatOutboundTool(client)
    challenge = await tool.execute({"uuid": "nat-1"})
    result = await tool.execute(
        {
            "uuid": "nat-1",
            "confirm": challenge["confirm_token"],
            "apply": True,
        }
    )

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is False
    assert "apply_error" in result
