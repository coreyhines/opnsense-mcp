"""Tests for firewall rule deletion tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool


@pytest.mark.asyncio
async def test_rmfw_rule_success_after_result_not_success_key() -> None:
    """Delete uses result=success, not success=true — must not report failure."""
    client = MagicMock()
    client.delete_firewall_rule = AsyncMock(return_value={"result": "success"})
    client.apply_firewall_changes = AsyncMock(return_value={"result": "applied"})

    tool = RmfwRuleTool(client)
    result = await tool.execute({"rule_uuid": "abc-123", "apply": True})

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is True
    client.delete_firewall_rule.assert_awaited_once_with("abc-123")
    client.apply_firewall_changes.assert_awaited_once()


@pytest.mark.asyncio
async def test_rmfw_rule_delete_without_apply() -> None:
    client = MagicMock()
    client.delete_firewall_rule = AsyncMock(return_value={"result": "success"})
    client.apply_firewall_changes = AsyncMock()

    tool = RmfwRuleTool(client)
    result = await tool.execute({"rule_uuid": "abc-123", "apply": False})

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is False
    client.apply_firewall_changes.assert_not_awaited()
