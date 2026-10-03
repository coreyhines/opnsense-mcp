"""A failed filter reload must not report a completed fw_rule write as failed.

Issues #60 and #61: each fw_rule write ran `apply_firewall_changes()` inside
the write's `try`. When the write succeeded and the reload raised, the tool
returned `status: "error"`. Create dropped the new uuid, so a retry made a
duplicate; delete consumed its single-use confirm token on a rule that was
already gone. These tests make the write succeed and the apply raise, then
assert on the structured fields.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
from opnsense_mcp.tools.toggle_fw_rule import ToggleFwRuleTool


def _client() -> MagicMock:
    """Return a client whose writes succeed and whose apply raises."""
    client = MagicMock()
    client.add_firewall_rule = AsyncMock(return_value={"uuid": "U1"})
    client.update_firewall_rule = AsyncMock(return_value={"result": "saved"})
    client.toggle_firewall_rule = AsyncMock(return_value={"result": "success"})
    client.delete_firewall_rule = AsyncMock(return_value={"result": "success"})
    client.apply_firewall_changes = AsyncMock(side_effect=RuntimeError("reload x"))
    return client


@pytest.mark.asyncio
async def test_mkfw_rule_apply_failure_keeps_the_created_rule() -> None:
    client = _client()

    result = await MkfwRuleTool(client).execute({"description": "t", "apply": True})

    assert result["status"] == "success"
    assert result["applied"] is False
    assert result["rule_uuid"] == "U1"
    assert result["apply_error"] == "reload x"
    client.apply_firewall_changes.assert_awaited_once()


@pytest.mark.asyncio
async def test_set_fw_rule_apply_failure_keeps_the_update() -> None:
    client = _client()

    result = await SetFwRuleTool(client).execute(
        {"rule_uuid": "U1", "description": "new", "apply": True}
    )

    assert result["status"] == "success"
    assert result["applied"] is False
    assert result["uuid"] == "U1"
    assert result["updated_fields"] == ["description"]
    assert result["apply_error"] == "reload x"


@pytest.mark.asyncio
async def test_toggle_fw_rule_apply_failure_keeps_the_toggle() -> None:
    client = _client()

    result = await ToggleFwRuleTool(client).execute(
        {"rule_uuid": "U1", "enabled": False, "apply": True}
    )

    assert result["status"] == "success"
    assert result["applied"] is False
    assert result["enabled"] is False
    assert result["apply_error"] == "reload x"


@pytest.mark.asyncio
async def test_rmfw_rule_apply_failure_reports_the_delete() -> None:
    client = _client()
    tool = RmfwRuleTool(client)
    token = (await tool.execute({"rule_uuid": "U1"}))["confirm_token"]

    result = await tool.execute({"rule_uuid": "U1", "apply": True, "confirm": token})

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is False
    assert result["apply_error"] == "reload x"
    client.delete_firewall_rule.assert_awaited_once_with("U1")


@pytest.mark.asyncio
async def test_a_failed_write_is_still_an_error_and_never_applies() -> None:
    """The split must not turn a failed write into a success."""
    client = _client()
    client.add_firewall_rule = AsyncMock(side_effect=RuntimeError("write x"))

    result = await MkfwRuleTool(client).execute({"description": "t", "apply": True})

    assert result["status"] == "error"
    assert "applied" not in result
    client.apply_firewall_changes.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_successful_apply_carries_no_apply_error() -> None:
    client = _client()
    client.apply_firewall_changes = AsyncMock(return_value={"status": "ok"})

    result = await ToggleFwRuleTool(client).execute(
        {"rule_uuid": "U1", "enabled": True, "apply": True}
    )

    assert result["status"] == "success"
    assert result["applied"] is True
    assert "apply_error" not in result
