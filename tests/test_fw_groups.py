"""Apply-result regression tests for firewall-group writes."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.fw_groups import SetFwGroupTool

GROUP_UUID = "2873531a-bf3b-42c6-9b90-676e193edd67"


@pytest.mark.asyncio
async def test_fw_group_apply_status_failed_keeps_successful_write_visible() -> None:
    client = MagicMock()

    async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "get_item" in endpoint:
            return {
                "group": {
                    "ifname": "workshopNets",
                    "members": "opt3,opt4",
                    "descr": "lab networks",
                    "sequence": "0",
                }
            }
        if "set_item" in endpoint:
            return {"result": "saved"}
        if "reconfigure" in endpoint:
            return {"status": "failed", "message": "group reload refused"}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._make_request = AsyncMock(side_effect=fake_request)

    result = await SetFwGroupTool(client).execute(
        {"uuid": GROUP_UUID, "members": ["opt3"], "apply": True}
    )

    assert result["status"] == "success"
    assert result["applied"] is False
    assert "apply_error" in result
