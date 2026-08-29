"""Apply-result regression tests for outbound NAT writes."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.nat_outbound import MkNatOutboundTool


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
