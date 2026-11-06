"""A failed read is an error, not an empty table (#152).

`get_lldp_table` and `get_gateway_status` caught every exception and returned
[], so the tools' own error branches never ran and a missing plugin, a 403 or
a timeout read as "no neighbours" / "count: 0" with status success.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.gateway_status import GatewayStatusTool
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.utils.api import OPNsenseClient, ResponseError


def _client(make_request: Any) -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)
    client._make_request = make_request
    return client


FAILING = AsyncMock(side_effect=ResponseError("HTTP 404: plugin not installed"))


@pytest.mark.asyncio
async def test_a_failed_lldp_read_is_an_error() -> None:
    result = await LLDPTool(_client(FAILING)).execute({})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_a_failed_gateway_read_is_an_error() -> None:
    result = await GatewayStatusTool(_client(FAILING)).execute({})
    assert result["status"] == "error"
    assert "count" not in result


@pytest.mark.asyncio
async def test_an_empty_lldp_table_is_still_success() -> None:
    """The guard against over-correcting: no neighbours is a real answer."""
    client = _client(AsyncMock(return_value={"response": ""}))
    result = await LLDPTool(client).execute({})
    assert result["status"] == "success"
    assert result["neighbors"] == []
