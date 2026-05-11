"""Tests for OPNsense addRule API payload wrapping."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient, _firewall_rule_inner_for_add_api


def test_firewall_rule_inner_flattens_nested_source_destination() -> None:
    inner = _firewall_rule_inner_for_add_api(
        {
            "description": "Block DMZ to guest",
            "interface": "opt7",
            "direction": "in",
            "ipprotocol": "inet46",
            "protocol": "any",
            "action": "block",
            "enabled": True,
            "source": {"net": "opt7", "port": "any"},
            "destination": {"net": "opt6", "port": "any"},
        }
    )
    assert inner["description"] == "Block DMZ to guest"
    assert inner["interface"] == "opt7"
    assert inner["action"] == "block"
    assert inner["enabled"] == "1"
    assert inner["source_net"] == "opt7"
    assert inner["destination_net"] == "opt6"
    assert "source_port" not in inner
    assert "destination_port" not in inner


@pytest.mark.asyncio
async def test_add_firewall_rule_posts_wrapped_rule_key() -> None:
    config = {
        "firewall_host": "192.0.2.1",
        "api_key": "k",
        "api_secret": "s",
    }
    captured: dict = {}

    async def fake_make_request(
        method: str,
        endpoint: str,
        **kwargs: object,
    ) -> dict:
        captured["method"] = method
        captured["endpoint"] = endpoint
        captured["json"] = kwargs.get("json")
        return {"result": "saved", "uuid": "test-uuid-1"}

    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.return_value = MagicMock()
        client = OPNsenseClient(config)
        client._make_request = AsyncMock(side_effect=fake_make_request)

        await client.add_firewall_rule(
            {
                "description": "x",
                "interface": "opt7",
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": "any",
                "action": "pass",
                "enabled": True,
                "source": {"net": "any", "port": "any"},
                "destination": {"net": "any", "port": "any"},
            }
        )

    assert captured["method"] == "POST"
    assert captured["endpoint"] == "/api/firewall/filter/addRule"
    body = captured["json"]
    assert isinstance(body, dict)
    assert "rule" in body
    assert body["rule"]["description"] == "x"
    assert body["rule"]["interface"] == "opt7"
    assert body["rule"]["source_net"] == "any"
    assert body["rule"]["destination_net"] == "any"
