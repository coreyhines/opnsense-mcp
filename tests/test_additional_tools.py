"""Additional unit tests for previously untested tools."""

from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.tools.aliases import AliasesTool
from opnsense_mcp.tools.dns import DNSTool
from opnsense_mcp.tools.gateway_status import GatewayStatusTool
from opnsense_mcp.tools.get_logs import GetLogsTool
from opnsense_mcp.tools.mkdns import MkdnsTool
from opnsense_mcp.tools.rmdns import RmdnsTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
from opnsense_mcp.tools.ssh_fw_rule import SSHFirewallRuleTool
from opnsense_mcp.tools.toggle_fw_rule import ToggleFwRuleTool


@pytest.mark.asyncio
async def test_dns_tool_success_and_error_paths() -> None:
    client = AsyncMock()
    client.search_host_overrides.return_value = [{"hostname": "ds"}]
    tool = DNSTool(client)
    result = await tool.execute({"search": "ds"})
    assert result["status"] == "success"
    assert result["count"] == 1

    tool_no_client = DNSTool(None)
    error_result = await tool_no_client.execute({})
    assert error_result["status"] == "error"


@pytest.mark.asyncio
async def test_aliases_tool_success_and_error_paths() -> None:
    client = AsyncMock()
    client.search_aliases.return_value = [{"name": "lan_hosts"}]
    tool = AliasesTool(client)
    result = await tool.execute({"search": "lan"})
    assert result["status"] == "success"
    assert result["count"] == 1

    tool_no_client = AliasesTool(None)
    error_result = await tool_no_client.execute({})
    assert error_result["status"] == "error"


@pytest.mark.asyncio
async def test_gateway_status_tool_success_and_error_paths() -> None:
    client = AsyncMock()
    client.get_gateway_status.return_value = [{"name": "WAN_DHCP", "status": "online"}]
    tool = GatewayStatusTool(client)
    result = await tool.execute({})
    assert result["status"] == "success"
    assert result["count"] == 1

    tool_no_client = GatewayStatusTool(None)
    error_result = await tool_no_client.execute({})
    assert error_result["status"] == "error"


@pytest.mark.asyncio
async def test_mkdns_and_rmdns_success_and_error_paths() -> None:
    client = AsyncMock()
    client.add_host_override.return_value = {"uuid": "abc-123"}
    client.reconfigure_unbound.return_value = {"status": "ok"}
    mkdns = MkdnsTool(client)
    mkdns_result = await mkdns.execute(
        {"hostname": "pi5", "domain": "freeblizz.com", "server": "10.0.2.2"}
    )
    assert mkdns_result["status"] == "success"
    assert mkdns_result["uuid"] == "abc-123"

    rmdns = RmdnsTool(client)
    client.del_host_override.return_value = {"result": "deleted"}
    rmdns_result = await rmdns.execute({"uuid": "abc-123"})
    assert rmdns_result["status"] == "success"
    assert rmdns_result["uuid"] == "abc-123"

    mkdns_error = await MkdnsTool(None).execute(
        {"hostname": "pi5", "domain": "freeblizz.com", "server": "10.0.2.2"}
    )
    assert mkdns_error["status"] == "error"
    rmdns_error = await RmdnsTool(None).execute({"uuid": "abc-123"})
    assert rmdns_error["status"] == "error"


@pytest.mark.asyncio
async def test_set_and_toggle_fw_rule_success_and_error_paths() -> None:
    client = AsyncMock()
    client.update_firewall_rule.return_value = {"status": "ok"}
    client.toggle_firewall_rule.return_value = {"status": "ok"}
    client.apply_firewall_changes.return_value = {"status": "ok"}

    set_tool = SetFwRuleTool(client)
    set_result = await set_tool.execute(
        {"rule_uuid": "u-1", "description": "updated", "apply": True}
    )
    assert set_result["status"] == "success"
    assert set_result["applied"] is True

    toggle_tool = ToggleFwRuleTool(client)
    toggle_result = await toggle_tool.execute(
        {"rule_uuid": "u-1", "enabled": "false", "apply": True}
    )
    assert toggle_result["status"] == "success"
    assert toggle_result["enabled"] is False

    set_error = await SetFwRuleTool(None).execute({"rule_uuid": "u-1"})
    assert set_error["status"] == "error"
    toggle_error = await ToggleFwRuleTool(None).execute(
        {"rule_uuid": "u-1", "enabled": True}
    )
    assert toggle_error["status"] == "error"


@pytest.mark.asyncio
async def test_get_logs_tool_success_and_client_exception() -> None:
    client = AsyncMock()
    client.get_firewall_logs.return_value = [
        {
            "__timestamp__": datetime.now().isoformat(),
            "interface": "wan",
            "action": "block",
            "protoname": "tcp",
            "src": "1.1.1.1",
            "srcport": "12345",
            "dst": "2.2.2.2",
            "dstport": "443",
            "rid": "1",
            "label": "test",
        }
    ]
    tool = GetLogsTool(client)
    result = await tool.execute({"limit": 10, "action": "block"})
    assert result["status"] == "success"
    assert len(result["logs"]) == 1
    assert result["summary"]["total_entries"] == 1

    client_error = AsyncMock()
    client_error.get_firewall_logs.side_effect = RuntimeError("boom")
    error_tool = GetLogsTool(client_error)
    error_result = await error_tool.execute({"limit": 10})
    assert error_result["status"] == "success"
    assert error_result["logs"] == []


@pytest.mark.asyncio
async def test_ssh_fw_rule_execute_returns_result() -> None:
    tool = SSHFirewallRuleTool(None)
    tool._create_rule_via_ssh = AsyncMock(  # type: ignore[method-assign]
        return_value={"status": "success", "message": "ok"}
    )
    result = await tool.execute({"description": "test rule"})
    assert result["status"] == "success"
