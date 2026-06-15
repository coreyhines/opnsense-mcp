import pytest

from opnsense_mcp.tools.dhcp_host_move import MoveDhcpHostTool


class FakeClient:
    def __init__(self):
        self.called = None

    async def move_dhcp_host(self, **kwargs):
        self.called = kwargs
        return {"status": "dry_run", "planned": {"host": "printer"}}


@pytest.mark.asyncio
async def test_tool_requires_identifier():
    tool = MoveDhcpHostTool(FakeClient())
    out = await tool.execute({"ipv4": 2})
    assert out["status"] == "error"
    assert "identifier" in out["error"].lower() or "host" in out["error"].lower()


@pytest.mark.asyncio
async def test_tool_requires_at_least_one_target():
    tool = MoveDhcpHostTool(FakeClient())
    out = await tool.execute({"host": "printer"})
    assert out["status"] == "error"


@pytest.mark.asyncio
async def test_tool_defaults_to_dry_run():
    client = FakeClient()
    tool = MoveDhcpHostTool(client)
    out = await tool.execute({"host": "printer", "ipv4": 2})
    assert out["status"] == "dry_run"
    assert client.called["dry_run"] is True


@pytest.mark.asyncio
async def test_tool_passes_apply_flag():
    client = FakeClient()
    tool = MoveDhcpHostTool(client)
    await tool.execute({"host": "printer", "ipv4": 2, "apply": True})
    assert client.called["dry_run"] is False


@pytest.mark.asyncio
async def test_tool_passes_new_hostname():
    client = FakeClient()
    tool = MoveDhcpHostTool(client)
    await tool.execute({"host": "printer", "new_hostname": "printer2"})
    assert client.called["new_hostname"] == "printer2"


@pytest.mark.asyncio
async def test_tool_no_client():
    tool = MoveDhcpHostTool(None)
    out = await tool.execute({"host": "printer", "ipv4": 2})
    assert out["status"] == "error"
