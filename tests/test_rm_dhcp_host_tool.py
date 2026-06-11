import pytest

from opnsense_mcp.tools.rm_dhcp_host import RmDhcpHostTool


class FakeClient:
    def __init__(self):
        self.called = None

    async def delete_dhcp_host(self, **kwargs):
        self.called = kwargs
        return {"status": "dry_run", "planned": {"host": "chines"}}


@pytest.mark.asyncio
async def test_tool_requires_host():
    tool = RmDhcpHostTool(FakeClient())
    out = await tool.execute({})
    assert out["status"] == "error"


@pytest.mark.asyncio
async def test_tool_defaults_to_dry_run():
    client = FakeClient()
    tool = RmDhcpHostTool(client)
    out = await tool.execute({"host": "chines"})
    assert out["status"] == "dry_run"
    assert client.called["identifier"] == "chines"
    assert client.called["dry_run"] is True


@pytest.mark.asyncio
async def test_tool_passes_apply_flag():
    client = FakeClient()
    tool = RmDhcpHostTool(client)
    await tool.execute({"host": "chines", "apply": True})
    assert client.called["dry_run"] is False


@pytest.mark.asyncio
async def test_tool_no_client():
    tool = RmDhcpHostTool(None)
    out = await tool.execute({"host": "chines"})
    assert out["status"] == "error"
