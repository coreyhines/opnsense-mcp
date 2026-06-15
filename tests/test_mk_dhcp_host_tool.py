import pytest

from opnsense_mcp.tools.mk_dhcp_host import MkDhcpHostTool


class FakeClient:
    def __init__(self, result=None):
        self.called = None
        self._result = result or {"status": "dry_run", "planned": {}}

    async def add_dhcp_host(self, **kwargs):
        self.called = kwargs
        return self._result


@pytest.mark.asyncio
async def test_tool_requires_hostname():
    tool = MkDhcpHostTool(FakeClient())
    out = await tool.execute({"mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.0.5"})
    assert out["status"] == "error"
    assert "hostname" in out["error"]


@pytest.mark.asyncio
async def test_tool_requires_mac():
    tool = MkDhcpHostTool(FakeClient())
    out = await tool.execute({"hostname": "myhost", "ipv4": "10.0.0.5"})
    assert out["status"] == "error"
    assert "mac" in out["error"]


@pytest.mark.asyncio
async def test_tool_requires_ipv4_or_ipv6():
    tool = MkDhcpHostTool(FakeClient())
    out = await tool.execute({"hostname": "myhost", "mac": "aa:bb:cc:dd:ee:ff"})
    assert out["status"] == "error"
    assert "ipv4" in out["error"] or "ipv6" in out["error"]


@pytest.mark.asyncio
async def test_tool_defaults_to_dry_run():
    client = FakeClient()
    tool = MkDhcpHostTool(client)
    out = await tool.execute(
        {"hostname": "myhost", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.8.50"}
    )
    assert client.called["dry_run"] is True
    assert client.called["hostname"] == "myhost"
    assert client.called["mac"] == "aa:bb:cc:dd:ee:ff"
    assert client.called["ipv4"] == "10.0.8.50"


@pytest.mark.asyncio
async def test_tool_passes_apply_flag():
    client = FakeClient({"status": "success", "created": {}})
    tool = MkDhcpHostTool(client)
    await tool.execute(
        {
            "hostname": "myhost",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ipv4": "10.0.8.50",
            "apply": True,
        }
    )
    assert client.called["dry_run"] is False


@pytest.mark.asyncio
async def test_tool_passes_ipv6():
    client = FakeClient()
    tool = MkDhcpHostTool(client)
    await tool.execute(
        {
            "hostname": "myhost",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ipv4": "10.0.8.50",
            "ipv6": 50,
        }
    )
    assert client.called["ipv6"] == 50


@pytest.mark.asyncio
async def test_tool_passes_descr_and_domain():
    client = FakeClient()
    tool = MkDhcpHostTool(client)
    await tool.execute(
        {
            "hostname": "myhost",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ipv4": "10.0.8.50",
            "descr": "test device",
            "domain": "lan",
        }
    )
    assert client.called["descr"] == "test device"
    assert client.called["domain"] == "lan"


@pytest.mark.asyncio
async def test_tool_passes_client_id():
    client = FakeClient()
    tool = MkDhcpHostTool(client)
    await tool.execute(
        {
            "hostname": "hermes",
            "mac": "52:54:00:ab:cd:01",
            "ipv4": "10.0.3.13",
            "ipv6": 13,
            "client_id": "00:03:00:01:52:54:00:ab:cd:01",
        }
    )
    assert client.called["client_id"] == "00:03:00:01:52:54:00:ab:cd:01"


@pytest.mark.asyncio
async def test_tool_no_client():
    tool = MkDhcpHostTool(None)
    out = await tool.execute(
        {"hostname": "myhost", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.8.50"}
    )
    assert out["status"] == "error"
