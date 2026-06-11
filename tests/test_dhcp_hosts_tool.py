import pytest

from opnsense_mcp.tools.dhcp_hosts import ListDhcpHostsTool


class FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.called = None

    async def list_dhcp_hosts(self, *, search=""):
        self.called = search
        return self.rows


@pytest.mark.asyncio
async def test_tool_lists_all_hosts():
    rows = [
        {
            "uuid": "u1",
            "host": "printer",
            "ip": "10.0.8.2,::2",
            "hwaddr": "aa:bb:cc:dd:ee:ff",
            "descr": "VLAN81wifi",
        },
        {
            "uuid": "u2",
            "host": "ztx",
            "ip": "10.0.5.6",
            "hwaddr": "11:22:33:44:55:66",
            "descr": "VLAN5LAB",
        },
    ]
    client = FakeClient(rows)
    tool = ListDhcpHostsTool(client)
    out = await tool.execute({})
    assert out["status"] == "success"
    assert out["count"] == 2
    assert out["missing_ipv6_count"] == 1
    assert client.called == ""


@pytest.mark.asyncio
async def test_tool_passes_search_to_client():
    client = FakeClient([])
    tool = ListDhcpHostsTool(client)
    await tool.execute({"search": "printer"})
    assert client.called == "printer"


@pytest.mark.asyncio
async def test_tool_filters_by_descr():
    rows = [
        {
            "uuid": "u1",
            "host": "a",
            "ip": "10.0.2.1,::1",
            "hwaddr": "aa:bb:cc:dd:ee:01",
            "descr": "VLAN2wired",
        },
        {
            "uuid": "u2",
            "host": "b",
            "ip": "10.0.8.2,::2",
            "hwaddr": "aa:bb:cc:dd:ee:02",
            "descr": "VLAN81wifi",
        },
    ]
    tool = ListDhcpHostsTool(FakeClient(rows))
    out = await tool.execute({"descr": "vlan2"})
    assert out["count"] == 1
    assert out["hosts"][0]["host"] == "a"


@pytest.mark.asyncio
async def test_tool_missing_ipv6_filter():
    rows = [
        {
            "uuid": "u1",
            "host": "a",
            "ip": "10.0.2.1,::1",
            "hwaddr": "aa:bb:cc:dd:ee:01",
            "descr": "VLAN2wired",
        },
        {
            "uuid": "u2",
            "host": "b",
            "ip": "10.0.5.6",
            "hwaddr": "aa:bb:cc:dd:ee:02",
            "descr": "VLAN5LAB",
        },
    ]
    tool = ListDhcpHostsTool(FakeClient(rows))
    out = await tool.execute({"missing_ipv6": True})
    assert out["count"] == 1
    assert out["hosts"][0]["host"] == "b"
    assert out["missing_ipv6_count"] == 1


@pytest.mark.asyncio
async def test_tool_no_client():
    tool = ListDhcpHostsTool(None)
    out = await tool.execute({})
    assert out["status"] == "error"
