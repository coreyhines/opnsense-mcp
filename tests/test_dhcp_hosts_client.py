import pytest

from opnsense_mcp.utils.api import OPNsenseClient


class FakeProvider:
    name = "dnsmasq"
    HOST_MOVE_SUPPORTED = True

    def __init__(self):
        self.called = None

    async def list_hosts(self, search=""):
        self.called = search
        return [{"uuid": "u1", "host": "printer", "ip": "10.0.8.2,::2"}]


@pytest.mark.asyncio
async def test_client_list_dhcp_hosts_delegates():
    client = OPNsenseClient.__new__(OPNsenseClient)
    client._dhcp_provider = FakeProvider()
    rows = await client.list_dhcp_hosts(search="printer")
    assert len(rows) == 1
    assert client._dhcp_provider.called == "printer"


@pytest.mark.asyncio
async def test_client_list_dhcp_hosts_unsupported_backend_raises():
    class NoSupport:
        name = "isc"
        HOST_MOVE_SUPPORTED = False

    client = OPNsenseClient.__new__(OPNsenseClient)
    client._dhcp_provider = NoSupport()
    with pytest.raises(ValueError, match="host move"):
        await client.list_dhcp_hosts()
