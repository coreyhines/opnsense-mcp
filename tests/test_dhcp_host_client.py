import pytest

from opnsense_mcp.utils.api import OPNsenseClient


class FakeProvider:
    name = "dnsmasq"
    HOST_MOVE_SUPPORTED = True

    def __init__(self):
        self.called = None

    async def move_host(self, **kwargs):
        self.called = kwargs
        return {"status": "dry_run", "planned": {}}


@pytest.mark.asyncio
async def test_client_move_dhcp_host_delegates():
    client = OPNsenseClient.__new__(OPNsenseClient)  # bypass network init
    client._dhcp_provider = FakeProvider()
    out = await client.move_dhcp_host(
        identifier="printer", ipv4=2, ipv6=2, dry_run=True
    )
    assert out["status"] == "dry_run"
    assert client._dhcp_provider.called["identifier"] == "printer"
    assert client._dhcp_provider.called["ipv4_target"] == 2
    assert client._dhcp_provider.called["ipv6_target"] == 2
    assert client._dhcp_provider.called["dry_run"] is True


@pytest.mark.asyncio
async def test_client_move_dhcp_host_unsupported_backend_raises():
    class NoSupport:
        name = "isc"
        HOST_MOVE_SUPPORTED = False

    client = OPNsenseClient.__new__(OPNsenseClient)
    client._dhcp_provider = NoSupport()
    with pytest.raises(ValueError, match="host move"):
        await client.move_dhcp_host(identifier="x", ipv4=2)
