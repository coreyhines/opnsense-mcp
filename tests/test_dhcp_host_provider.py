import pytest

from opnsense_mcp.utils.dhcp_provider import (
    provider_supports_host_move,
    require_host_provider,
)


class _Supports:
    name = "dnsmasq"
    HOST_MOVE_SUPPORTED = True


class _NoSupport:
    name = "isc"
    HOST_MOVE_SUPPORTED = False


def test_provider_supports_host_move():
    assert provider_supports_host_move(_Supports()) is True
    assert provider_supports_host_move(_NoSupport()) is False


def test_require_host_provider_raises_for_unsupported():
    with pytest.raises(ValueError, match="host move"):
        require_host_provider(_NoSupport())


def test_require_host_provider_returns_supported():
    p = _Supports()
    assert require_host_provider(p) is p


from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider


class FakeRequest:
    """Records (method, endpoint, kwargs) and returns scripted responses."""

    def __init__(self, responses):
        self.responses = responses  # dict: endpoint-substring -> response
        self.calls = []

    async def __call__(self, method, endpoint, **kwargs):
        self.calls.append((method, endpoint, kwargs))
        for key, resp in self.responses.items():
            if key in endpoint:
                return resp
        return {}


@pytest.mark.asyncio
async def test_list_hosts_returns_rows():
    fake = FakeRequest(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.2,::2",
                        "hwaddr": "AA",
                    }
                ],
                "total": 1,
            }
        }
    )
    p = DnsmasqProvider(fake)
    rows = await p.list_hosts()
    assert rows[0]["host"] == "printer"
    method, endpoint, kwargs = fake.calls[0]
    assert method == "POST" and "search_host" in endpoint
    assert kwargs["json"]["rowCount"] == -1


@pytest.mark.asyncio
async def test_set_host_posts_to_uuid_with_host_envelope():
    fake = FakeRequest({"set_host": {"result": "saved"}})
    p = DnsmasqProvider(fake)
    out = await p.set_host("u1", {"ip": "10.0.8.9,::9", "host": "printer"})
    assert out["result"] == "saved"
    method, endpoint, kwargs = fake.calls[0]
    assert method == "POST" and endpoint.endswith("set_host/u1")
    assert kwargs["json"] == {"host": {"ip": "10.0.8.9,::9", "host": "printer"}}


@pytest.mark.asyncio
async def test_del_host_sends_empty_json_body():
    fake = FakeRequest({"del_host": {"result": "deleted"}})
    p = DnsmasqProvider(fake)
    out = await p.del_host("u1")
    assert out["result"] == "deleted"
    method, endpoint, kwargs = fake.calls[0]
    assert method == "POST" and endpoint.endswith("del_host/u1")
    assert kwargs["json"] == {}  # CRITICAL: empty body required


@pytest.mark.asyncio
async def test_get_host_uses_get_without_json_body():
    fake = FakeRequest({"get_host": {"host": {"host": "printer"}}})
    p = DnsmasqProvider(fake)
    out = await p.get_host("u1")
    assert out["host"]["host"] == "printer"
    method, endpoint, kwargs = fake.calls[0]
    assert method == "GET" and endpoint.endswith("get_host/u1")
    assert "json" not in kwargs  # no body / no Content-Type on GET
