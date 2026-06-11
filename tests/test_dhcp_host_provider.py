"""Tests for the DHCP host-move provider layer.

Verified-live API contract (Phase 0 spike + Task 1.9, against fw.freeblizz.com):
- ``GET get_host/{uuid}`` must carry NO JSON body — ``OPNsenseClient._make_request``
  omits the ``Content-Type`` header when no ``json=`` kwarg is passed (requests
  default), which the dnsmasq endpoint requires.
- ``POST del_host/{uuid}`` must send a literal ``{}`` body; an empty body returns
  HTTP 400 "Invalid JSON syntax".
- ``_make_request`` raises ``RequestError`` on ``{"result": "failed"}`` responses,
  so a rejected ``set_host`` propagates and triggers ``move_host`` rollback against
  the real client (the FakeRequest stubs below do not model this).
"""

import pytest

from opnsense_mcp.utils.dhcp_provider import (
    provider_supports_host_move,
    require_host_provider,
)
from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


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


@pytest.mark.asyncio
async def test_move_host_dry_run_does_not_write():
    fake = FakeRequest(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.55,::55",
                        "hwaddr": "AA",
                        "descr": "VLAN81wifi",
                        "domain": "",
                        "local": "0",
                        "cnames": "",
                        "client_id": "",
                        "lease_time": "",
                        "ignore": "0",
                        "set_tag": "",
                        "comments": "",
                        "aliases": "",
                    }
                ],
                "total": 1,
            },
            "leases/search": {"rows": []},
        }
    )
    p = DnsmasqProvider(fake)
    out = await p.move_host(
        identifier="printer", ipv4_target=2, ipv6_target=2, dry_run=True
    )
    assert out["status"] == "dry_run"
    assert out["planned"]["ipv4"] == {"from": "10.0.8.55", "to": "10.0.8.2"}
    assert not any("set_host" in c[1] or "reconfigure" in c[1] for c in fake.calls)


@pytest.mark.asyncio
async def test_move_host_conflict_blocks():
    fake = FakeRequest(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.55,::55",
                        "hwaddr": "AA",
                        "descr": "",
                        "domain": "",
                        "local": "0",
                        "cnames": "",
                        "client_id": "",
                        "lease_time": "",
                        "ignore": "0",
                        "set_tag": "",
                        "comments": "",
                        "aliases": "",
                    },
                    {
                        "uuid": "u2",
                        "host": "bose",
                        "ip": "10.0.8.2,::2",
                        "hwaddr": "BB",
                    },
                ],
                "total": 2,
            },
            "leases/search": {"rows": []},
        }
    )
    p = DnsmasqProvider(fake)
    out = await p.move_host(
        identifier="printer", ipv4_target=2, ipv6_target=None, dry_run=False
    )
    assert out["status"] == "error"
    assert out["conflicts"]


@pytest.mark.asyncio
async def test_move_host_applies_and_reconfigures():
    fake = FakeRequest(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.55,::55",
                        "hwaddr": "AA",
                        "descr": "",
                        "domain": "",
                        "local": "0",
                        "cnames": "",
                        "client_id": "",
                        "lease_time": "",
                        "ignore": "0",
                        "set_tag": "",
                        "comments": "",
                        "aliases": "",
                    }
                ],
                "total": 1,
            },
            "leases/search": {"rows": []},
            "set_host": {"result": "saved"},
            "reconfigure": {"status": "ok"},
        }
    )
    p = DnsmasqProvider(fake)
    out = await p.move_host(
        identifier="printer", ipv4_target=2, ipv6_target=2, dry_run=False
    )
    assert out["status"] == "success"
    endpoints = [c[1] for c in fake.calls]
    assert any("set_host/u1" in e for e in endpoints)
    assert any("reconfigure" in e for e in endpoints)
    set_call = next(c for c in fake.calls if "set_host" in c[1])
    assert set_call[2]["json"]["host"]["ip"] == "10.0.8.2,::2"
    assert (
        len([c for c in fake.calls if "set_host" in c[1]]) == 1
    )  # no spurious rollback


@pytest.mark.asyncio
async def test_move_host_rolls_back_on_reconfigure_failure():
    class Boom(FakeRequest):
        async def __call__(self, method, endpoint, **kwargs):
            self.calls.append((method, endpoint, kwargs))
            if "reconfigure" in endpoint and not getattr(self, "_rolled", False):
                self._rolled = True
                raise RuntimeError("reconfigure failed")
            for key, resp in self.responses.items():
                if key in endpoint:
                    return resp
            return {}

    fake = Boom(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.55,::55",
                        "hwaddr": "AA",
                        "descr": "",
                        "domain": "",
                        "local": "0",
                        "cnames": "",
                        "client_id": "",
                        "lease_time": "",
                        "ignore": "0",
                        "set_tag": "",
                        "comments": "",
                        "aliases": "",
                    }
                ],
                "total": 1,
            },
            "leases/search": {"rows": []},
            "set_host": {"result": "saved"},
        }
    )
    p = DnsmasqProvider(fake)
    out = await p.move_host(
        identifier="printer", ipv4_target=2, ipv6_target=2, dry_run=False
    )
    assert out["status"] == "error"
    set_calls = [c for c in fake.calls if "set_host" in c[1]]
    assert set_calls[-1][2]["json"]["host"]["ip"] == "10.0.8.55,::55"


@pytest.mark.asyncio
async def test_move_host_noop_when_no_change():
    # ip field uses "::37" because apply_v6_suffix(55) -> "::37" (55 decimal = 0x37)
    fake = FakeRequest(
        {
            "search_host": {
                "rows": [
                    {
                        "uuid": "u1",
                        "host": "printer",
                        "ip": "10.0.8.55,::37",
                        "hwaddr": "AA",
                        "descr": "",
                        "domain": "",
                        "local": "0",
                        "cnames": "",
                        "client_id": "",
                        "lease_time": "",
                        "ignore": "0",
                        "set_tag": "",
                        "comments": "",
                        "aliases": "",
                    }
                ],
                "total": 1,
            },
        }
    )
    p = DnsmasqProvider(fake)
    # ipv4_target=55 -> "10.0.8.55" (same); ipv6_target=55 -> "::37" (same) -> no change
    out = await p.move_host(
        identifier="printer", ipv4_target=55, ipv6_target=55, dry_run=False
    )
    assert out["status"] == "noop"
    assert not any("set_host" in c[1] or "reconfigure" in c[1] for c in fake.calls)


@pytest.mark.asyncio
async def test_move_host_not_found_returns_error():
    fake = FakeRequest({"search_host": {"rows": [], "total": 0}})
    p = DnsmasqProvider(fake)
    out = await p.move_host(
        identifier="ghost", ipv4_target=2, ipv6_target=None, dry_run=True
    )
    assert out["status"] == "error"
    assert "ghost" in out["error"]


@pytest.mark.asyncio
async def test_find_host_falls_back_to_full_list_on_fuzzy_miss():
    # First call (with search=) returns a non-matching row (matched on descr);
    # second call (full list) returns the real host. The endpoint substring is
    # identical for both, so use a stateful fake that returns different payloads
    # per call count.
    class SeqRequest:
        def __init__(self):
            self.calls = []
            self._n = 0

        async def __call__(self, method, endpoint, **kwargs):
            self.calls.append((method, endpoint, kwargs))
            if "search_host" in endpoint:
                self._n += 1
                if self._n == 1:
                    return {
                        "rows": [
                            {
                                "uuid": "x",
                                "host": "other",
                                "ip": "10.0.8.9,::9",
                                "hwaddr": "ZZ",
                                "descr": "printer rack",
                            }
                        ]
                    }
                return {
                    "rows": [
                        {
                            "uuid": "u1",
                            "host": "printer",
                            "ip": "10.0.8.55,::55",
                            "hwaddr": "AA",
                            "descr": "",
                        }
                    ]
                }
            return {}

    fake = SeqRequest()
    p = DnsmasqProvider(fake)
    row = await p._find_host("printer")
    assert row is not None and row["uuid"] == "u1"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [ISCProvider, KeaProvider])
async def test_move_host_unsupported_backends(cls):
    p = cls(FakeRequest({}))
    assert getattr(cls, "HOST_MOVE_SUPPORTED", False) is False
    out = await p.move_host(
        identifier="x", ipv4_target=2, ipv6_target=None, dry_run=True
    )
    assert out["status"] == "error"
    assert "not supported" in out["error"].lower()
