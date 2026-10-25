"""Tests for single and paired Unbound host override creation."""

from unittest.mock import AsyncMock, call

import pytest

from opnsense_mcp.tools.mkdns import MkdnsTool


def _client() -> AsyncMock:
    client = AsyncMock()
    client.search_host_overrides.return_value = []
    client.reconfigure_unbound.return_value = {"applied": True}
    return client


@pytest.mark.asyncio
async def test_mkdns_pair_creates_a_and_aaaa_then_one_reconfigure() -> None:
    client = _client()
    client.add_host_override.side_effect = [{"uuid": "u1"}, {"uuid": "u2"}]

    result = await MkdnsTool(client).execute(
        {
            "hostname": "firecrawl-cache",
            "domain": "example.com",
            "server": "192.0.2.37",
            "server6": "2001:db8:5eed:b501::37",
        }
    )

    assert result["status"] == "success"
    assert result["uuids"] == {"A": "u1", "AAAA": "u2"}
    assert result["uuid"] == "u1"
    assert result["rr"] == "A+AAAA"
    assert result["server6"] == "2001:db8:5eed:b501::37"
    assert result["applied"] is True
    client.search_host_overrides.assert_awaited_once_with("firecrawl-cache")
    assert client.add_host_override.await_args_list == [
        call(
            hostname="firecrawl-cache",
            domain="example.com",
            server="192.0.2.37",
            description="",
            enabled=True,
            rr="A",
        ),
        call(
            hostname="firecrawl-cache",
            domain="example.com",
            server="2001:db8:5eed:b501::37",
            description="",
            enabled=True,
            rr="AAAA",
        ),
    ]
    client.reconfigure_unbound.assert_awaited_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server", "server6"),
    [
        ("2001:db8:5eed:b501::37", "2001:db8:5eed:b501::38"),
        ("192.0.2.37", "192.0.2.38"),
    ],
)
async def test_mkdns_rejects_wrong_family_pair(server: str, server6: str) -> None:
    client = _client()

    result = await MkdnsTool(client).execute(
        {
            "hostname": "host",
            "domain": "example.com",
            "server": server,
            "server6": server6,
        }
    )

    assert result["status"] == "error"
    client.search_host_overrides.assert_not_awaited()
    client.add_host_override.assert_not_awaited()


@pytest.mark.asyncio
async def test_mkdns_refuses_exact_duplicate() -> None:
    client = _client()
    client.search_host_overrides.return_value = [
        {
            "hostname": "Firecrawl-Cache",
            "domain": "example.com",
            "server": "192.0.2.37",
            "rr": "A",
        }
    ]

    result = await MkdnsTool(client).execute(
        {
            "hostname": "firecrawl-cache",
            "domain": "EXAMPLE.COM",
            "server": "192.0.2.37",
        }
    )

    assert result["status"] == "error"
    assert "already exists" in result["error"]
    client.add_host_override.assert_not_awaited()


@pytest.mark.asyncio
async def test_mkdns_duplicate_check_failure_is_error() -> None:
    client = _client()
    client.search_host_overrides.side_effect = RuntimeError("lookup failed")

    result = await MkdnsTool(client).execute(
        {"hostname": "host", "domain": "example.com", "server": "192.0.2.37"}
    )

    assert result["status"] == "error"
    assert "lookup failed" in result["error"]
    client.add_host_override.assert_not_awaited()


@pytest.mark.asyncio
async def test_mkdns_rolls_back_first_row_when_second_add_fails() -> None:
    client = _client()
    client.add_host_override.side_effect = [{"uuid": "u1"}, RuntimeError("AAAA failed")]

    result = await MkdnsTool(client).execute(
        {
            "hostname": "host",
            "domain": "example.com",
            "server": "192.0.2.37",
            "server6": "2001:db8:5eed:b501::37",
        }
    )

    assert result["status"] == "error"
    assert "AAAA failed" in result["error"]
    client.del_host_override.assert_awaited_once_with("u1")
    client.reconfigure_unbound.assert_not_awaited()


@pytest.mark.asyncio
async def test_mkdns_reports_leftover_when_rollback_fails() -> None:
    client = _client()
    client.add_host_override.side_effect = [{"uuid": "u1"}, RuntimeError("AAAA failed")]
    client.del_host_override.side_effect = RuntimeError("delete failed")

    result = await MkdnsTool(client).execute(
        {
            "hostname": "host",
            "domain": "example.com",
            "server": "192.0.2.37",
            "server6": "2001:db8:5eed:b501::37",
        }
    )

    assert result["status"] == "error"
    assert "AAAA failed" in result["error"]
    assert "rollback failed" in result["error"]
    assert "u1" in result["error"]


@pytest.mark.asyncio
async def test_mkdns_applied_reflects_reconfigure() -> None:
    client = _client()
    client.add_host_override.return_value = {"uuid": "u1"}
    client.reconfigure_unbound.return_value = {"applied": False, "apply_error": "x"}

    result = await MkdnsTool(client).execute(
        {"hostname": "host", "domain": "example.com", "server": "192.0.2.37"}
    )

    assert result["status"] == "success"
    assert result["uuids"] == {"A": "u1"}
    assert result["applied"] is False
    assert result["apply_error"] == "x"
