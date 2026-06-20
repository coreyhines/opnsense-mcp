"""Tests for MockOPNsenseClient shaper write endpoints (bucket 4c)."""

from __future__ import annotations

from pathlib import Path

import pytest

from opnsense_mcp.utils.mock_api import MockOPNsenseClient

DOWNLOAD_PIPE = "e93038e5-5422-4557-b0f2-082c4cb0ddf4"
DOWNLOAD_QUEUE = "84c6c7d8-09a6-40d6-b2b7-2c1485c9d6e3"
DOWNLOAD_RULE = "690c995b-bebd-4a8d-a4c9-df6fd0dc61ea"


@pytest.fixture
def mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


@pytest.mark.asyncio
async def test_add_pipe_updates_settings_and_search(
    mock_client: MockOPNsenseClient,
) -> None:
    before = await mock_client._make_request("GET", "/trafficshaper/settings/get")
    before_count = len((before.get("ts") or {}).get("pipes", {}).get("pipe", {}))
    result = await mock_client._make_request(
        "POST", "/trafficshaper/settings/add_pipe/"
    )
    assert result["status"] == "ok"
    pipe_uuid = result["id"]
    after = await mock_client._make_request("GET", "/trafficshaper/settings/get")
    pipes = (after.get("ts") or {}).get("pipes", {}).get("pipe", {})
    assert len(pipes) == before_count + 1
    search = await mock_client._make_request(
        "POST", "/trafficshaper/settings/search_pipes"
    )
    assert search["rowCount"] == before_count + 1
    assert any(r["uuid"] == pipe_uuid for r in search["rows"])


@pytest.mark.asyncio
async def test_del_pipe_removes_row(mock_client: MockOPNsenseClient) -> None:
    result = await mock_client._make_request(
        "POST",
        f"/trafficshaper/settings/del_pipe/{DOWNLOAD_PIPE}",
    )
    assert result["status"] == "ok"
    after = await mock_client._make_request("GET", "/trafficshaper/settings/get")
    pipes = (after.get("ts") or {}).get("pipes", {}).get("pipe", {})
    assert DOWNLOAD_PIPE not in pipes


@pytest.mark.asyncio
async def test_toggle_pipe_flips_enabled(mock_client: MockOPNsenseClient) -> None:
    result = await mock_client._make_request(
        "POST",
        f"/trafficshaper/settings/toggle_pipe/{DOWNLOAD_PIPE}",
    )
    assert result["status"] == "ok"
    assert result.get("enabled") == "0"


@pytest.mark.asyncio
async def test_add_queue_and_rule(mock_client: MockOPNsenseClient) -> None:
    q = await mock_client._make_request("POST", "/trafficshaper/settings/add_queue/")
    assert q["status"] == "ok"
    r = await mock_client._make_request("POST", "/trafficshaper/settings/add_rule/")
    assert r["status"] == "ok"


@pytest.mark.asyncio
async def test_del_queue_and_rule(mock_client: MockOPNsenseClient) -> None:
    dq = await mock_client._make_request(
        "POST",
        f"/trafficshaper/settings/del_queue/{DOWNLOAD_QUEUE}",
    )
    assert dq["status"] == "ok"
    dr = await mock_client._make_request(
        "POST",
        f"/trafficshaper/settings/del_rule/{DOWNLOAD_RULE}",
    )
    assert dr["status"] == "ok"


@pytest.mark.asyncio
async def test_set_and_reconfigure(mock_client: MockOPNsenseClient) -> None:
    s = await mock_client._make_request("POST", "/trafficshaper/settings/set")
    assert s["status"] == "ok"
    rc = await mock_client._make_request("POST", "/trafficshaper/service/reconfigure")
    assert rc["status"] == "ok"


@pytest.mark.asyncio
async def test_read_paths_still_work(mock_client: MockOPNsenseClient) -> None:
    stats = await mock_client._make_request("GET", "/trafficshaper/service/statistics")
    assert stats["status"] == "ok"
