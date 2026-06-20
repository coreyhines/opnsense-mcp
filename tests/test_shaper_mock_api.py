"""Tests for MockOPNsenseClient traffic shaper endpoints (bucket 3c)."""

from __future__ import annotations

from pathlib import Path

import pytest

from opnsense_mcp.utils.mock_api import MockOPNsenseClient


@pytest.fixture
def mock_client() -> MockOPNsenseClient:
    """Mock client with examples/mock_data including traffic_shaper.json."""
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


@pytest.mark.asyncio
async def test_mock_shaper_settings_get(mock_client: MockOPNsenseClient) -> None:
    data = await mock_client._make_request("GET", "/trafficshaper/settings/get")
    pipes = (data.get("ts") or {}).get("pipes", {}).get("pipe", {})
    assert len(pipes) == 2


@pytest.mark.asyncio
async def test_mock_shaper_search_pipes(mock_client: MockOPNsenseClient) -> None:
    data = await mock_client._make_request(
        "POST", "/trafficshaper/settings/search_pipes"
    )
    assert data.get("rowCount") == 2
    assert data["rows"][0]["scheduler"] == "fq_codel"


@pytest.mark.asyncio
async def test_mock_shaper_statistics_fifo_runtime(
    mock_client: MockOPNsenseClient,
) -> None:
    data = await mock_client._make_request("GET", "/trafficshaper/service/statistics")
    pipes = [i for i in data.get("items", []) if i.get("type") == "pipe"]
    assert pipes[0]["scheduler"]["sched_type"] == "FIFO"


@pytest.mark.asyncio
async def test_mock_shaper_get_pipe_by_uuid(mock_client: MockOPNsenseClient) -> None:
    uuid = "e93038e5-5422-4557-b0f2-082c4cb0ddf4"
    data = await mock_client._make_request(
        "GET", f"/trafficshaper/settings/get_pipe/{uuid}"
    )
    assert data["pipe"]["uuid"] == uuid
