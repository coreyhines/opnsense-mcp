"""Unit tests for traffic shaper read-path MCP tool classes (bucket 3a)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from opnsense_mcp.tools.shaper_audit import (
    AuditShaperConfigTool,
    ExplainShaperConfigTool,
)
from opnsense_mcp.tools.shaper_pipes import GetShaperPipeTool, ListShaperPipesTool
from opnsense_mcp.tools.shaper_queues import GetShaperQueueTool, ListShaperQueuesTool
from opnsense_mcp.tools.shaper_rules import GetShaperRuleTool, ListShaperRulesTool
from opnsense_mcp.tools.shaper_service import ShaperStatisticsTool
from opnsense_mcp.tools.shaper_settings import GetShaperSettingsTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.shaper_interpret import clear_baselines, store_baseline
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS

DOWNLOAD_PIPE_UUID = "e93038e5-5422-4557-b0f2-082c4cb0ddf4"
DOWNLOAD_QUEUE_UUID = "84c6c7d8-09a6-40d6-b2b7-2c1485c9d6e3"
DOWNLOAD_RULE_UUID = "690c995b-bebd-4a8d-a4c9-df6fd0dc61ea"


@pytest.fixture
def mock_client() -> MockOPNsenseClient:
    """Mock client backed by examples/mock_data traffic shaper fixtures."""
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


@pytest.fixture(autouse=True)
def reset_baselines() -> None:
    """Clear statistics baseline store between tests."""
    clear_baselines()


@pytest.mark.asyncio
async def test_list_shaper_pipes(mock_client: MockOPNsenseClient) -> None:
    tool = ListShaperPipesTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["count"] == 2
    assert len(resp["structured"]["pipes"]) == 2
    assert "Download pipe" in resp["summary"]


@pytest.mark.asyncio
async def test_list_shaper_pipes_description_filter(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = ListShaperPipesTool(mock_client)
    resp = await tool.execute({"description": "upload"})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["count"] == 1
    assert resp["structured"]["pipes"][0]["description"] == "Upload pipe"


@pytest.mark.asyncio
async def test_get_shaper_pipe_by_uuid(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperPipeTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_PIPE_UUID})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["pipe"]["uuid"] == DOWNLOAD_PIPE_UUID
    assert resp["structured"]["pipe"]["scheduler"] == "fq_codel"


@pytest.mark.asyncio
async def test_get_shaper_pipe_by_description(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperPipeTool(mock_client)
    resp = await tool.execute({"description": "Download pipe"})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["pipe"]["description"] == "Download pipe"


@pytest.mark.asyncio
async def test_get_shaper_pipe_not_found(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperPipeTool(mock_client)
    resp = await tool.execute({"uuid": "00000000-0000-0000-0000-000000000000"})
    assert resp["status"] == "error"


@pytest.mark.asyncio
async def test_list_shaper_queues(mock_client: MockOPNsenseClient) -> None:
    tool = ListShaperQueuesTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["count"] == 2


@pytest.mark.asyncio
async def test_get_shaper_queue_by_uuid(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperQueueTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_QUEUE_UUID})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["queue"]["pipe_uuid"] == DOWNLOAD_PIPE_UUID


@pytest.mark.asyncio
async def test_list_shaper_rules(mock_client: MockOPNsenseClient) -> None:
    tool = ListShaperRulesTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["count"] == 2


@pytest.mark.asyncio
async def test_get_shaper_rule_by_uuid(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperRuleTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_RULE_UUID})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["rule"]["interface"] == "wan"
    assert resp["structured"]["rule"]["direction"] == "in"


@pytest.mark.asyncio
async def test_get_shaper_settings(mock_client: MockOPNsenseClient) -> None:
    tool = GetShaperSettingsTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["pipe_count"] == 2
    assert resp["structured"]["queue_count"] == 2
    assert resp["structured"]["rule_count"] == 2


@pytest.mark.asyncio
async def test_shaper_statistics_fqcodel_layout_not_critical_drift(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = ShaperStatisticsTool(mock_client)
    resp = await tool.execute({})
    assert resp["baseline_id"]
    assert resp["structured"]["stored_baseline_id"] == resp["baseline_id"]
    assert not any("SCHEDULER_DRIFT" in hint for hint in resp["hints"])
    assert resp["status"] != "critical"


@pytest.mark.asyncio
async def test_shaper_statistics_true_drift_is_critical(
    mock_client: MockOPNsenseClient,
) -> None:
    mock_client._ensure_shaper_mutable_copy()
    stats = copy.deepcopy(mock_client._mutable_shaper["statistics"])  # type: ignore[index]
    for item in stats.get("items", []):
        if item.get("type") == "pipe":
            item.pop("flowset", None)
            item.pop("pipe", None)
            item.pop("id", None)
    mock_client._mutable_shaper["statistics"] = stats  # type: ignore[index]
    tool = ShaperStatisticsTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == "critical"
    assert any("SCHEDULER_DRIFT" in hint for hint in resp["hints"])


@pytest.mark.asyncio
async def test_shaper_statistics_baseline_delta(
    mock_client: MockOPNsenseClient,
) -> None:
    stats = await mock_client._make_request("GET", "/trafficshaper/service/statistics")
    store_baseline("prior-run", stats)

    tool = ShaperStatisticsTool(mock_client)
    resp = await tool.execute({"baseline_id": "prior-run"})
    assert resp["structured"]["baseline_delta"] is not None
    assert resp["baseline_id"] != "prior-run"


@pytest.mark.asyncio
async def test_audit_shaper_config(mock_client: MockOPNsenseClient) -> None:
    tool = AuditShaperConfigTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == "warning"
    assert resp["structured"]["score"] >= 0
    assert resp["structured"]["finding_count"] >= 1
    assert "Traffic Shaper Audit" in resp["summary"]
    assert not any(
        f.get("code") == "SCHEDULER_DRIFT" for f in resp["structured"]["findings"]
    )


@pytest.mark.asyncio
async def test_audit_shaper_config_isp_rates(mock_client: MockOPNsenseClient) -> None:
    tool = AuditShaperConfigTool(mock_client)
    resp = await tool.execute(
        {"isp_download_mbit": 1000, "isp_upload_mbit": 40, "wan_line_rate_mbit": 1000}
    )
    assert resp["structured"]["finding_count"] >= 1


@pytest.mark.asyncio
async def test_explain_shaper_config(mock_client: MockOPNsenseClient) -> None:
    tool = ExplainShaperConfigTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] in {"success", "warning", "error", "critical"}
    assert "narrative" in resp["structured"]
    assert len(resp["structured"]["narrative"]) > 20
    assert "Traffic Shaper Explained" in resp["summary"]


@pytest.mark.asyncio
async def test_explain_shaper_config_without_audit(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = ExplainShaperConfigTool(mock_client)
    resp = await tool.execute({"include_audit": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["hints"] == []


@pytest.mark.asyncio
async def test_tools_no_client() -> None:
    resp = await ListShaperPipesTool(None).execute({})
    assert resp["status"] == "error"
