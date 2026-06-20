"""Unit tests for traffic shaper write-path MCP tools (buckets 4d–4h, 5a)."""

from __future__ import annotations

from pathlib import Path

import pytest

from opnsense_mcp.tools.shaper_pipes import (
    AddShaperPipeTool,
    DeleteShaperPipeTool,
    SetShaperPipeTool,
    ToggleShaperPipeTool,
)
from opnsense_mcp.tools.shaper_presets import ApplyShaperPresetTool
from opnsense_mcp.tools.shaper_queues import AddShaperQueueTool, ToggleShaperQueueTool
from opnsense_mcp.tools.shaper_rules import AddShaperRuleTool
from opnsense_mcp.tools.shaper_service import ApplyShaperTool
from opnsense_mcp.tools.shaper_settings import SetShaperSettingsTool
from opnsense_mcp.tools.shaper_snapshot import RestoreShaperSnapshotTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.shaper_snapshot_store import clear_snapshots, get_snapshot
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS

DOWNLOAD_PIPE = "e93038e5-5422-4557-b0f2-082c4cb0ddf4"
DOWNLOAD_QUEUE = "84c6c7d8-09a6-40d6-b2b7-2c1485c9d6e3"
DOWNLOAD_RULE = "690c995b-bebd-4a8d-a4c9-df6fd0dc61ea"


@pytest.fixture
def mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


@pytest.fixture(autouse=True)
def reset_snapshots() -> None:
    clear_snapshots()


@pytest.mark.asyncio
async def test_add_shaper_pipe(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperPipeTool(mock_client)
    resp = await tool.execute(
        {
            "description": "Test pipe",
            "bandwidth": 500,
            "apply": False,
        }
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["pipe"]["bandwidth"] == 500
    assert resp.get("snapshot_id")


@pytest.mark.asyncio
async def test_set_shaper_pipe(mock_client: MockOPNsenseClient) -> None:
    tool = SetShaperPipeTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_PIPE, "bandwidth": 900, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["pipe"]["bandwidth"] == 900


@pytest.mark.asyncio
async def test_toggle_shaper_pipe(mock_client: MockOPNsenseClient) -> None:
    tool = ToggleShaperPipeTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_PIPE, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["api_result"]["status"] == "ok"


@pytest.mark.asyncio
async def test_delete_shaper_pipe_requires_confirm(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = DeleteShaperPipeTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_PIPE})
    assert resp["status"] == "error"
    token = resp["structured"]["confirm_token"]
    resp2 = await tool.execute(
        {"uuid": DOWNLOAD_PIPE, "confirm": token, "apply": False}
    )
    assert resp2["status"] == TOOL_STATUS_SUCCESS


@pytest.mark.asyncio
async def test_add_shaper_queue(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperQueueTool(mock_client)
    resp = await tool.execute(
        {
            "description": "Test queue",
            "pipe_uuid": DOWNLOAD_PIPE,
            "apply": False,
        }
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["queue"]["pipe_uuid"] == DOWNLOAD_PIPE


@pytest.mark.asyncio
async def test_add_shaper_rule(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperRuleTool(mock_client)
    resp = await tool.execute(
        {
            "description": "Test rule",
            "interface": "wan",
            "direction": "in",
            "target_uuid": DOWNLOAD_PIPE,
            "apply": False,
        }
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS


@pytest.mark.asyncio
async def test_set_shaper_settings(mock_client: MockOPNsenseClient) -> None:
    tool = SetShaperSettingsTool(mock_client)
    resp = await tool.execute({"apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["applied"] is False


@pytest.mark.asyncio
async def test_apply_shaper(mock_client: MockOPNsenseClient) -> None:
    tool = ApplyShaperTool(mock_client)
    resp = await tool.execute({})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["applied"] is True


@pytest.mark.asyncio
async def test_restore_shaper_snapshot(mock_client: MockOPNsenseClient) -> None:
    add = AddShaperPipeTool(mock_client)
    created = await add.execute(
        {"description": "Snap pipe", "bandwidth": 100, "apply": False}
    )
    snapshot_id = created["snapshot_id"]
    assert get_snapshot(snapshot_id) is not None
    restore = RestoreShaperSnapshotTool(mock_client)
    resp = await restore.execute({"snapshot_id": snapshot_id, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["restored"] >= 1


@pytest.mark.asyncio
async def test_apply_shaper_preset(mock_client: MockOPNsenseClient) -> None:
    tool = ApplyShaperPresetTool(mock_client)
    resp = await tool.execute(
        {"download_mbit": 1000, "upload_mbit": 500, "apply": False}
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["preset"] == "bufferbloat_wan"
    assert resp["structured"]["download_mbit"] == 850
    assert resp["structured"]["upload_mbit"] == 425


@pytest.mark.asyncio
async def test_toggle_shaper_queue(mock_client: MockOPNsenseClient) -> None:
    tool = ToggleShaperQueueTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_QUEUE, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
