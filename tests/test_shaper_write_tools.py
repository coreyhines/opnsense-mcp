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
from opnsense_mcp.tools.shaper_presets import PRESET_RULES, ApplyShaperPresetTool
from opnsense_mcp.tools.shaper_queues import (
    AddShaperQueueTool,
    DeleteShaperQueueTool,
    ToggleShaperQueueTool,
)
from opnsense_mcp.tools.shaper_rules import AddShaperRuleTool, DeleteShaperRuleTool
from opnsense_mcp.tools.shaper_service import ApplyShaperTool
from opnsense_mcp.tools.shaper_settings import (
    SetShaperSettingsTool,
    search_shaper_pipes,
    search_shaper_rules,
)
from opnsense_mcp.tools.shaper_snapshot import RestoreShaperSnapshotTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.shaper_snapshot_store import clear_snapshots, get_snapshot
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS, TOOL_STATUS_WARNING

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


@pytest.mark.asyncio
async def test_add_shaper_queue_no_client() -> None:
    tool = AddShaperQueueTool(None)
    resp = await tool.execute({"description": "x", "pipe_uuid": DOWNLOAD_PIPE})
    assert resp["status"] == "error"
    assert "No client" in resp["structured"]["error"]


@pytest.mark.asyncio
async def test_add_shaper_queue_invalid_pipe(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperQueueTool(mock_client)
    resp = await tool.execute(
        {
            "description": "Bad queue",
            "pipe_uuid": "00000000-0000-0000-0000-000000000000",
            "apply": False,
        }
    )
    assert resp["status"] == "error"
    assert resp["structured"]["error"] == "pipe_uuid not found"


@pytest.mark.asyncio
async def test_add_shaper_rule_invalid_target(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperRuleTool(mock_client)
    resp = await tool.execute(
        {
            "description": "Bad rule",
            "interface": "wan",
            "direction": "in",
            "target_uuid": "00000000-0000-0000-0000-000000000000",
            "apply": False,
        }
    )
    assert resp["status"] == "error"
    assert resp["structured"]["error"] == "target_uuid not found"


@pytest.mark.asyncio
async def test_delete_shaper_queue_requires_confirm(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = DeleteShaperQueueTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_QUEUE})
    assert resp["status"] == "error"
    token = resp["structured"]["confirm_token"]
    resp2 = await tool.execute(
        {"uuid": DOWNLOAD_QUEUE, "confirm": token, "apply": False}
    )
    assert resp2["status"] == TOOL_STATUS_SUCCESS


@pytest.mark.asyncio
async def test_delete_shaper_rule_requires_confirm(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = DeleteShaperRuleTool(mock_client)
    resp = await tool.execute({"uuid": DOWNLOAD_RULE})
    assert resp["status"] == "error"
    token = resp["structured"]["confirm_token"]
    resp2 = await tool.execute(
        {"uuid": DOWNLOAD_RULE, "confirm": token, "apply": False}
    )
    assert resp2["status"] == TOOL_STATUS_SUCCESS


@pytest.mark.asyncio
async def test_apply_shaper_preset_ensures_four_rules(
    mock_client: MockOPNsenseClient,
) -> None:
    tool = ApplyShaperPresetTool(mock_client)
    resp = await tool.execute(
        {"download_mbit": 1000, "upload_mbit": 500, "apply": False}
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    rules = await search_shaper_rules(mock_client)
    descriptions = {(r.get("description") or "").lower() for r in rules}
    for spec in PRESET_RULES:
        assert spec["description"].lower() in descriptions


@pytest.mark.asyncio
async def test_restore_shaper_snapshot_pending_apply(
    mock_client: MockOPNsenseClient,
) -> None:
    add = AddShaperPipeTool(mock_client)
    created = await add.execute(
        {"description": "Snap pipe", "bandwidth": 100, "apply": False}
    )
    snapshot_id = created["snapshot_id"]
    restore = RestoreShaperSnapshotTool(mock_client)
    resp = await restore.execute({"snapshot_id": snapshot_id, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["applied"] is False
    assert resp["structured"]["pending_changes"] is True
    assert resp.get("snapshot_id")


@pytest.mark.asyncio
async def test_mock_add_pipe_preserves_description(mock_client: MockOPNsenseClient) -> None:
    tool = AddShaperPipeTool(mock_client)
    resp = await tool.execute(
        {"description": "Unique mock pipe", "bandwidth": 50, "apply": False}
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    pipes = await search_shaper_pipes(mock_client)
    assert any(p.get("description") == "Unique mock pipe" for p in pipes)


@pytest.mark.asyncio
async def test_restore_shaper_snapshot_fails_on_api_error(
    mock_client: MockOPNsenseClient,
) -> None:
    add = AddShaperPipeTool(mock_client)
    created = await add.execute(
        {"description": "Snap pipe", "bandwidth": 100, "apply": False}
    )
    snapshot_id = created["snapshot_id"]
    original = mock_client._make_request

    async def failing_make_request(
        method: str, endpoint: str, **kwargs: object
    ) -> dict[str, object]:
        if "set_pipe" in endpoint:
            return {"status": "failed", "error": "simulated failure"}
        return await original(method, endpoint, **kwargs)

    mock_client._make_request = failing_make_request  # type: ignore[method-assign]
    restore = RestoreShaperSnapshotTool(mock_client)
    resp = await restore.execute({"snapshot_id": snapshot_id, "apply": False})
    assert resp["status"] == "error"
    assert "simulated failure" in resp["structured"]["error"]


@pytest.mark.asyncio
async def test_add_shaper_pipe_warning_when_reconfigure_fails(
    mock_client: MockOPNsenseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fail_reconfigure(_client: MockOPNsenseClient) -> dict[str, str]:
        return {"status": "failed", "error": "reconfigure failed"}

    monkeypatch.setattr(
        "opnsense_mcp.utils.shaper_mutation.reconfigure_shaper",
        fail_reconfigure,
    )
    tool = AddShaperPipeTool(mock_client)
    resp = await tool.execute(
        {"description": "Warn pipe", "bandwidth": 100, "apply": True}
    )
    assert resp["status"] == TOOL_STATUS_WARNING
    assert resp["structured"]["pending_changes"] is True
