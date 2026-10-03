"""Snapshot restore must undo a delete, and its own deletes must be gated.

#76: restore only called ``set_*``, so the snapshot a delete returned could
not bring back the object that delete removed.
#77: ``remove_orphans=true`` deleted every live object missing from the
snapshot with no preview and no confirmation token.
#78: those deletes skipped the kernel-sync check the single deletes run, so a
restore reported ``applied: true`` while dummynet still held the pipe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opnsense_mcp.tools.shaper_pipes import AddShaperPipeTool, DeleteShaperPipeTool
from opnsense_mcp.tools.shaper_queues import DeleteShaperQueueTool
from opnsense_mcp.tools.shaper_rules import DeleteShaperRuleTool
from opnsense_mcp.tools.shaper_settings import (
    search_shaper_pipes,
    search_shaper_queues,
    search_shaper_rules,
)
from opnsense_mcp.tools.shaper_snapshot import RestoreShaperSnapshotTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.shaper_mutation import capture_pre_mutation_snapshot
from opnsense_mcp.utils.shaper_snapshot_store import clear_snapshots
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_CONFIRMATION_REQUIRED,
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
)

DOWNLOAD_PIPE = "e93038e5-5422-4557-b0f2-082c4cb0ddf4"
DOWNLOAD_QUEUE = "84c6c7d8-09a6-40d6-b2b7-2c1485c9d6e3"
DOWNLOAD_RULE = "690c995b-bebd-4a8d-a4c9-df6fd0dc61ea"

DELETE_TOOLS = {
    "pipe": (DeleteShaperPipeTool, DOWNLOAD_PIPE, search_shaper_pipes),
    "queue": (DeleteShaperQueueTool, DOWNLOAD_QUEUE, search_shaper_queues),
    "rule": (DeleteShaperRuleTool, DOWNLOAD_RULE, search_shaper_rules),
}


@pytest.fixture
def mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


@pytest.fixture(autouse=True)
def reset_snapshots() -> None:
    clear_snapshots()


async def _delete(client: MockOPNsenseClient, resource: str, uuid: str) -> str:
    """Run a confirmed delete and return its pre-delete snapshot id."""
    tool = DELETE_TOOLS[resource][0](client)
    first = await tool.execute({"uuid": uuid})
    token = first["structured"]["confirm_token"]
    resp = await tool.execute({"uuid": uuid, "confirm": token, "apply": False})
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["snapshot_id"]
    return resp["snapshot_id"]


async def _rows(client: MockOPNsenseClient) -> dict[str, list[dict[str, Any]]]:
    return {
        "pipe": await search_shaper_pipes(client),
        "queue": await search_shaper_queues(client),
        "rule": await search_shaper_rules(client),
    }


# --- #76: rollback recreates deleted objects --------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("resource", ["pipe", "queue", "rule"])
async def test_restore_recreates_an_object_deleted_after_the_snapshot(
    mock_client: MockOPNsenseClient, resource: str
) -> None:
    _tool, uuid, search = DELETE_TOOLS[resource]
    before = next(r for r in await search(mock_client) if r["uuid"] == uuid)
    snapshot_id = await _delete(mock_client, resource, uuid)
    assert all(r["uuid"] != uuid for r in await search(mock_client))

    resp = await RestoreShaperSnapshotTool(mock_client).execute(
        {"snapshot_id": snapshot_id, "apply": False}
    )

    assert resp["status"] == TOOL_STATUS_SUCCESS
    recreated = resp["structured"]["recreated"]
    assert [(r["resource"], r["snapshot_uuid"]) for r in recreated] == [
        (resource, uuid)
    ]
    new_uuid = recreated[0]["uuid"]
    assert new_uuid
    assert new_uuid != uuid
    after = next(r for r in await search(mock_client) if r["uuid"] == new_uuid)
    assert after["description"] == before["description"]
    assert after["description"]
    if resource == "pipe":
        assert str(after["bandwidth"]) == str(before["bandwidth"])
    if resource == "queue":
        assert after["pipe_uuid"] == before["pipe_uuid"] == DOWNLOAD_PIPE
    if resource == "rule":
        assert after["target_uuid"] == before["target_uuid"] == DOWNLOAD_QUEUE


@pytest.mark.asyncio
async def test_restore_remaps_references_to_recreated_objects(
    mock_client: MockOPNsenseClient,
) -> None:
    """Rule -> queue -> pipe all deleted: each recreated reference must point
    at the uuid OPNsense assigned, not the one the snapshot recorded."""
    snapshot_id = await capture_pre_mutation_snapshot(mock_client)
    await _delete(mock_client, "rule", DOWNLOAD_RULE)
    await _delete(mock_client, "queue", DOWNLOAD_QUEUE)
    await _delete(mock_client, "pipe", DOWNLOAD_PIPE)

    resp = await RestoreShaperSnapshotTool(mock_client).execute(
        {"snapshot_id": snapshot_id, "apply": False}
    )

    assert resp["status"] == TOOL_STATUS_SUCCESS
    new = {r["snapshot_uuid"]: r["uuid"] for r in resp["structured"]["recreated"]}
    assert set(new) == {DOWNLOAD_PIPE, DOWNLOAD_QUEUE, DOWNLOAD_RULE}
    rows = await _rows(mock_client)
    queue = next(q for q in rows["queue"] if q["uuid"] == new[DOWNLOAD_QUEUE])
    rule = next(r for r in rows["rule"] if r["uuid"] == new[DOWNLOAD_RULE])
    assert queue["pipe_uuid"] == new[DOWNLOAD_PIPE]
    assert rule["target_uuid"] == new[DOWNLOAD_QUEUE]
    # Dependency order: a queue cannot be added before the pipe it names.
    actions = [r["action"] for r in resp["structured"]["results"]]
    assert actions.index("add_pipe") < actions.index("add_queue")
    assert actions.index("add_queue") < actions.index("add_rule")


@pytest.mark.asyncio
async def test_restore_of_a_live_object_updates_it_rather_than_duplicating(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id = await capture_pre_mutation_snapshot(mock_client)
    before = await _rows(mock_client)

    resp = await RestoreShaperSnapshotTool(mock_client).execute(
        {"snapshot_id": snapshot_id, "apply": False}
    )

    assert resp["structured"]["recreated"] == []
    after = await _rows(mock_client)
    for kind in ("pipe", "queue", "rule"):
        assert sorted(r["uuid"] for r in after[kind]) == sorted(
            r["uuid"] for r in before[kind]
        )


# --- #77: remove_orphans needs a scoped confirmation --------------------------


async def _snapshot_then_add_orphan(client: MockOPNsenseClient) -> tuple[str, str]:
    snapshot_id = await capture_pre_mutation_snapshot(client)
    added = await AddShaperPipeTool(client).execute(
        {"description": "Orphan pipe", "bandwidth": 50, "apply": False}
    )
    return snapshot_id, added["structured"]["pipe"]["uuid"]


@pytest.mark.asyncio
async def test_remove_orphans_without_confirm_deletes_nothing_and_plans(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id, orphan = await _snapshot_then_add_orphan(mock_client)

    resp = await RestoreShaperSnapshotTool(mock_client).execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )

    assert resp["status"] == TOOL_STATUS_CONFIRMATION_REQUIRED
    assert resp["structured"]["deletion_plan"] == {
        "rules": [],
        "queues": [],
        "pipes": [orphan],
    }
    assert resp["structured"]["confirm_token"]
    assert resp["structured"]["applied"] is False
    assert any(p["uuid"] == orphan for p in await search_shaper_pipes(mock_client))


@pytest.mark.asyncio
async def test_remove_orphans_with_confirm_deletes_exactly_the_plan(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id, orphan = await _snapshot_then_add_orphan(mock_client)
    tool = RestoreShaperSnapshotTool(mock_client)
    plan = await tool.execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )

    resp = await tool.execute(
        {
            "snapshot_id": snapshot_id,
            "remove_orphans": True,
            "apply": False,
            "confirm": plan["structured"]["confirm_token"],
        }
    )

    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["orphans_removed"] == 1
    uuids = {p["uuid"] for p in await search_shaper_pipes(mock_client)}
    assert orphan not in uuids
    assert DOWNLOAD_PIPE in uuids


@pytest.mark.asyncio
async def test_remove_orphans_aborts_when_the_live_set_changed(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id, orphan = await _snapshot_then_add_orphan(mock_client)
    tool = RestoreShaperSnapshotTool(mock_client)
    plan = await tool.execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )
    late = await AddShaperPipeTool(mock_client).execute(
        {"description": "Arrived after the plan", "bandwidth": 5, "apply": False}
    )
    late_uuid = late["structured"]["pipe"]["uuid"]

    resp = await tool.execute(
        {
            "snapshot_id": snapshot_id,
            "remove_orphans": True,
            "apply": False,
            "confirm": plan["structured"]["confirm_token"],
        }
    )

    assert resp["status"] == TOOL_STATUS_ERROR
    assert resp["structured"]["deletion_set_changed"] is True
    assert resp["structured"]["applied"] is False
    uuids = {p["uuid"] for p in await search_shaper_pipes(mock_client)}
    assert {orphan, late_uuid} <= uuids


@pytest.mark.asyncio
async def test_remove_orphans_token_is_bound_to_its_snapshot(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id, orphan = await _snapshot_then_add_orphan(mock_client)
    tool = RestoreShaperSnapshotTool(mock_client)
    other_id = await capture_pre_mutation_snapshot(mock_client)
    # A token for snapshot B must not confirm a restore of snapshot A.
    await AddShaperPipeTool(mock_client).execute(
        {"description": "Second orphan", "bandwidth": 5, "apply": False}
    )
    other_plan = await tool.execute(
        {"snapshot_id": other_id, "remove_orphans": True, "apply": False}
    )
    assert other_plan["status"] == TOOL_STATUS_CONFIRMATION_REQUIRED

    resp = await tool.execute(
        {
            "snapshot_id": snapshot_id,
            "remove_orphans": True,
            "apply": False,
            "confirm": other_plan["structured"]["confirm_token"],
        }
    )

    assert resp["status"] == TOOL_STATUS_ERROR
    assert resp["structured"]["applied"] is False
    assert any(p["uuid"] == orphan for p in await search_shaper_pipes(mock_client))


@pytest.mark.asyncio
async def test_remove_orphans_token_is_single_use(
    mock_client: MockOPNsenseClient,
) -> None:
    snapshot_id, _orphan = await _snapshot_then_add_orphan(mock_client)
    tool = RestoreShaperSnapshotTool(mock_client)
    plan = await tool.execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )
    token = plan["structured"]["confirm_token"]
    args = {
        "snapshot_id": snapshot_id,
        "remove_orphans": True,
        "apply": False,
        "confirm": token,
    }
    assert (await tool.execute(args))["status"] == TOOL_STATUS_SUCCESS
    await AddShaperPipeTool(mock_client).execute(
        {"description": "Orphan pipe", "bandwidth": 50, "apply": False}
    )

    resp = await tool.execute(args)

    assert resp["status"] == TOOL_STATUS_ERROR
    assert resp["structured"]["deletion_set_changed"] is False


@pytest.mark.asyncio
async def test_remove_orphans_does_not_delete_what_the_restore_recreated(
    mock_client: MockOPNsenseClient,
) -> None:
    """Recreated objects carry uuids absent from the snapshot; an orphan set
    computed after the replay deleted them again."""
    snapshot_id = await _delete(mock_client, "pipe", DOWNLOAD_PIPE)
    tool = RestoreShaperSnapshotTool(mock_client)
    plan = await tool.execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )
    # Nothing live is missing from the snapshot, so nothing needs confirming.
    assert plan["status"] == TOOL_STATUS_SUCCESS

    recreated = plan["structured"]["recreated"][0]["uuid"]
    assert plan["structured"]["orphans_removed"] == 0
    assert any(p["uuid"] == recreated for p in await search_shaper_pipes(mock_client))


# --- #78: an orphan-removing restore is checked against the kernel -----------


def _kernel_keeps_orphan(client: MockOPNsenseClient) -> None:
    """Make statistics report the live config plus one pipe with no uuid."""
    original = client._make_request

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "service/statistics" in endpoint:
            pipes = await search_shaper_pipes(client)
            items = [
                {"type": "pipe", "uuid": p["uuid"], "pipe": str(10000 + i)}
                for i, p in enumerate(pipes)
            ]
            items.append({"type": "pipe", "pipe": "10099", "id": 10099})
            return {"status": "ok", "items": items}
        return await original(method, endpoint, **kwargs)

    client._make_request = make_request  # type: ignore[method-assign]


async def _confirmed_orphan_restore(client: MockOPNsenseClient) -> dict[str, Any]:
    snapshot_id, _orphan = await _snapshot_then_add_orphan(client)
    tool = RestoreShaperSnapshotTool(client)
    plan = await tool.execute(
        {"snapshot_id": snapshot_id, "remove_orphans": True, "apply": False}
    )
    return await tool.execute(
        {
            "snapshot_id": snapshot_id,
            "remove_orphans": True,
            "apply": True,
            "confirm": plan["structured"]["confirm_token"],
        }
    )


@pytest.mark.asyncio
async def test_orphan_restore_is_not_applied_while_the_kernel_keeps_the_pipe(
    mock_client: MockOPNsenseClient,
) -> None:
    _kernel_keeps_orphan(mock_client)

    resp = await _confirmed_orphan_restore(mock_client)

    assert resp["status"] == TOOL_STATUS_WARNING
    assert resp["structured"]["applied"] is False
    assert resp["structured"]["config_applied"] is True
    assert resp["structured"]["kernel_in_sync"] is False
    assert resp["structured"]["orphaned_kernel_pipes"] == ["10099"]


@pytest.mark.asyncio
async def test_orphan_restore_is_applied_when_the_kernel_matches(
    mock_client: MockOPNsenseClient,
) -> None:
    original = mock_client._make_request

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "service/statistics" in endpoint:
            pipes = await search_shaper_pipes(mock_client)
            return {
                "status": "ok",
                "items": [{"type": "pipe", "uuid": p["uuid"]} for p in pipes],
            }
        return await original(method, endpoint, **kwargs)

    mock_client._make_request = make_request  # type: ignore[method-assign]

    resp = await _confirmed_orphan_restore(mock_client)

    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["structured"]["applied"] is True
    assert resp["structured"]["kernel_in_sync"] is True
