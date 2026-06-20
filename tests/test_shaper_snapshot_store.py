"""Tests for opnsense_mcp/utils/shaper_snapshot_store.py — bucket 4a."""

from __future__ import annotations

import json
import pathlib
import uuid

import pytest

from opnsense_mcp.utils.shaper_snapshot_store import (
    build_restore_plan,
    capture_snapshot,
    clear_snapshots,
    get_snapshot,
    list_snapshots,
)

_FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures" / "shaper"


def _load_fixture(filename: str) -> dict:
    path = _FIXTURES_DIR / filename
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(autouse=True)
def clear_snapshots_fixture() -> None:
    """Ensure snapshots are cleared before and after each test."""
    clear_snapshots()
    yield
    clear_snapshots()


class TestCaptureSnapshot:
    def test_returns_uuid_string(self) -> None:
        settings = _load_fixture("settings_get.json")
        pipes = _load_fixture("search_pipes.json").get("rows", [])
        queues = _load_fixture("search_queues.json").get("rows", [])
        rules = _load_fixture("search_rules.json").get("rows", [])

        sid = capture_snapshot(
            settings_get=settings,
            search_pipes=pipes,
            search_queues=queues,
            search_rules=rules,
        )
        parsed = uuid.UUID(sid)
        assert parsed.version == 4

    def test_stores_full_settings_tree(self) -> None:
        settings = _load_fixture("settings_get.json")
        sid = capture_snapshot(
            settings_get=settings,
            search_pipes=[],
            search_queues=[],
            search_rules=[],
        )
        snap = get_snapshot(sid)
        assert snap is not None
        assert snap["settings_get"] == settings

    def test_stores_search_rows(self) -> None:
        pipes = _load_fixture("search_pipes.json").get("rows", [])
        queues = _load_fixture("search_queues.json").get("rows", [])
        rules = _load_fixture("search_rules.json").get("rows", [])
        sid = capture_snapshot(
            settings_get={},
            search_pipes=pipes,
            search_queues=queues,
            search_rules=rules,
        )
        snap = get_snapshot(sid)
        assert snap is not None
        assert snap["search_pipes"] == pipes
        assert snap["search_queues"] == queues
        assert snap["search_rules"] == rules

    def test_stores_timestamp_and_description(self) -> None:
        custom_ts = "2026-06-20T12:00:00+00:00"
        sid = capture_snapshot(
            settings_get={},
            search_pipes=[],
            search_queues=[],
            search_rules=[],
            timestamp=custom_ts,
            description="Pre-mutation snapshot",
        )
        snap = get_snapshot(sid)
        assert snap is not None
        assert snap["created_at"] == custom_ts
        assert snap["description"] == "Pre-mutation snapshot"

    def test_deep_copy_isolation(self) -> None:
        pipes = [{"uuid": "test-1", "description": "Original"}]
        sid = capture_snapshot(
            settings_get={},
            search_pipes=pipes,
            search_queues=[],
            search_rules=[],
        )
        pipes[0]["description"] = "Modified"
        snap = get_snapshot(sid)
        assert snap is not None
        assert snap["search_pipes"][0]["description"] == "Original"


class TestGetSnapshot:
    def test_returns_none_for_missing_id(self) -> None:
        assert get_snapshot("nonexistent-uuid") is None


class TestListSnapshots:
    def test_empty_returns_empty_list(self) -> None:
        assert list_snapshots() == []

    def test_lists_stored_snapshots(self) -> None:
        s1 = capture_snapshot({}, [], [], [], description="First")
        s2 = capture_snapshot({}, [], [], [], description="Second")
        result = list_snapshots()
        assert len(result) == 2
        ids = {item["snapshot_id"] for item in result}
        assert s1 in ids and s2 in ids


class TestBuildRestorePlan:
    def test_plan_from_fixtures(self) -> None:
        pipes = _load_fixture("search_pipes.json").get("rows", [])
        queues = _load_fixture("search_queues.json").get("rows", [])
        rules = _load_fixture("search_rules.json").get("rows", [])
        settings = _load_fixture("settings_get.json")
        snapshot = {
            "snapshot_id": "snap-full",
            "created_at": "2026-06-20T10:00:00+00:00",
            "description": "Full restore test",
            "search_pipes": pipes,
            "search_queues": queues,
            "search_rules": rules,
            "settings_get": settings,
        }
        plan = build_restore_plan(snapshot)
        assert len(plan["pipes"]) == 2
        assert len(plan["queues"]) == 2
        assert len(plan["rules"]) == 2
        assert plan["settings"] == settings
        assert plan["pipes"][0]["action"] == "set_pipe"


class TestClearSnapshots:
    def test_clears_all_snapshots(self) -> None:
        capture_snapshot({}, [], [], [])
        capture_snapshot({}, [], [], [])
        assert len(list_snapshots()) == 2
        clear_snapshots()
        assert list_snapshots() == []
