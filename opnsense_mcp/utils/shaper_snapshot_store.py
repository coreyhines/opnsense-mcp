"""In-process snapshot store for traffic-shaper session scoping (bucket 4a).

.. note::
    Snapshots are stored **in-memory only** (Python dict keyed by UUID).
    They are NOT persisted to disk and DO NOT survive a server restart.
    This is acceptable for the SSE multi-tenant deployment model where
    each client session maps to its own Python worker process.  Cross-session
    rollback is explicitly out of scope for v1.

APIs
----
* ``capture_snapshot(settings_get, search_pipes, search_queues, search_rules,
                      timestamp, description)`` -- store a full shaper snapshot
* ``get_snapshot(snapshot_id)`` -- retrieve by id or None
* ``list_snapshots()`` -- list all snapshots with id/created_at/description
* ``build_restore_plan(snapshot)`` -- structured dict for bucket-4h tool
* ``clear_snapshots()`` -- destroy all snapshots (test teardown helper)
"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any

_SNAPSHOT_STORE: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def capture_snapshot(
    settings_get: dict[str, Any],
    search_pipes: list[dict[str, Any]],
    search_queues: list[dict[str, Any]],
    search_rules: list[dict[str, Any]],
    timestamp: str | None = None,
    description: str = "",
) -> str:
    """Capture a full shaper snapshot and return its unique id."""
    snapshot_id = str(uuid.uuid4())
    _SNAPSHOT_STORE[snapshot_id] = {
        "snapshot_id": snapshot_id,
        "created_at": timestamp or _now_iso(),
        "description": description,
        "settings_get": copy.deepcopy(settings_get),
        "search_pipes": copy.deepcopy(search_pipes),
        "search_queues": copy.deepcopy(search_queues),
        "search_rules": copy.deepcopy(search_rules),
    }
    return snapshot_id


def get_snapshot(snapshot_id: str) -> dict[str, Any] | None:
    """Return a deep copy of the stored snapshot blob, or **None**."""
    snap = _SNAPSHOT_STORE.get(snapshot_id)
    return copy.deepcopy(snap) if snap is not None else None


def list_snapshots() -> list[dict[str, str]]:
    """Return a summary list of all stored snapshots."""
    return [
        {
            "snapshot_id": sid,
            "created_at": snap["created_at"],
            "description": snap.get("description", ""),
        }
        for sid, snap in _SNAPSHOT_STORE.items()
    ]


def build_restore_plan(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build a structured restore plan from a snapshot blob (no API I/O)."""
    pipes = []
    for row in snapshot.get("search_pipes", []):
        uuid_val = row.get("uuid", "")
        if uuid_val:
            pipes.append(
                {
                    "action": "set_pipe",
                    "uuid": uuid_val,
                    "flat_data": dict(row),
                }
            )

    queues = []
    for row in snapshot.get("search_queues", []):
        uuid_val = row.get("uuid", "")
        if uuid_val:
            queues.append(
                {
                    "action": "set_queue",
                    "uuid": uuid_val,
                    "flat_data": dict(row),
                }
            )

    rules = []
    for row in snapshot.get("search_rules", []):
        uuid_val = row.get("uuid", "")
        if uuid_val:
            rules.append(
                {
                    "action": "set_rule",
                    "uuid": uuid_val,
                    "flat_data": dict(row),
                }
            )

    return {
        "snapshot_id": snapshot.get("snapshot_id", ""),
        "created_at": snapshot.get("created_at", ""),
        "description": snapshot.get("description", ""),
        "pipes": pipes,
        "queues": queues,
        "rules": rules,
        "settings": snapshot.get("settings_get", {}),
    }


def clear_snapshots() -> None:
    """Remove all stored snapshots. Intended for test teardown."""
    _SNAPSHOT_STORE.clear()
