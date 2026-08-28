"""Shared async mutation helpers for traffic shaper write MCP tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import (
    fetch_shaper_search_rows,
    fetch_shaper_settings_raw,
    search_shaper_pipes,
    search_shaper_queues,
    search_shaper_rules,
)
from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
)
from opnsense_mcp.utils.shaper_serialize import (
    merge_flat_into_pipe_api_post,
    merge_flat_into_queue_api_post,
    merge_flat_into_rule_api_post,
)
from opnsense_mcp.utils.shaper_snapshot_store import (
    build_restore_plan,
    capture_snapshot,
)
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS, TOOL_STATUS_WARNING
from opnsense_mcp.utils.shaper_write_helpers import (
    build_mutation_response,
    pending_apply_fields,
    shaper_api_result_ok,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient"


async def _search_rows(client: ClientT, path: str) -> list[dict[str, Any]]:
    """POST a shaper search_* endpoint and return all flat rows."""
    if not client:
        return []
    return await fetch_shaper_search_rows(client, path, fetch_all=True)


async def capture_pre_mutation_snapshot(
    client: ClientT,
    *,
    description: str = "",
) -> str:
    """Capture settings/get + search rows before a mutation."""
    settings_raw = await fetch_shaper_settings_raw(client)
    pipes = await _search_rows(client, "/trafficshaper/settings/search_pipes")
    queues = await _search_rows(client, "/trafficshaper/settings/search_queues")
    rules = await _search_rows(client, "/trafficshaper/settings/search_rules")
    return capture_snapshot(
        settings_get=settings_raw,
        search_pipes=pipes,
        search_queues=queues,
        search_rules=rules,
        description=description,
    )


async def mutation_snapshot_for_tool(
    client: ClientT,
    params: dict[str, Any],
    *,
    description: str,
) -> str:
    """Resolve snapshot id for a write tool (preset can pass ``mutation_snapshot_id``)."""
    override = str(params.get("mutation_snapshot_id") or "").strip()
    if override:
        return override
    if params.get("capture_snapshot") is False:
        return ""
    return await capture_pre_mutation_snapshot(client, description=description)


def _require_api_ok(action: str, uid: str, resp: dict[str, Any]) -> None:
    ok, detail = shaper_api_result_ok(resp)
    if not ok:
        msg = f"{action} {uid} failed"
        if detail:
            msg = f"{msg}: {detail}"
        raise RuntimeError(msg)


async def _delete_shaper_resource(
    client: ClientT,
    resource: str,
    uuid: str,
) -> dict[str, Any]:
    """POST del_pipe/del_queue/del_rule without MCP confirm tokens (internal restore)."""
    if not client:
        raise RuntimeError("No client available")
    action = {"pipe": "del_pipe", "queue": "del_queue", "rule": "del_rule"}[resource]
    return await client._make_request(
        "POST",
        f"/trafficshaper/settings/{action}/{uuid}",
    )


async def remove_orphan_shaper_resources(
    client: ClientT,
    snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    """Delete live pipes/queues/rules whose UUID is not present in *snapshot*."""
    snap_rule_ids = {
        str(row.get("uuid") or "").strip()
        for row in snapshot.get("search_rules") or []
        if row.get("uuid")
    }
    snap_queue_ids = {
        str(row.get("uuid") or "").strip()
        for row in snapshot.get("search_queues") or []
        if row.get("uuid")
    }
    snap_pipe_ids = {
        str(row.get("uuid") or "").strip()
        for row in snapshot.get("search_pipes") or []
        if row.get("uuid")
    }
    live_pipes, live_queues, live_rules = await load_pipe_queue_rule_rows(client)
    deleted: list[dict[str, Any]] = []
    for row in live_rules:
        uid = str(row.get("uuid") or "").strip()
        if uid and uid not in snap_rule_ids:
            resp = await _delete_shaper_resource(client, "rule", uid)
            _require_api_ok("del_rule", uid, resp)
            deleted.append({"action": "del_rule", "uuid": uid, "result": resp})
    for row in live_queues:
        uid = str(row.get("uuid") or "").strip()
        if uid and uid not in snap_queue_ids:
            resp = await _delete_shaper_resource(client, "queue", uid)
            _require_api_ok("del_queue", uid, resp)
            deleted.append({"action": "del_queue", "uuid": uid, "result": resp})
    for row in live_pipes:
        uid = str(row.get("uuid") or "").strip()
        if uid and uid not in snap_pipe_ids:
            resp = await _delete_shaper_resource(client, "pipe", uid)
            _require_api_ok("del_pipe", uid, resp)
            deleted.append({"action": "del_pipe", "uuid": uid, "result": resp})
    return deleted


async def apply_snapshot_restore(
    client: ClientT,
    snapshot: dict[str, Any],
    *,
    remove_orphans: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Replay *snapshot* via get+normalize+merge set endpoints."""
    if not client:
        raise RuntimeError("No client available")
    plan = build_restore_plan(snapshot)
    pipe_rows = list(snapshot.get("search_pipes") or [])
    queue_rows = list(snapshot.get("search_queues") or [])
    pmap = pipe_description_map(pipe_rows)
    tmap = target_description_map(queue_rows, pipe_rows)
    results: list[dict[str, Any]] = []
    resource_updates = 0

    for step in plan["pipes"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        gui_resp = await client._make_request(
            "GET", f"/trafficshaper/settings/get_pipe/{uid}"
        )
        flat = normalize_pipe({**row, "uuid": uid})
        payload = merge_flat_into_pipe_api_post(gui_resp.get("pipe") or {}, flat)
        resp = await client._make_request(
            "POST",
            f"/trafficshaper/settings/set_pipe/{uid}",
            json=payload,
        )
        _require_api_ok("set_pipe", uid, resp)
        results.append({"action": "set_pipe", "uuid": uid, "result": resp})
        resource_updates += 1

    for step in plan["queues"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        gui_resp = await client._make_request(
            "GET", f"/trafficshaper/settings/get_queue/{uid}"
        )
        flat = normalize_queue({**row, "uuid": uid})
        payload = merge_flat_into_queue_api_post(
            gui_resp.get("queue") or {}, flat, pmap
        )
        resp = await client._make_request(
            "POST",
            f"/trafficshaper/settings/set_queue/{uid}",
            json=payload,
        )
        _require_api_ok("set_queue", uid, resp)
        results.append({"action": "set_queue", "uuid": uid, "result": resp})
        resource_updates += 1

    for step in plan["rules"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        gui_resp = await client._make_request(
            "GET", f"/trafficshaper/settings/get_rule/{uid}"
        )
        flat = normalize_rule({**row, "uuid": uid})
        payload = merge_flat_into_rule_api_post(gui_resp.get("rule") or {}, flat, tmap)
        resp = await client._make_request(
            "POST",
            f"/trafficshaper/settings/set_rule/{uid}",
            json=payload,
        )
        _require_api_ok("set_rule", uid, resp)
        results.append({"action": "set_rule", "uuid": uid, "result": resp})
        resource_updates += 1

    settings_raw = plan.get("settings")
    if isinstance(settings_raw, dict) and settings_raw:
        settings_resp = await client._make_request(
            "POST",
            "/trafficshaper/settings/set",
            json=settings_raw,
        )
        _require_api_ok("set_settings", "global", settings_resp)
        results.append({"action": "set_settings", "result": settings_resp})

    if remove_orphans:
        orphan_results = await remove_orphan_shaper_resources(client, snapshot)
        results.extend(orphan_results)

    return results, resource_updates


async def reconfigure_shaper(client: ClientT) -> dict[str, Any]:
    """POST service/reconfigure."""
    if not client:
        raise RuntimeError("No client available")
    return await client._make_request(
        "POST", "/trafficshaper/service/reconfigure", call_class="apply"
    )


def pipe_description_map(pipes: list[dict[str, Any]]) -> dict[str, str]:
    """Map pipe uuid -> description for queue/rule serialize enums."""
    return {
        str(row.get("uuid", "")): str(row.get("description", row.get("uuid", "")))
        for row in pipes
        if row.get("uuid")
    }


def target_description_map(
    queues: list[dict[str, Any]],
    pipes: list[dict[str, Any]],
) -> dict[str, str]:
    """Map target uuid -> label for rule serialize enums."""
    result = pipe_description_map(pipes)
    for row in queues:
        uid = str(row.get("uuid", ""))
        if uid:
            result[uid] = str(row.get("description", uid))
    return result


def orphaned_kernel_pipes(
    statistics: dict[str, Any],
    config_pipes: list[dict[str, Any]],
) -> list[str]:
    """Kernel pipe numbers the running dummynet holds but the config does not.

    `service/reconfigure` removes the config object without flushing the
    dummynet pipe, so a delete leaves an inert orphan behind and one
    accumulates per delete. Reporting `applied: true` alone hid that.

    A live pipe in `service/statistics` carries the uuid of its config row.
    The orphan does not: the row it pointed at is gone, so nothing ties the
    running pipe back to a uuid. That absence is what identifies it.
    """
    known = {
        str(row.get("uuid", "")) for row in config_pipes if str(row.get("uuid", ""))
    }
    orphans: set[str] = set()
    for item in statistics.get("items") or []:
        if not isinstance(item, dict) or str(item.get("type", "")) != "pipe":
            continue
        uuid = str(item.get("uuid") or "")
        if uuid and uuid in known:
            continue
        number = str(item.get("pipe") or item.get("id") or "")
        if number:
            orphans.add(number)
    return sorted(orphans)


async def _kernel_sync_fields(client: ClientT) -> tuple[dict[str, Any], list[str]]:
    """Compare the running shaper against the config after an apply.

    Returns the structured fields and any hints. A failure to check is not a
    failure of the mutation, so it reports that it could not verify rather
    than claiming either state.
    """
    try:
        statistics = await client._make_request(
            "GET", "/trafficshaper/service/statistics"
        )
        pipes = await _search_rows(client, "/trafficshaper/settings/search_pipes")
    except Exception:  # noqa: BLE001
        logger.exception("Could not verify shaper kernel state after apply")
        return {"kernel_in_sync": None}, [
            "Could not read the running shaper to verify the apply."
        ]

    orphans = orphaned_kernel_pipes(
        statistics if isinstance(statistics, dict) else {}, pipes
    )
    if not orphans:
        return {"kernel_in_sync": True}, []

    return (
        {"kernel_in_sync": False, "orphaned_kernel_pipes": orphans},
        [
            f"The config applied, but the running dummynet still holds "
            f"pipe(s) {', '.join(orphans)}. Removing the config row does not "
            f"flush the kernel object, and `shaper action='apply'` will not "
            f"clear it either: that is the same service/reconfigure call that "
            f"left it behind. Remove it on the firewall with "
            f"`ipfw pipe {orphans[0]} delete` (repeat per pipe, then confirm "
            f"with `ipfw pipe show`). A reboot also clears it. The orphan is "
            f"inert meanwhile: no ipfw rule references it."
        ],
    )


async def finish_mutation(
    client: ClientT,
    *,
    snapshot_id: str,
    apply: bool,
    summary: str,
    structured: dict[str, Any],
    hints: list[str] | None = None,
    status: str = "success",
    verify_kernel: bool = False,
) -> dict[str, Any]:
    """Apply reconfigure when requested and return standard tool envelope.

    With ``verify_kernel``, an applied change is checked against the running
    shaper before it is reported as done. A delete used to report
    ``applied: true`` while the kernel still held the pipe.
    """
    reconfigure_result: dict[str, Any] | None = None
    if apply:
        reconfigure_result = await reconfigure_shaper(client)
    merged = {**structured, **pending_apply_fields(apply, reconfigure_result)}
    final_status = status
    if apply and merged.get("pending_changes") and not merged.get("applied"):
        final_status = TOOL_STATUS_WARNING

    all_hints = list(hints or [])
    if verify_kernel and merged.get("applied"):
        sync_fields, sync_hints = await _kernel_sync_fields(client)
        merged.update(sync_fields)
        all_hints.extend(sync_hints)
        if sync_fields.get("kernel_in_sync") is False:
            final_status = TOOL_STATUS_WARNING

    return build_mutation_response(
        merged,
        summary,
        snapshot_id=snapshot_id,
        hints=all_hints or None,
        status=final_status,
    )


async def load_pipe_queue_rule_rows(
    client: ClientT,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch raw search rows for pipes, queues, and rules."""
    pipes = await _search_rows(client, "/trafficshaper/settings/search_pipes")
    queues = await _search_rows(client, "/trafficshaper/settings/search_queues")
    rules = await _search_rows(client, "/trafficshaper/settings/search_rules")
    return pipes, queues, rules
