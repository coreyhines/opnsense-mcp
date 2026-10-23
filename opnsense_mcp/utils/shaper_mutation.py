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
from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
)
from opnsense_mcp.utils.shaper_serialize import (
    merge_flat_into_pipe_api_post,
    merge_flat_into_queue_api_post,
    merge_flat_into_rule_api_post,
    serialize_pipe_api_post,
    serialize_queue_api_post,
    serialize_rule_api_post,
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


# Delete order: rules reference queues and pipes, queues reference pipes.
_ORPHAN_ORDER: tuple[tuple[str, str, str], ...] = (
    ("rules", "rule", "search_rules"),
    ("queues", "queue", "search_queues"),
    ("pipes", "pipe", "search_pipes"),
)


def _row_uuids(rows: list[dict[str, Any]]) -> list[str]:
    """Non-empty uuids of *rows*, in row order."""
    return [
        str(row.get("uuid") or "").strip()
        for row in rows
        if str(row.get("uuid") or "").strip()
    ]


async def plan_orphan_removal(
    client: ClientT,
    snapshot: dict[str, Any],
) -> dict[str, list[str]]:
    """Live rule/queue/pipe uuids absent from *snapshot*, keyed by plural kind.

    This is the exact set a confirmed ``remove_orphans`` restore deletes. It
    is computed before the restore runs: objects the restore recreates get
    new uuids that are not in the snapshot either, and computing orphans
    afterwards deleted them again.
    """
    live_pipes, live_queues, live_rules = await load_pipe_queue_rule_rows(client)
    live = {"pipes": live_pipes, "queues": live_queues, "rules": live_rules}
    plan: dict[str, list[str]] = {}
    for kind, _resource, snap_key in _ORPHAN_ORDER:
        keep = set(_row_uuids(list(snapshot.get(snap_key) or [])))
        plan[kind] = [uid for uid in _row_uuids(live[kind]) if uid not in keep]
    return plan


async def remove_orphan_shaper_resources(
    client: ClientT,
    orphans: dict[str, list[str]],
    results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Delete exactly the uuids in *orphans* (from :func:`plan_orphan_removal`).

    Nothing is re-derived from live state here, so a delete cannot reach an
    object the caller did not confirm.
    """
    deleted = results if results is not None else []
    for kind, resource, _snap_key in _ORPHAN_ORDER:
        for uid in orphans.get(kind) or []:
            resp = await _delete_shaper_resource(client, resource, uid)
            _require_api_ok(f"del_{resource}", uid, resp)
            deleted.append({"action": f"del_{resource}", "uuid": uid, "result": resp})
    return deleted


async def _add_shaper_resource(
    client: ClientT,
    resource: str,
    snapshot_uuid: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """POST add_<resource> and return the uuid OPNsense assigned."""
    resp = await client._make_request(
        "POST", f"/trafficshaper/settings/add_{resource}/", json=payload
    )
    _require_api_ok(f"add_{resource}", snapshot_uuid, resp)
    new_uuid = str(resp.get("uuid") or resp.get("id") or "").strip()
    if not new_uuid:
        raise RuntimeError(
            f"add_{resource} for snapshot {resource} {snapshot_uuid} returned no uuid"
        )
    return new_uuid, resp


async def apply_snapshot_restore(
    client: ClientT,
    snapshot: dict[str, Any],
    *,
    orphans: dict[str, list[str]] | None = None,
    results: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Replay *snapshot* and return ``(results, resource_updates)``.

    A snapshot row still present live is replayed through ``set_*``. A row
    absent live (deleted since the snapshot) is recreated through ``add_*``,
    in dependency order pipes, queues, rules. OPNsense assigns the recreated
    object a new uuid, so queue ``pipe`` and rule ``target`` references to
    it are remapped; each ``add_*`` result records ``snapshot_uuid``.

    Restore used to call ``set_*`` only, which cannot bring back a deleted
    object, so the snapshot a delete returned could not undo that delete.

    *orphans* is a confirmed deletion set; it is deleted after the replay.
    *results* collects steps as they complete, so a caller still holds the
    finished steps (including created uuids) when a later step raises.
    """
    if not client:
        raise RuntimeError("No client available")
    results = results if results is not None else []
    plan = build_restore_plan(snapshot)
    pipe_rows = list(snapshot.get("search_pipes") or [])
    queue_rows = list(snapshot.get("search_queues") or [])
    pmap = pipe_description_map(pipe_rows)
    tmap = target_description_map(queue_rows, pipe_rows)
    live_pipes, live_queues, live_rules = await load_pipe_queue_rule_rows(client)
    live_ids = {
        "pipe": set(_row_uuids(live_pipes)),
        "queue": set(_row_uuids(live_queues)),
        "rule": set(_row_uuids(live_rules)),
    }
    uuid_map: dict[str, str] = {}
    resource_updates = 0

    for step in plan["pipes"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        flat = normalize_pipe({**row, "uuid": uid})
        if uid in live_ids["pipe"]:
            gui_resp = await client._make_request(
                "GET", f"/trafficshaper/settings/get_pipe/{uid}"
            )
            payload = merge_flat_into_pipe_api_post(gui_resp.get("pipe") or {}, flat)
            resp = await client._make_request(
                "POST",
                f"/trafficshaper/settings/set_pipe/{uid}",
                json=payload,
            )
            _require_api_ok("set_pipe", uid, resp)
            results.append({"action": "set_pipe", "uuid": uid, "result": resp})
        else:
            flat["uuid"] = ""
            new_uuid, resp = await _add_shaper_resource(
                client, "pipe", uid, serialize_pipe_api_post(flat)
            )
            uuid_map[uid] = new_uuid
            pmap[new_uuid] = pmap.get(uid, new_uuid)
            tmap[new_uuid] = tmap.get(uid, new_uuid)
            results.append(
                {
                    "action": "add_pipe",
                    "uuid": new_uuid,
                    "snapshot_uuid": uid,
                    "result": resp,
                }
            )
        resource_updates += 1

    for step in plan["queues"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        flat = normalize_queue({**row, "uuid": uid})
        pipe_ref = flat.get("pipe_uuid", "")
        flat["pipe_uuid"] = uuid_map.get(pipe_ref, pipe_ref)
        if uid in live_ids["queue"]:
            gui_resp = await client._make_request(
                "GET", f"/trafficshaper/settings/get_queue/{uid}"
            )
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
        else:
            flat["uuid"] = ""
            new_uuid, resp = await _add_shaper_resource(
                client, "queue", uid, serialize_queue_api_post(flat, pmap)
            )
            uuid_map[uid] = new_uuid
            tmap[new_uuid] = tmap.get(uid, new_uuid)
            results.append(
                {
                    "action": "add_queue",
                    "uuid": new_uuid,
                    "snapshot_uuid": uid,
                    "result": resp,
                }
            )
        resource_updates += 1

    for step in plan["rules"]:
        uid = str(step.get("uuid") or "").strip()
        row = step.get("search_row") or {}
        if not uid:
            continue
        flat = normalize_rule({**row, "uuid": uid})
        target_ref = flat.get("target_uuid", "")
        flat["target_uuid"] = uuid_map.get(target_ref, target_ref)
        if uid in live_ids["rule"]:
            gui_resp = await client._make_request(
                "GET", f"/trafficshaper/settings/get_rule/{uid}"
            )
            payload = merge_flat_into_rule_api_post(
                gui_resp.get("rule") or {}, flat, tmap
            )
            resp = await client._make_request(
                "POST",
                f"/trafficshaper/settings/set_rule/{uid}",
                json=payload,
            )
            _require_api_ok("set_rule", uid, resp)
            results.append({"action": "set_rule", "uuid": uid, "result": resp})
        else:
            flat["uuid"] = ""
            new_uuid, resp = await _add_shaper_resource(
                client, "rule", uid, serialize_rule_api_post(flat, tmap)
            )
            uuid_map[uid] = new_uuid
            results.append(
                {
                    "action": "add_rule",
                    "uuid": new_uuid,
                    "snapshot_uuid": uid,
                    "result": resp,
                }
            )
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

    if orphans:
        await remove_orphan_shaper_resources(client, orphans, results)

    return results, resource_updates


async def reconfigure_shaper(client: ClientT) -> dict[str, Any]:
    """POST service/reconfigure, raising :class:`ApplyError` unless it applied.

    The raw POST returned whatever document arrived at HTTP 200 and left it
    to the callers to read, and a configd refusal has exactly that shape, so
    a refused reload was indistinguishable from a completed one.
    ``run_apply`` reads the ``status`` the service answers with. The
    ``error``-key check the shaper already made stays on top of it, so
    nothing that used to be refused now passes: a document carrying both a
    healthy status and an error is still not an applied change.
    """
    if not client:
        raise RuntimeError("No client available")
    result = await run_apply(client, "/trafficshaper/service/reconfigure")
    ok, detail = shaper_api_result_ok(result)
    if not ok:
        raise ApplyError(
            "/trafficshaper/service/reconfigure answered "
            f"{detail or result!r} rather than success"
        )
    return result


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

    A reconfigure that does not apply is reported, not raised: the change
    stays staged, ``applied`` is false and ``apply_error`` carries the
    reason, so the caller can tell a made change from a live one.
    """
    reconfigure_result: dict[str, Any] | None = None
    apply_error = ""
    if apply:
        try:
            reconfigure_result = await reconfigure_shaper(client)
        except ApplyError as exc:
            # The writes this finishes already happened. Letting the apply
            # failure escape would report a finished mutation as a failed
            # one — for a delete, that invites a retry against a record
            # that is already gone.
            logger.warning("Shaper change staged but not applied: %s", exc)
            apply_error = str(exc)
    merged = {**structured, **pending_apply_fields(apply, reconfigure_result)}
    if apply_error:
        merged["apply_error"] = apply_error
    final_status = status
    if apply and merged.get("pending_changes") and not merged.get("applied"):
        final_status = TOOL_STATUS_WARNING

    all_hints = list(hints or [])
    if verify_kernel and merged.get("applied"):
        sync_fields, sync_hints = await _kernel_sync_fields(client)
        merged.update(sync_fields)
        all_hints.extend(sync_hints)
        # Reconfigure accepted the config, but applied means the runtime
        # matches. Orphans or an unverifiable kernel leave applied false.
        if sync_fields.get("kernel_in_sync") is not True:
            merged["config_applied"] = True
            merged["applied"] = False
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
