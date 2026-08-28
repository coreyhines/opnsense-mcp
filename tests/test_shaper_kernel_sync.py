"""A shaper delete must not report a state the kernel did not reach (#19).

`shaper action=delete_pipe` returned `applied: true, reconfigure_result:
{status: ok}` and the config object was gone, but `ipfw pipe show` still
listed the pipe. `shaper action=statistics`, seconds later, still returned it:

    {'pipe': '10002', 'bw': '10.000 Mbit/s', 'description': '',
     'type': 'pipe', 'id': 10002, 'rules': []}

Config: 2 pipes. Kernel: 3. No ipfw rule referenced 10002, so the orphan was
inert, but one accumulates per delete and `applied: true` actively hid the
divergence.

OPNsense exposes only service/reconfigure, with no flush endpoint, so these
tests cover detecting and reporting the divergence. Removing the orphan needs
`ipfw pipe <n> delete` on the firewall, or a reboot. Note that
`shaper action='apply'` will not do it: that is the same service/reconfigure
call that left the orphan behind.
"""

from __future__ import annotations

from typing import Any

# A live pipe carries the uuid of its config object. The orphan left behind by
# a delete does not: reconfigure removed the config row but not the kernel
# object, so nothing ties the running pipe back to a uuid any more.
LIVE_PIPE = {
    "uuid": "e93038e5-1234-5678-abcd-000000000001",
    "description": "Download pipe",
    "bw": "1.958 Gbit/s",
    "type": "pipe",
    "pipe": "10000",
    "id": 10000,
    "rules": [],
}
ORPHAN_PIPE = {
    "description": "",
    "bw": "10.000 Mbit/s",
    "type": "pipe",
    "pipe": "10002",
    "id": 10002,
    "rules": [],
}
LIVE_CONFIG_ROW = {"uuid": LIVE_PIPE["uuid"], "description": "Download pipe"}


def test_a_pipe_the_kernel_kept_is_reported_as_an_orphan() -> None:
    """The exact divergence observed live."""
    from opnsense_mcp.utils.shaper_mutation import orphaned_kernel_pipes

    orphans = orphaned_kernel_pipes(
        {"status": "ok", "items": [LIVE_PIPE, ORPHAN_PIPE]},
        [LIVE_CONFIG_ROW],
    )

    assert orphans == ["10002"]


def test_a_kernel_matching_the_config_reports_no_orphans() -> None:
    """The check must be quiet when nothing is wrong."""
    from opnsense_mcp.utils.shaper_mutation import orphaned_kernel_pipes

    assert orphaned_kernel_pipes({"items": [LIVE_PIPE]}, [LIVE_CONFIG_ROW]) == []


def test_queues_and_rules_are_not_mistaken_for_orphaned_pipes() -> None:
    """statistics returns more than pipes; only pipes are compared to pipes."""
    from opnsense_mcp.utils.shaper_mutation import orphaned_kernel_pipes

    queue = {"uuid": "other", "type": "queue", "pipe": "10000", "id": 2}

    assert orphaned_kernel_pipes({"items": [LIVE_PIPE, queue]}, [LIVE_CONFIG_ROW]) == []


def test_empty_statistics_reports_no_orphans() -> None:
    """A shaper that is off must not read as wholly divergent."""
    from opnsense_mcp.utils.shaper_mutation import orphaned_kernel_pipes

    assert orphaned_kernel_pipes({"status": "ok", "items": []}, [LIVE_CONFIG_ROW]) == []
    assert orphaned_kernel_pipes({}, []) == []


class _Client:
    """Client stub whose kernel keeps a pipe the config no longer has."""

    def __init__(self, *, orphan: bool) -> None:
        self.orphan = orphan
        self.calls: list[str] = []

    async def _make_request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        self.calls.append(endpoint)
        if "search_pipes" in endpoint:
            return {"rows": [LIVE_CONFIG_ROW], "rowCount": 1}
        if "search_queues" in endpoint or "search_rules" in endpoint:
            return {"rows": [], "rowCount": 0}
        if "service/statistics" in endpoint:
            items = [LIVE_PIPE, ORPHAN_PIPE] if self.orphan else [LIVE_PIPE]
            return {"status": "ok", "items": items}
        return {"status": "ok"}


async def _finish(client: _Client) -> dict[str, Any]:
    from opnsense_mcp.utils.shaper_mutation import finish_mutation

    return await finish_mutation(
        client,
        snapshot_id="snap-1",
        apply=True,
        summary="deleted",
        structured={"uuid": "gone"},
        verify_kernel=True,
    )


def test_finish_mutation_flags_the_divergence_it_used_to_hide() -> None:
    """`applied: true` alone said the tool reached a state it had not."""
    import asyncio

    result = asyncio.run(_finish(_Client(orphan=True)))
    structured = result.get("structured", result)

    assert structured["kernel_in_sync"] is False
    assert structured["orphaned_kernel_pipes"] == ["10002"]
    assert result["status"] == "warning"


def test_a_clean_delete_still_reports_success() -> None:
    """The check must not turn every successful delete into a warning."""
    import asyncio

    result = asyncio.run(_finish(_Client(orphan=False)))
    structured = result.get("structured", result)

    assert structured["kernel_in_sync"] is True
    assert structured["applied"] is True
    assert result["status"] == "success"
    assert "orphaned_kernel_pipes" not in structured


def test_verification_is_skipped_when_nothing_was_applied() -> None:
    """A staged change cannot have diverged, and must not cost two API calls."""
    import asyncio

    from opnsense_mcp.utils.shaper_mutation import finish_mutation

    client = _Client(orphan=True)
    asyncio.run(
        finish_mutation(
            client,
            snapshot_id="snap-1",
            apply=False,
            summary="staged",
            structured={"uuid": "gone"},
            verify_kernel=True,
        )
    )

    assert not any("service/statistics" in call for call in client.calls)


def test_the_hint_does_not_name_the_call_that_left_the_orphan() -> None:
    """`shaper action='apply'` is service/reconfigure, which is the problem.

    An earlier version of this hint offered "a full shaper apply" as the
    remedy. That is the same call whose failure to flush created the orphan,
    so following the hint would have left the pipe in place and looked like
    the detection was wrong.
    """
    import asyncio

    from opnsense_mcp.utils.shaper_mutation import _kernel_sync_fields

    _fields, hints = asyncio.run(_kernel_sync_fields(_Client(orphan=True)))
    hint = " ".join(hints)

    assert "ipfw pipe 10002 delete" in hint
    assert "will not" in hint, "the hint must say reconfigure does not clear it"
