"""Wave 2: the write landed, the apply did not, and the caller was told nothing.

Every `apply=True` path ran the reconfigure inside the same `try` as the write,
so an apply-phase failure was caught by the write's handler and reported as
though the write itself had failed. For a delete that is actively wrong: the
record is gone and the caller is told it is not.

Separately, `reconfigure` answers with a `status` document and nothing looked at
it. The client only raises on `result == "failed"`, so a configd failure at
HTTP 200 was invisible — and the success notes then told the operator to go and
reconfigure, which the tool had just tried and failed to do.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import MkBgpNeighborTool, RmBgpNeighborTool
from opnsense_mcp.tools.ipv6_stack import MkLoopbackTool
from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.apply import ApplyError, run_apply


def _client(
    responses: dict[str, Any] | None = None,
) -> tuple[OPNsenseClient, list[str]]:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)

    table = responses or {}
    calls: list[str] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append(endpoint)
        for key, value in table.items():
            if key in endpoint:
                if isinstance(value, Exception):
                    raise value
                return value
        return {"result": "saved", "uuid": "new-uuid"}

    client._make_request = AsyncMock(side_effect=fake)
    return client, calls


# --- the helper -----------------------------------------------------------


def test_run_apply_rejects_a_failed_status() -> None:
    """reconfigure returns {"status": ...}; the client only raises on result."""
    import asyncio

    client, _ = _client({"reconfigure": {"status": "failed"}})

    with pytest.raises(ApplyError, match="failed"):
        asyncio.run(run_apply(client, "/api/x/service/reconfigure"))


def test_run_apply_accepts_the_shapes_the_api_actually_sends() -> None:
    import asyncio

    for payload in ({"status": "ok"}, {"status": "OK\n\n"}, {"status": "running"}):
        client, _ = _client({"reconfigure": payload})
        asyncio.run(run_apply(client, "/api/x/service/reconfigure"))


def test_run_apply_reports_a_transport_failure_as_an_apply_failure() -> None:
    import asyncio

    client, _ = _client({"reconfigure": TimeoutError("read timed out")})

    with pytest.raises(ApplyError, match="timed out"):
        asyncio.run(run_apply(client, "/api/x/service/reconfigure"))


# --- writes that succeed while the apply fails ----------------------------


@pytest.mark.asyncio
async def test_a_failed_apply_does_not_report_the_create_as_failed() -> None:
    client, calls = _client(
        {"searchNeighbor": {"rows": []}, "reconfigure": {"status": "failed"}}
    )

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009", "apply": True}
    )

    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert result["apply_error"]
    assert any("addNeighbor" in c for c in calls)


@pytest.mark.asyncio
async def test_a_failed_apply_does_not_report_the_delete_as_failed() -> None:
    """Worst case of the pattern: the peer is gone and the caller is told it is not."""
    client, calls = _client(
        {"delNeighbor": {"result": "deleted"}, "reconfigure": {"status": "failed"}}
    )
    tool = RmBgpNeighborTool(client)

    challenge = await tool.execute({"uuid": "nbr-1"})
    result = await tool.execute(
        {"uuid": "nbr-1", "confirm": challenge["confirm_token"], "apply": True}
    )

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is False
    assert any("delNeighbor" in c for c in calls)


@pytest.mark.asyncio
async def test_a_successful_apply_says_so() -> None:
    client, _ = _client(
        {"searchNeighbor": {"rows": []}, "reconfigure": {"status": "ok"}}
    )

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009", "apply": True}
    )

    assert result["applied"] is True
    assert "apply_error" not in result


@pytest.mark.asyncio
async def test_a_write_failure_is_still_a_failure() -> None:
    """Separating the phases must not soften a genuine write error."""
    client, _ = _client(
        {"searchNeighbor": {"rows": []}, "addNeighbor": TimeoutError("boom")}
    )

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009", "apply": True}
    )

    assert result["status"] == "error"


# --- notes that describe work the tool already did ------------------------


@pytest.mark.asyncio
async def test_the_note_does_not_ask_for_a_reconfigure_that_already_ran() -> None:
    client, _ = _client(
        {"searchNeighbor": {"rows": []}, "reconfigure": {"status": "ok"}}
    )

    result = await MkBgpNeighborTool(client).execute(
        {
            "address": "198.51.100.9",
            "remote_as": "65009",
            "enabled": True,
            "apply": True,
        }
    )

    assert "reconfigure" not in result["note"].lower()


@pytest.mark.asyncio
async def test_mk_loopback_does_not_claim_instantiation_on_a_failed_apply() -> None:
    """The note asserted "created and instantiated" without checking."""
    client, _ = _client({"reconfigure": {"status": "failed"}})

    result = await MkLoopbackTool(client).execute(
        {"description": "probe", "apply": True}
    )

    assert result["applied"] is False
    # The note must say it was not instantiated, not merely avoid the word.
    assert "not instantiated" in result["note"].lower()
    assert "will not appear as assignable" in result["note"].lower()
