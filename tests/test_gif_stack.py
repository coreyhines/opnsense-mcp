"""Unit tests for GIF wire mappers and fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.tools.gif_stack import (
    AssignInterfaceTool,
    ListGifTool,
    MkGifTool,
    RmGifTool,
    SetGifTool,
    gif_params_to_wire,
    privilege_error_message,
    project_gif_row,
)
from opnsense_mcp.utils.api import RequestError

FIX = Path(__file__).parent / "fixtures" / "opnsense-26.7.3"

GIF_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GIF_ROW = {
    "uuid": GIF_UUID,
    "gifif": "gif0",
    "if": "wan",
    "remote-addr": "203.0.113.10",
    "tunnel-local-addr": "2001:db8:1::2",
    "tunnel-remote-addr": "2001:db8:1::1",
    "tunnel-remote-net": "64",
    "descr": "lab",
}
GIF_NODE = json.loads((FIX / "gif_get_item_blank.json").read_text())["gif"]
GIF_NODE["gifif"] = "gif0"
GIF_NODE["remote-addr"] = "203.0.113.10"


def test_gif_params_to_wire_maps_parent_interface() -> None:
    wire = gif_params_to_wire(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
            "description": "lab",
            "ecn": True,
        }
    )
    assert wire["if"] == "wan"
    assert wire["remote-addr"] == "203.0.113.10"
    assert wire["tunnel-local-addr"] == "2001:db8:1::2"
    assert wire["tunnel-remote-addr"] == "2001:db8:1::1"
    assert wire["tunnel-remote-net"] == "64"
    assert wire["descr"] == "lab"
    assert wire["link1"] == "1"
    assert "ipaddr" not in wire or wire.get("ipaddr") in ("", None)


def test_gif_params_to_wire_defaults_tunnel_remote_net_to_32() -> None:
    wire = gif_params_to_wire(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "192.0.2.1",
            "tunnel_remote": "192.0.2.2",
        }
    )
    assert wire["tunnel-remote-net"] == "32"


def test_gif_params_to_wire_maps_parent_as_ipaddr() -> None:
    wire = gif_params_to_wire(
        {
            "parent": "198.51.100.1",
            "remote": "203.0.113.10",
            "tunnel_local": "192.0.2.1",
            "tunnel_remote": "192.0.2.2",
        }
    )
    assert wire["ipaddr"] == "198.51.100.1"
    assert "if" not in wire


def test_project_gif_row_uses_wire_keys() -> None:
    public = project_gif_row(
        {
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "gifif": "gif0",
            "if": "wan",
            "remote-addr": "203.0.113.10",
            "tunnel-local-addr": "2001:db8:1::2",
            "tunnel-remote-addr": "2001:db8:1::1",
            "tunnel-remote-net": "64",
            "descr": "lab",
        }
    )
    assert public["device"] == "gif0"
    assert public["parent"] == "wan"
    assert public["remote"] == "203.0.113.10"
    assert public["tunnel_local"] == "2001:db8:1::2"
    assert public["uuid"]


def test_privilege_error_message_mentions_gif_settings() -> None:
    message = privilege_error_message()
    assert "403" in message
    assert "gif_settings" in message


def test_gif_search_fixture_bootgrid_shape() -> None:
    payload = json.loads((FIX / "gif_search_item_empty.json").read_text())
    assert "rows" in payload
    assert payload["total"] == 0
    assert payload["rows"] == []


def test_gif_get_item_fixture_carries_wire_keys() -> None:
    payload = json.loads((FIX / "gif_get_item_blank.json").read_text())
    node = payload["gif"]
    for key in (
        "if",
        "ipaddr",
        "gifif",
        "remote-addr",
        "tunnel-local-addr",
        "tunnel-remote-addr",
        "tunnel-remote-net",
        "descr",
        "link1",
        "link2",
        "noclamp",
    ):
        assert key in node


@pytest.mark.asyncio
async def test_list_gif_projects_rows() -> None:
    payload = json.loads((FIX / "gif_search_item_empty.json").read_text())
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=payload)
    tool = ListGifTool(client)
    result = await tool.execute({})
    assert result["status"] == "success"
    assert "gifs" in result
    assert result["count"] == len(result["gifs"])
    for row in result["gifs"]:
        assert row.get("device") or result["count"] == 0


@pytest.mark.asyncio
async def test_list_gif_maps_403_to_privilege_error() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(side_effect=RequestError("HTTP 403: Forbidden"))
    tool = ListGifTool(client)
    result = await tool.execute({})
    assert result["status"] == "error"
    assert "403" in result["error"] or "privilege" in result["error"].lower()
    assert "gif_settings" in result["error"]


@pytest.mark.asyncio
async def test_mk_gif_requires_core_fields() -> None:
    tool = MkGifTool(AsyncMock())
    result = await tool.execute({"parent": "wan"})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_mk_gif_reuses_identical_tunnel() -> None:
    existing = {
        "rows": [
            {
                "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "gifif": "gif0",
                "if": "wan",
                "remote-addr": "203.0.113.10",
                "tunnel-local-addr": "2001:db8:1::2",
                "tunnel-remote-addr": "2001:db8:1::1",
                "tunnel-remote-net": "64",
                "descr": "lab",
            }
        ]
    }
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=existing)
    tool = MkGifTool(client)
    result = await tool.execute(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
        }
    )
    assert result["status"] == "success"
    assert result["created"] is False
    assert result["device"] == "gif0"
    assert not any(
        "add_item" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_mk_gif_stages_without_apply_by_default() -> None:
    client = AsyncMock()

    async def fake(method, endpoint, **kwargs):
        if "search_item" in endpoint:
            return {"rows": []}
        if "add_item" in endpoint:
            return {"uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "result": "saved"}
        raise AssertionError(endpoint)

    client._make_request = AsyncMock(side_effect=fake)
    tool = MkGifTool(client)
    result = await tool.execute(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
        }
    )
    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert not any(
        "reconfigure" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_set_gif_refuses_device_rename() -> None:
    tool = SetGifTool(AsyncMock())
    result = await tool.execute({"uuid": GIF_UUID, "device": "gif1"})
    assert result["status"] == "error"
    assert "gifif" in result["error"] or "device" in result["error"].lower()


@pytest.mark.asyncio
async def test_set_gif_stages_without_apply_by_default() -> None:
    client = AsyncMock()

    async def fake(method, endpoint, **kwargs):
        if "get_item" in endpoint:
            return {"gif": GIF_NODE}
        if "set_item" in endpoint:
            return {"result": "saved"}
        raise AssertionError(endpoint)

    client._make_request = AsyncMock(side_effect=fake)
    tool = SetGifTool(client)
    result = await tool.execute(
        {"uuid": GIF_UUID, "description": "updated", "tunnel_remote_net": 64}
    )
    assert result["status"] == "success"
    assert result["applied"] is False
    set_calls = [
        c
        for c in client._make_request.await_args_list
        if c.args and "set_item" in str(c.args[1])
    ]
    assert set_calls
    payload = set_calls[0].kwargs.get("json", {}).get("gif", {})
    assert "gifif" not in payload or payload.get("gifif") == "gif0"
    assert not any(
        "reconfigure" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_rm_gif_requires_confirm_token() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(return_value={"rows": []})
    tool = RmGifTool(client)

    result = await tool.execute({"uuid": GIF_UUID})

    assert result["status"] == "confirmation_required"
    assert result.get("confirm_token")
    assert not any(
        "del_item" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_rm_gif_refuses_while_assigned() -> None:
    client = AsyncMock()

    async def fake(method, endpoint, **kwargs):
        if "gif_settings/search" in endpoint:
            return {"rows": [GIF_ROW]}
        if "assignment/search" in endpoint:
            return {
                "rows": [
                    {"if": "gif0", "identifier": "opt5", "uuid": "asn-uuid"},
                ]
            }
        raise AssertionError(endpoint)

    client._make_request = AsyncMock(side_effect=fake)
    tool = RmGifTool(client)

    first = await tool.execute({"uuid": GIF_UUID})
    result = await tool.execute({"uuid": GIF_UUID, "confirm": first["confirm_token"]})

    assert result["status"] == "error"
    assert "assigned" in result["error"].lower() or "opt5" in result["error"]
    assert not any(
        "del_item" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_rm_gif_deletes_once_confirmed() -> None:
    client = AsyncMock()

    async def fake(method, endpoint, **kwargs):
        if "gif_settings/search" in endpoint:
            return {"rows": [GIF_ROW]}
        if "assignment/search" in endpoint:
            return {"rows": []}
        if "del_item" in endpoint:
            return {"result": "deleted"}
        raise AssertionError(endpoint)

    client._make_request = AsyncMock(side_effect=fake)
    tool = RmGifTool(client)

    challenge = await tool.execute({"uuid": GIF_UUID})
    result = await tool.execute(
        {"uuid": GIF_UUID, "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert any(
        "del_item" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_assign_refuses_unknown_device() -> None:
    blank = json.loads((FIX / "assignment_get_item_blank.json").read_text())
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=blank)
    tool = AssignInterfaceTool(client)
    result = await tool.execute({"device": "gif99"})
    assert result["status"] == "error"
    assert "gif99" in result["error"]


@pytest.mark.asyncio
async def test_assign_reuses_existing_binding() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(
        return_value={
            "rows": [
                {
                    "uuid": "opt20",
                    "identifier": "opt20",
                    "if": "gif0",
                    "descr": "lab",
                    "lock": "0",
                }
            ]
        }
    )
    tool = AssignInterfaceTool(client)
    result = await tool.execute({"device": "gif0"})
    assert result["status"] == "success"
    assert result.get("created") is False
    assert result["identifier"] == "opt20"


@pytest.mark.asyncio
async def test_rm_gif_refuses_truncated_gif_listing() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(
        return_value={"rows": [], "total": 6000, "rowCount": 5000}
    )
    tool = RmGifTool(client)
    challenge = await tool.execute({"uuid": GIF_UUID})
    result = await tool.execute(
        {"uuid": GIF_UUID, "confirm": challenge["confirm_token"]}
    )
    assert result["status"] == "error"
    assert "truncated" in result["error"]


@pytest.mark.asyncio
async def test_assign_refuses_truncated_assignment_listing() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(
        return_value={"rows": [], "total": 6000, "rowCount": 5000}
    )
    tool = AssignInterfaceTool(client)
    result = await tool.execute({"device": "gif0"})
    assert result["status"] == "error"
    assert "truncated" in result["error"]
