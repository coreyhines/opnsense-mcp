"""Alias write tools.

Aliases are named groups of addresses, ports or networks that firewall and NAT
rules reference. The routing wave needs to create them, and today only a
read-only search exists.

Two properties matter beyond CRUD working:

* URL-table aliases can carry HTTP credentials, so the raw rows include
  `username` and `password`. Those must never come back out.
* `set_alias` must read, merge and write the whole node. A partial POST to an
  MVC model blanks the fields it omits, which is the same defect `set_fw_rule`
  had.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.alias_write import (
    MkAliasTool,
    RmAliasTool,
    SetAliasTool,
    ToggleAliasTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

ALIAS_UUID = "9d6dbe4b-cb2a-4908-b379-876a94a39fd9"

SEARCH_ROWS = {
    "rows": [
        {
            "uuid": ALIAS_UUID,
            "name": "bootstrpDNS",
            "type": "host",
            "content": "1.1.1.1,8.8.8.8",
            "description": "Bootstrap DNS servers",
            "enabled": "1",
            "username": "svc-account",
            "password": "hunter2",
            "current_items": "2",
        }
    ],
    "total": 1,
}

# getItem shape: enums are {key: {selected, value}}, content's selected keys are
# the alias members.
GET_ITEM = {
    "alias": {
        "name": "bootstrpDNS",
        "description": "Bootstrap DNS servers",
        "enabled": "1",
        "type": {
            "host": {"selected": 1, "value": "Host(s)"},
            "network": {"selected": 0, "value": "Network(s)"},
        },
        "content": {
            "1.1.1.1": {"selected": 1, "value": "1.1.1.1"},
            "8.8.8.8": {"selected": 1, "value": "8.8.8.8"},
            "9.9.9.9": {"selected": 0, "value": "9.9.9.9"},
        },
        "proto": {"IPv4": {"selected": 0, "value": "IPv4"}},
        "counters": "1",
        "current_items": "2",
        "last_updated": "2026-07-22T09:39:45",
        "username": "svc-account",
        "password": "hunter2",
    }
}


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _stub(client: OPNsenseClient, responses: dict[str, Any]) -> list[dict[str, Any]]:
    """Answer by endpoint substring; record every call for inspection."""
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append(
            {"method": method, "endpoint": endpoint, "json": kwargs.get("json")}
        )
        for key, value in responses.items():
            if key in endpoint:
                return value
        return {"result": "saved"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- create ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_mk_alias_posts_the_expected_payload() -> None:
    client = _client()
    calls = _stub(client, {"searchItem": {"rows": [], "total": 0}})

    result = await MkAliasTool(client).execute(
        {
            "name": "FABRIC_INTERNAL",
            "type": "network",
            "content": ["172.20.2.0/24", "172.20.8.0/24"],
            "description": "fabric internal prefixes",
        }
    )

    assert result["status"] == "success"
    add = next(c for c in calls if "addItem" in c["endpoint"])
    payload = add["json"]["alias"]
    assert payload["name"] == "FABRIC_INTERNAL"
    assert payload["type"] == "network"
    assert payload["content"] == "172.20.2.0/24\n172.20.8.0/24"


@pytest.mark.asyncio
async def test_mk_alias_is_idempotent_on_name() -> None:
    """A second create must return the existing alias, not a duplicate."""
    client = _client()
    calls = _stub(client, {"searchItem": SEARCH_ROWS})

    result = await MkAliasTool(client).execute(
        {"name": "bootstrpDNS", "type": "host", "content": ["1.1.1.1"]}
    )

    assert result["created"] is False
    assert result["uuid"] == ALIAS_UUID
    assert not [c for c in calls if "addItem" in c["endpoint"]]


@pytest.mark.asyncio
async def test_mk_alias_rejects_an_unknown_type() -> None:
    client = _client()
    _stub(client, {"searchItem": {"rows": [], "total": 0}})

    result = await MkAliasTool(client).execute(
        {"name": "x", "type": "nonsense", "content": ["1.1.1.1"]}
    )

    assert result["status"] == "error"
    assert "type" in result["error"]


# --- update ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_alias_preserves_fields_it_was_not_asked_to_change() -> None:
    """A partial POST blanks omitted fields; this is the set_fw_rule defect."""
    client = _client()
    calls = _stub(client, {"getItem": GET_ITEM, "searchItem": SEARCH_ROWS})

    result = await SetAliasTool(client).execute(
        {"uuid": ALIAS_UUID, "description": "renamed"}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "setItem" in c["endpoint"])["json"]["alias"]
    assert payload["description"] == "renamed"
    assert payload["name"] == "bootstrpDNS"
    assert payload["type"] == "host"
    # Newline-separated: the alias model reads a comma-joined string as one
    # malformed entry, which the live firewall rejects.
    assert payload["content"] == "1.1.1.1\n8.8.8.8"


@pytest.mark.asyncio
async def test_set_alias_replaces_content_when_asked() -> None:
    client = _client()
    calls = _stub(client, {"getItem": GET_ITEM, "searchItem": SEARCH_ROWS})

    await SetAliasTool(client).execute(
        {"uuid": ALIAS_UUID, "content": ["10.10.10.1", "10.10.10.2"]}
    )

    payload = next(c for c in calls if "setItem" in c["endpoint"])["json"]["alias"]
    assert payload["content"] == "10.10.10.1\n10.10.10.2"


@pytest.mark.asyncio
async def test_set_alias_drops_computed_fields() -> None:
    """Counters and timestamps are read-only; posting them back is noise."""
    client = _client()
    calls = _stub(client, {"getItem": GET_ITEM, "searchItem": SEARCH_ROWS})

    await SetAliasTool(client).execute({"uuid": ALIAS_UUID, "description": "x"})

    payload = next(c for c in calls if "setItem" in c["endpoint"])["json"]["alias"]
    for field in ("current_items", "last_updated", "counters"):
        assert field not in payload


@pytest.mark.asyncio
async def test_set_alias_requires_a_uuid() -> None:
    client = _client()

    result = await SetAliasTool(client).execute({"description": "x"})

    assert result["status"] == "error"
    assert "uuid" in result["error"]


# --- credentials never leak ------------------------------------------------


@pytest.mark.asyncio
async def test_alias_results_never_carry_credentials() -> None:
    """URL-table aliases can hold HTTP auth; it must not come back out."""
    client = _client()
    _stub(client, {"getItem": GET_ITEM, "searchItem": SEARCH_ROWS})

    updated = await SetAliasTool(client).execute(
        {"uuid": ALIAS_UUID, "description": "x"}
    )
    toggled = await ToggleAliasTool(client).execute(
        {"uuid": ALIAS_UUID, "enabled": False}
    )

    for result in (updated, toggled):
        blob = str(result)
        assert "hunter2" not in blob
        assert "svc-account" not in blob


# --- toggle ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_toggle_takes_an_explicit_state() -> None:
    """A blind flip double-toggles when an agent retries a timed-out call."""
    client = _client()
    calls = _stub(client, {"searchItem": SEARCH_ROWS})

    await ToggleAliasTool(client).execute({"uuid": ALIAS_UUID, "enabled": False})

    toggle = next(c for c in calls if "toggleItem" in c["endpoint"])
    assert toggle["endpoint"].endswith("/0")


@pytest.mark.asyncio
async def test_toggle_requires_the_enabled_flag() -> None:
    client = _client()

    result = await ToggleAliasTool(client).execute({"uuid": ALIAS_UUID})

    assert result["status"] == "error"
    assert "enabled" in result["error"]


# --- delete ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_requires_a_confirmation_token() -> None:
    client = _client()
    calls = _stub(client, {"searchItem": SEARCH_ROWS})

    result = await RmAliasTool(client).execute({"uuid": ALIAS_UUID})

    assert result["status"] == "confirmation_required"
    assert result["confirm_token"]
    assert not [c for c in calls if "delItem" in c["endpoint"]]


@pytest.mark.asyncio
async def test_delete_proceeds_with_a_valid_token() -> None:
    client = _client()
    calls = _stub(client, {"searchItem": SEARCH_ROWS})
    tool = RmAliasTool(client)

    first = await tool.execute({"uuid": ALIAS_UUID})
    result = await tool.execute({"uuid": ALIAS_UUID, "confirm": first["confirm_token"]})

    assert result["status"] == "success"
    assert [c for c in calls if "delItem" in c["endpoint"]]


@pytest.mark.asyncio
async def test_delete_rejects_a_wrong_token() -> None:
    client = _client()
    calls = _stub(client, {"searchItem": SEARCH_ROWS})
    tool = RmAliasTool(client)

    await tool.execute({"uuid": ALIAS_UUID})
    result = await tool.execute({"uuid": ALIAS_UUID, "confirm": "not-the-token"})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "delItem" in c["endpoint"]]


# --- apply -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_writes_reconfigure_by_default() -> None:
    """Alias reconfigure is cheap and not an interface rebuild, so it applies."""
    client = _client()
    calls = _stub(client, {"searchItem": {"rows": [], "total": 0}})

    await MkAliasTool(client).execute(
        {"name": "A", "type": "host", "content": ["1.1.1.1"]}
    )

    assert [c for c in calls if "reconfigure" in c["endpoint"]]


@pytest.mark.asyncio
async def test_apply_false_stages_without_reconfiguring() -> None:
    client = _client()
    calls = _stub(client, {"searchItem": {"rows": [], "total": 0}})

    await MkAliasTool(client).execute(
        {"name": "A", "type": "host", "content": ["1.1.1.1"], "apply": False}
    )

    assert not [c for c in calls if "reconfigure" in c["endpoint"]]
