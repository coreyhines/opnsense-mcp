"""WireGuard writes (#43), against the shapes and rules the firmware really has.

Every case here corresponds to something invisible from the outside, read off
`OPNsense/Wireguard/Api/{Client,Server,Service}Controller.php` on the live
firewall. A test that only round-tripped a hand-written dict would pass against
all of them.

The two fixtures are captured `get*` responses, and both carry a trap:

- `wg_getserver_dangling.json` has `carp_depend_on` as
  `{"": {"value": "None", "selected": 1}}`, where the key is the stored value
  and `None` is display text. A flattener that took the label writes the literal
  string "None" back as data.
- `wg_getclient_multi_instance.json` is a peer in one of three instances, so its
  `servers` map enumerates all three with membership carried only by `selected`.
  Reading the keys enrols the peer everywhere.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import pytest

from opnsense_mcp.tools.wireguard_write import (
    WG_CLIENT_WRITE,
    WG_RECONFIGURE,
    WG_SERVER_WRITE,
    CreateWgPeerTool,
    DeleteWgPeerTool,
    SetWgInstanceTool,
    SetWgPeerTool,
    ToggleWgTool,
    WgWriteError,
    removed_entries,
    set_or_refuse,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"
SERVER = json.loads((FIXTURES / "wg_getserver_dangling.json").read_text())
CLIENT = json.loads((FIXTURES / "wg_getclient_multi_instance.json").read_text())

SERVER_UUID = "00524b42-93b5-455f-982f-8c7c4174ab73"
CLIENT_UUID = "693b9fb2-d68a-450c-b5b7-fa0ec7cec302"

# The instance this peer actually belongs to, taken from the fixture so the
# test cannot drift from it.
MEMBER_UUID = next(
    key for key, opt in CLIENT["client"]["servers"].items() if opt["selected"] == 1
)
NON_MEMBER_UUIDS = [
    key for key, opt in CLIENT["client"]["servers"].items() if opt["selected"] != 1
]

SERVER_ROWS = {
    "total": 3,
    "rowCount": 3,
    "current": 1,
    "rows": [
        {"uuid": key, "name": opt["value"]}
        for key, opt in CLIENT["client"]["servers"].items()
    ],
}

SAVED = {"result": "saved"}


class FakeClient:
    """Records every request and replays canned responses by path."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.responses = dict(responses or {})

    def on(self, path: str, response: Any) -> FakeClient:
        self.responses[path] = response
        return self

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        call_class: str | None = None,
        **kwargs: Any,
    ) -> Any:
        self.requests.append(
            {
                "method": method,
                "endpoint": endpoint,
                "json": json,
                "call_class": call_class,
            }
        )
        for path, response in self.responses.items():
            if endpoint == path or endpoint.startswith(path.rstrip("/") + "/"):
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected request to {endpoint}")

    def posted_to(self, path: str) -> list[dict[str, Any]]:
        return [
            r
            for r in self.requests
            if r["method"] == "POST" and r["endpoint"].startswith(path)
        ]


def _base_client() -> FakeClient:
    """A client that can serve both reads, both writes and a reconfigure."""
    return FakeClient(
        {
            "/api/wireguard/server/getServer": SERVER,
            "/api/wireguard/client/getClient": CLIENT,
            "/api/wireguard/server/searchServer": SERVER_ROWS,
            WG_SERVER_WRITE["set"]: SAVED,
            WG_CLIENT_WRITE["set"]: SAVED,
            WG_CLIENT_WRITE["add"]: {"result": "saved", "uuid": "new-uuid"},
            WG_CLIENT_WRITE["del"]: {"result": "deleted"},
            WG_RECONFIGURE: {"result": "ok"},
        }
    )


# --- membership goes through the client, never the server ------------------


@pytest.mark.asyncio
async def test_membership_is_written_through_the_client_not_the_server() -> None:
    """`setClientAction` maintains `server.peers` itself.

    It reads the posted `client.servers`, locks the config, and walks every
    server node adding or removing this uuid. Posting `server.peers` through
    `setServer` fights that and desynchronises the back-reference, so this
    asserts the negative as well as the positive.
    """
    client = _base_client()

    result = await SetWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "instances": [MEMBER_UUID, NON_MEMBER_UUIDS[0]]}
    )

    assert result["status"] == "success"
    assert client.posted_to(WG_SERVER_WRITE["set"]) == []

    posted = client.posted_to(WG_CLIENT_WRITE["set"])
    assert len(posted) == 1
    sent = posted[0]["json"]["client"]["servers"].split(",")
    assert sorted(sent) == sorted([MEMBER_UUID, NON_MEMBER_UUIDS[0]])


@pytest.mark.asyncio
async def test_membership_is_never_built_from_the_node_maps_keys() -> None:
    """The map enumerates every instance on the box; only `selected` is truth.

    Writing the keys back enrols the peer in all three. Here the caller changes
    something else entirely, so the membership must round-trip as the one
    instance it already had.
    """
    client = _base_client()

    await SetWgPeerTool(client).execute({"uuid": CLIENT_UUID, "keepalive": "25"})

    sent = client.posted_to(WG_CLIENT_WRITE["set"])[0]["json"]["client"]
    assert sent["servers"] == MEMBER_UUID
    for other in NON_MEMBER_UUIDS:
        assert other not in sent["servers"]


# --- a set replaces the whole node -----------------------------------------


@pytest.mark.asyncio
async def test_a_set_sends_every_field_not_only_the_changed_one() -> None:
    """A `set*` POST resets any field it omits to the model default.

    `privkey` is `Required` in Server.xml, so a payload without it is refused
    outright; the rest would be silently blanked.
    """
    client = _base_client()

    await SetWgInstanceTool(client).execute({"uuid": SERVER_UUID, "mtu": "1400"})

    sent = client.posted_to(WG_SERVER_WRITE["set"])[0]["json"]["server"]
    assert sent["mtu"] == "1400"
    for field in ("name", "port", "privkey", "pubkey", "instance", "interface"):
        assert field in sent, f"{field} would be reset to its model default"
    assert sent["name"] == SERVER["server"]["name"]


@pytest.mark.asyncio
async def test_carp_depend_on_writes_its_key_not_its_display_label() -> None:
    """`{"": {"value": "None", "selected": 1}}` means unset.

    The key is the stored value and `None` is display text, so a flattener that
    took the label writes the literal string "None" into the config.
    """
    assert SERVER["server"]["carp_depend_on"] == {
        "": {"value": "None", "selected": 1}
    }, "the fixture no longer carries the shape this guards"

    client = _base_client()
    await SetWgInstanceTool(client).execute({"uuid": SERVER_UUID, "mtu": "1400"})

    sent = client.posted_to(WG_SERVER_WRITE["set"])[0]["json"]["server"]
    assert sent["carp_depend_on"] == ""
    assert sent["carp_depend_on"] != "None"


@pytest.mark.asyncio
async def test_an_instance_write_never_posts_the_servers_peer_list() -> None:
    """`peers` is the output of the client-side relation, not an input here."""
    client = _base_client()

    await SetWgInstanceTool(client).execute({"uuid": SERVER_UUID, "mtu": "1400"})

    sent = client.posted_to(WG_SERVER_WRITE["set"])[0]["json"]["server"]
    # merge_for_set collapses it to the selected keys; whatever it becomes, the
    # tool must not have been given a way to change it.
    assert "peers" not in SetWgInstanceTool.input_schema["properties"]


# --- failures that arrive at HTTP 200 --------------------------------------


def test_a_validation_failure_is_parsed_not_merely_stringified() -> None:
    """`setBase` answers 200 with `{"result": "failed", "validations": {...}}`.

    The transport raises on `result == "failed"` without reading `validations`,
    so without this the caller learns only that something failed.

    Asserted on the exception's field rather than on its message. The first
    version of this test checked that "client.tunneladdress" appeared in the
    text, and it passed with the parsing branch removed entirely -- because the
    fallback dumps the whole body into the message, so the field name is there
    either way. That is the wording-versus-structure mistake this repo has
    already paid for once.
    """
    with pytest.raises(WgWriteError) as caught:
        set_or_refuse(
            {
                "result": "failed",
                "validations": {"client.tunneladdress": "not a valid network"},
            },
            "the peer",
        )

    assert caught.value.validations == {"client.tunneladdress": "not a valid network"}


def test_a_body_with_no_validations_carries_none_rather_than_inventing_them() -> None:
    """The other direction, or "always return {}" would pass the test above."""
    with pytest.raises(WgWriteError) as caught:
        set_or_refuse({"result": "failed"}, "the peer")

    assert caught.value.validations == {}


@pytest.mark.asyncio
async def test_a_refused_write_is_reported_as_an_error_not_a_success() -> None:
    client = _base_client().on(
        WG_CLIENT_WRITE["set"],
        {"result": "failed", "validations": {"client.pubkey": "invalid key"}},
    )

    result = await SetWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "keepalive": "25"}
    )

    assert result["status"] == "error"
    assert result["validations"] == {"client.pubkey": "invalid key"}


# --- toggle sets a target, it does not flip --------------------------------


@pytest.mark.asyncio
async def test_toggle_writes_nothing_when_already_in_the_target_state() -> None:
    """`toggleServerAction($uuid)` declares one parameter, so a target state
    cannot be passed and the action flips whatever it finds. Two callers, or
    one retrying after a timeout, would land on the state they were leaving."""
    assert SERVER["server"]["enabled"] == "0"
    client = _base_client()

    result = await ToggleWgTool(client).execute(
        {"uuid": SERVER_UUID, "kind": "instance", "enabled": False}
    )

    assert result["status"] == "success"
    assert result["changed"] is False
    assert client.posted_to(WG_SERVER_WRITE["set"]) == []


@pytest.mark.asyncio
async def test_toggle_writes_the_target_when_it_differs() -> None:
    client = _base_client()

    result = await ToggleWgTool(client).execute(
        {"uuid": SERVER_UUID, "kind": "instance", "enabled": True}
    )

    assert result["changed"] is True
    sent = client.posted_to(WG_SERVER_WRITE["set"])[0]["json"]["server"]
    assert sent["enabled"] == "1"


@pytest.mark.asyncio
async def test_toggle_never_calls_the_firmwares_toggle_endpoints() -> None:
    client = _base_client()

    await ToggleWgTool(client).execute(
        {"uuid": CLIENT_UUID, "kind": "peer", "enabled": False}
    )

    assert not [r for r in client.requests if "toggle" in r["endpoint"].lower()]


# --- removals need confirming ----------------------------------------------


def test_removed_entries_is_what_a_wholesale_replace_takes_away() -> None:
    assert removed_entries(["a", "b", "c"], ["a", "c"]) == ["b"]
    assert removed_entries(["a"], ["a", "b"]) == []
    assert removed_entries(["a", "b"], []) == ["a", "b"]


@pytest.mark.asyncio
async def test_dropping_an_allowed_ip_needs_a_confirm_token() -> None:
    """The peer's `tunneladdress` is its server-side Allowed-IPs, so a
    wholesale replace that drops one stops routing to that address."""
    keep = "192.168.10.2/32"
    dropped = next(
        entry for entry in CLIENT["client"]["tunneladdress"] if entry != keep
    )
    client = _base_client()

    first = await SetWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "tunneladdress": keep}
    )

    assert first["status"] == "confirmation_required"
    assert first["removing"] == {"allowed_ips": [dropped]}
    assert client.posted_to(WG_CLIENT_WRITE["set"]) == []

    second = await SetWgPeerTool(client).execute(
        {
            "uuid": CLIENT_UUID,
            "tunneladdress": keep,
            "confirm": first["confirm_token"],
        }
    )
    assert second["status"] == "success"
    assert len(client.posted_to(WG_CLIENT_WRITE["set"])) == 1


@pytest.mark.asyncio
async def test_adding_an_allowed_ip_does_not_need_a_confirm_token() -> None:
    """Only a removal is destructive; requiring a token for every list write
    would train the caller to paste one without reading it."""
    entries = ",".join([*CLIENT["client"]["tunneladdress"], "192.168.10.99/32"])
    client = _base_client()

    result = await SetWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "tunneladdress": entries}
    )

    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_unenrolling_a_peer_needs_a_confirm_token() -> None:
    client = _base_client()

    result = await SetWgPeerTool(client).execute({"uuid": CLIENT_UUID, "instances": []})

    assert result["status"] == "confirmation_required"
    assert result["removing"] == {"instances": [MEMBER_UUID]}


@pytest.mark.asyncio
async def test_a_membership_naming_an_unknown_instance_is_refused() -> None:
    """An unresolvable name must not become an empty membership, which would
    silently unenrol the peer everywhere instead of failing."""
    client = _base_client()

    result = await SetWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "instances": ["wgNoSuchInstance"]}
    )

    assert result["status"] == "error"
    assert "wgNoSuchInstance" in result["error"]
    assert client.posted_to(WG_CLIENT_WRITE["set"]) == []


# --- create_peer takes a public key and nothing else -----------------------


@pytest.mark.asyncio
async def test_create_peer_refuses_without_a_public_key() -> None:
    """The #44 decision, enforced rather than documented."""
    client = _base_client()

    result = await CreateWgPeerTool(client).execute(
        {"name": "phone", "pubkey": "", "instances": [MEMBER_UUID]}
    )

    assert result["status"] == "error"
    assert "pubkey" in result["error"]
    assert client.posted_to(WG_CLIENT_WRITE["add"]) == []


@pytest.mark.asyncio
async def test_no_wireguard_tool_ever_asks_the_firewall_for_a_key() -> None:
    """`server/keyPair` and `client/psk` both mint key material.

    Neither is called from anywhere in the write surface, and this says so as a
    test rather than as a comment, because the endpoints exist and adding a
    "convenience" call to one is the obvious wrong turn.
    """
    source = pathlib.Path("opnsense_mcp/tools/wireguard_write.py").read_text()

    assert "keyPair" not in source
    assert "/psk" not in source


@pytest.mark.asyncio
async def test_create_peer_enrols_through_the_clients_own_servers_field() -> None:
    client = _base_client()

    result = await CreateWgPeerTool(client).execute(
        {
            "name": "phone",
            "pubkey": "A" * 43 + "=",
            "instances": [MEMBER_UUID],
        }
    )

    assert result["status"] == "success"
    assert result["uuid"] == "new-uuid"
    sent = client.posted_to(WG_CLIENT_WRITE["add"])[0]["json"]["client"]
    assert sent["servers"] == MEMBER_UUID
    assert client.posted_to(WG_SERVER_WRITE["set"]) == []


@pytest.mark.asyncio
async def test_create_peer_refuses_to_enrol_a_peer_nowhere() -> None:
    """`addClient` accepts it, and the peer is then written but never loaded."""
    client = _base_client()

    result = await CreateWgPeerTool(client).execute(
        {"name": "phone", "pubkey": "A" * 43 + "=", "instances": []}
    )

    assert result["status"] == "error"
    assert client.posted_to(WG_CLIENT_WRITE["add"]) == []


# --- an apply is a request, not a state ------------------------------------


@pytest.mark.asyncio
async def test_nothing_is_applied_unless_asked() -> None:
    client = _base_client()

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": "1400"}
    )

    assert result["applied"] is False
    assert result["staged"] is True
    assert client.posted_to(WG_RECONFIGURE) == []


@pytest.mark.asyncio
async def test_an_apply_reports_unverified_when_the_re_read_disagrees() -> None:
    """`reconfigureAction` returns `{"result": "ok"}` unconditionally after
    handing off to configd, so its success says the request was accepted and
    nothing about the state reached.

    The case that pins the re-read is this one: asserting `verified is True` on
    a run where the write succeeded passes whether the code re-reads or just
    echoes what it sent.
    """
    client = _base_client()

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": "1400", "apply": True}
    )

    assert result["applied"] is True
    assert result["verified"] is False
    assert result["mismatched"]["mtu"] == {
        "wanted": "1400",
        "stored": SERVER["server"]["mtu"],
    }


@pytest.mark.asyncio
async def test_an_apply_reports_verified_when_the_re_read_agrees() -> None:
    client = _base_client()
    unchanged = SERVER["server"]["mtu"]

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": unchanged, "apply": True}
    )

    assert result["applied"] is True
    assert result["verified"] is True
    assert "mismatched" not in result


@pytest.mark.asyncio
async def test_a_failed_apply_leaves_the_write_in_place_and_says_so() -> None:
    """The write already happened. Reporting it as a write failure would tell
    the caller to try again, which is the inversion `utils/apply` exists for."""
    client = _base_client().on(WG_RECONFIGURE, {"result": "failed"})

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": "1400", "apply": True}
    )

    assert result["status"] == "success"
    assert result["applied"] is False
    assert "apply_error" in result
    assert len(client.posted_to(WG_SERVER_WRITE["set"])) == 1


# --- delete ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_deleting_a_peer_needs_a_confirm_token() -> None:
    client = _base_client()

    first = await DeleteWgPeerTool(client).execute({"uuid": CLIENT_UUID})

    assert first["status"] == "confirmation_required"
    assert first["instances"] == [MEMBER_UUID]
    assert client.posted_to(WG_CLIENT_WRITE["del"]) == []

    second = await DeleteWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "confirm": first["confirm_token"]}
    )
    assert second["status"] == "success"
    assert len(client.posted_to(WG_CLIENT_WRITE["del"])) == 1


@pytest.mark.asyncio
async def test_a_delete_verifies_the_record_is_gone_not_that_the_call_returned() -> (
    None
):
    """An unknown uuid answers 200 with `[]`, so "still readable" is the
    failure and a read error is the success. Here the fixture still answers,
    which must be reported as unverified rather than glossed over."""
    client = _base_client()
    token = (await DeleteWgPeerTool(client).execute({"uuid": CLIENT_UUID}))[
        "confirm_token"
    ]

    result = await DeleteWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "confirm": token, "apply": True}
    )

    assert result["applied"] is True
    assert result["verified"] is False
    assert "still readable" in result["verify_error"]


@pytest.mark.asyncio
async def test_a_delete_verifies_true_once_the_record_is_gone() -> None:
    client = _base_client()
    token = (await DeleteWgPeerTool(client).execute({"uuid": CLIENT_UUID}))[
        "confirm_token"
    ]
    # What the firewall answers for a uuid that no longer exists.
    client.on("/api/wireguard/client/getClient", [])

    result = await DeleteWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "confirm": token, "apply": True}
    )

    assert result["verified"] is True


@pytest.mark.asyncio
async def test_a_delete_does_not_touch_the_servers_peer_list() -> None:
    """`delClientAction` strips the uuid from every server itself, so a tool
    doing it too would race the firmware."""
    client = _base_client()
    token = (await DeleteWgPeerTool(client).execute({"uuid": CLIENT_UUID}))[
        "confirm_token"
    ]

    await DeleteWgPeerTool(client).execute(
        {"uuid": CLIENT_UUID, "confirm": token, "apply": True}
    )

    assert client.posted_to(WG_SERVER_WRITE["set"]) == []


# --- key material never reaches a result -----------------------------------


_KEY_SHAPED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def _key_shaped_values(value: Any) -> list[str]:
    """Anything in a result that decodes to a Curve25519-sized key.

    Same predicate as `tests/test_no_key_material`, applied to what a tool
    returns rather than to what is committed. The repo guard cannot see this:
    a key read from the firewall and echoed into a tool result never touches a
    file.
    """
    if isinstance(value, str):
        return [
            m
            for m in _KEY_SHAPED.findall(value.replace("\\/", "/"))
            if len(set(m[:43])) > 4
        ]
    if isinstance(value, dict):
        return [
            found
            for key, item in value.items()
            for found in _key_shaped_values(key) + _key_shaped_values(item)
        ]
    if isinstance(value, list):
        return [found for item in value for found in _key_shaped_values(item)]
    return []


def test_the_result_scanner_would_catch_a_key() -> None:
    """A guard that never fires is indistinguishable from one that works."""
    import base64

    real = base64.b64encode(bytes(range(32))).decode()

    assert _key_shaped_values({"privkey": real}) == [real]
    assert _key_shaped_values({"nested": [{"k": real}]}) == [real]
    assert _key_shaped_values({"privkey": "A" * 43 + "="}) == []


@pytest.mark.asyncio
async def test_no_write_result_carries_key_material() -> None:
    """The instance private key passes through this process by necessity.

    `privkey` is `Required` in Server.xml and a `set*` replaces the whole node,
    so `set_instance` must read it and write it back. What must never happen is
    it appearing in what the tool returns. The fixtures use an all-one-character
    placeholder, which the entropy floor ignores, so a real-looking key is put
    into the read for this test to have anything to catch.
    """
    import base64
    import copy

    real = base64.b64encode(bytes(range(32))).decode()
    server = copy.deepcopy(SERVER)
    server["server"]["privkey"] = real
    server["server"]["pubkey"] = base64.b64encode(bytes(range(32, 64))).decode()

    client = _base_client().on("/api/wireguard/server/getServer", server)

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": "1400", "apply": True}
    )

    assert result["status"] == "success"
    assert _key_shaped_values(result) == [], "a key reached the tool's result"

    # And it really did have to handle one, or this passes vacuously.
    sent = client.posted_to(WG_SERVER_WRITE["set"])[0]["json"]["server"]
    assert sent["privkey"] == real


@pytest.mark.asyncio
async def test_an_error_body_carrying_a_key_is_redacted() -> None:
    """The transport folds a response body into the exception text, so a body
    with no named message key arrives whole."""
    import base64

    real = base64.b64encode(bytes(range(32))).decode()
    client = _base_client().on(
        WG_SERVER_WRITE["set"], RuntimeError(f'{{"privkey": "{real}"}}')
    )

    result = await SetWgInstanceTool(client).execute(
        {"uuid": SERVER_UUID, "mtu": "1400"}
    )

    assert result["status"] == "error"
    assert real not in result["error"]
    assert "<redacted key>" in result["error"]
