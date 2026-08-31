"""WireGuard parsing, tested against responses captured from 26.7.3.

Every test here pins a way the API can be misread while raising nothing. The
search grid and the get node tree share field names and disagree on types for
four of them; a peer's Allowed-IPs live in a field called `tunneladdress` while
a field named `allowed_ips` exists only on servers and is empty on every row;
and both read paths hand back the instance private key unasked.
"""

from __future__ import annotations

import collections
import json
import pathlib

import pytest

from opnsense_mcp.tools.wireguard import (
    TruncatedListingError,
    get_path,
    is_host_route,
    networks_of,
    public_instance,
    public_peer,
    record_or_none,
    rows_or_refuse,
    selected_option_keys,
    split_list,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def test_rows_or_refuse_returns_every_row_when_the_page_is_whole() -> None:
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    assert len(rows) == 3
    assert {r["name"] for r in rows} == {
        "wg0HomeVpn",
        "wg1RemoteLabUsers",
        "wg2SiteToSite",
    }


def test_rows_or_refuse_refuses_a_truncated_page() -> None:
    """A short page must refuse, never return quietly.

    `rowCount` is deliberately never sent, so total and len(rows) agree. If that
    default ever changes, a caller acting on a partial view is the failure this
    prevents.
    """
    with pytest.raises(TruncatedListingError):
        rows_or_refuse({"rows": [{"uuid": "a"}], "total": 9}, "instances")


def test_rows_or_refuse_refuses_a_payload_that_is_not_a_search_result() -> None:
    with pytest.raises(TruncatedListingError):
        rows_or_refuse([], "instances")


def test_record_or_none_treats_an_empty_array_as_not_found() -> None:
    """An unknown uuid answers HTTP 200 with `[]`, not a 404."""
    assert record_or_none([], "server") is None
    assert record_or_none({"server": {"name": "x"}}, "server") == {"name": "x"}


def test_get_path_refuses_an_empty_uuid() -> None:
    """getServer with no uuid answers 200 with a blank new-instance template.

    A path built by concatenation with an empty uuid would read that template
    and report it as a real record.
    """
    with pytest.raises(ValueError):
        get_path("/api/wireguard/server/getServer", "")
    assert get_path("/api/wireguard/server/getServer", "abc").endswith("/abc")


def test_split_list_strips_the_space_the_resolved_form_uses() -> None:
    """Raw lists join on ',' and resolved ones on ', '."""
    assert split_list("a,b,c") == ["a", "b", "c"]
    assert split_list("peerA, peerB, peerC") == ["peerA", "peerB", "peerC"]
    assert split_list("") == []
    assert split_list(None) == []


def test_selected_option_keys_ignores_unselected_options_and_the_empty_key() -> None:
    """Membership is the selected flag, never the keys.

    The node map enumerates every peer on the box. An empty list is encoded as
    one selected node with an empty key, so a length check cannot tell empty
    from one entry.
    """
    node = {
        "a": {"value": "peerA", "selected": 1},
        "b": {"value": "peerB", "selected": 0},
        "": {"value": "", "selected": 1},
    }
    assert selected_option_keys(node) == ["a"]
    assert selected_option_keys({}) == []
    assert selected_option_keys("not a node map") == []


def test_the_dangling_instance_has_no_selected_peers() -> None:
    """The live disagreement, straight from the fixture."""
    record = record_or_none(fixture("wg_getserver_dangling"), "server")
    assert record is not None
    assert len(record["peers"]) == 11
    assert selected_option_keys(record["peers"]) == []


def test_is_host_route_uses_the_family_maximum() -> None:
    assert is_host_route("192.168.10.2/32")
    assert is_host_route("fd0b:cafe:f::2/128")
    assert is_host_route("192.168.11.1")  # no prefix length is a host route
    assert not is_host_route("192.168.99.0/24")
    assert not is_host_route("fd0b:cafe:f::/64")


def test_networks_of_reads_the_network_not_the_address() -> None:
    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])
    assert [str(n) for n in nets] == ["192.168.10.0/24", "fd0b:cafe:f::/64"]
    assert networks_of(["nonsense"]) == []


def test_public_instance_omits_every_key_field() -> None:
    """The allowlist, checked on the row the API really sends."""
    row = next(
        r
        for r in rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
        if r["name"] == "wg0HomeVpn"
    )
    assert row["privkey"], "fixture no longer carries the field being guarded"

    public = public_instance(row)

    assert "privkey" not in public
    assert "pubkey" not in public
    assert public["has_privkey"] is True
    assert json.dumps(public).find(row["privkey"]) == -1

    # The allowlist above is only half of it: `**extra` used to be applied
    # after it, so one caller splatting a raw row put the key straight back.
    splatted = public_instance(row, **row)

    assert "privkey" not in splatted
    assert json.dumps(splatted).find(row["privkey"]) == -1


def test_public_peer_omits_every_key_field() -> None:
    row = rows_or_refuse(fixture("wg_searchclient_rows"), "peers")[0]
    public = public_peer(row)
    assert "privkey" not in public
    assert "psk" not in public
    assert "pubkey" not in public

    splatted = public_peer(row, **row)

    assert "psk" not in splatted
    assert "pubkey" not in splatted
    for field in ("psk", "pubkey", "privkey"):
        if row.get(field):
            assert json.dumps(splatted).find(row[field]) == -1


def test_every_instance_normalizes_to_a_non_empty_tunnel_address() -> None:
    """The assertion whose absence let the any->any defect ship."""
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    for row in rows:
        public = public_instance(row)
        assert public["tunnel_addresses"], f"empty for {public['name']!r}"


def test_every_peer_normalizes_to_a_non_empty_allowed_ips() -> None:
    """Read from `tunneladdress`. The field named `allowed_ips` is a server
    field and is empty on every row, so reaching for the obvious name yields an
    always-empty column and a green suite."""
    rows = rows_or_refuse(fixture("wg_searchclient_rows"), "peers")
    for row in rows:
        public = public_peer(row)
        assert public["allowed_ips"], f"empty for {public['name']!r}"


def test_the_server_field_named_allowed_ips_is_empty_on_every_row() -> None:
    """Recorded so nobody reaches for it later believing it holds something."""
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    assert all(row.get("allowed_ips", "") == "" for row in rows)


class FakeClient:
    """Answers each endpoint from a fixture, and records what was asked.

    A dict of endpoint substring to payload rather than a mock, so a test that
    changes which endpoint a tool calls fails on the missing key instead of
    silently receiving a default.
    """

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, object]] = []

    async def _make_request(self, method, endpoint, json=None, **kwargs):
        self.calls.append((method, endpoint, json))
        for fragment, payload in self.responses.items():
            if fragment in endpoint:
                return payload
        raise AssertionError(f"unexpected endpoint {endpoint}")


def instance_client(**overrides):
    responses = {
        "searchServer": fixture("wg_searchserver_rows"),
        "searchClient": fixture("wg_searchclient_rows"),
        "service/show": fixture("wg_service_show_rows"),
        "core/service/search": {
            "rows": [
                {
                    "id": "wireguard/6975c926-5a06-4b5c-aa6e-86e14f39cd76",
                    "running": 1,
                    "name": "wireguard",
                }
            ],
            "total": 1,
        },
    }
    responses.update(overrides)
    return FakeClient(responses)


def reconcile_client(**overrides):
    responses = {
        "searchServer": fixture("wg_searchserver_rows"),
        "searchClient": fixture("wg_searchclient_rows"),
        "service/show": fixture("wg_service_show_rows"),
        "interfaces_info": fixture("wg_interfaces_info_wg0"),
        "core/service/search": {"rows": [], "total": 0},
    }
    responses.update(overrides)
    return FakeClient(responses)


class ExplodingClient:
    """Raises the transport's own error shape: the response body, folded in.

    `utils.api` builds an APIError message out of the failing body, and a body
    with no named message key is carried whole. That is the path by which a
    cleartext private key reaches an error string.
    """

    def __init__(self, message: str) -> None:
        self.message = message

    async def _make_request(self, method, endpoint, json=None, **kwargs):
        raise RuntimeError(self.message)


@pytest.mark.parametrize(
    "tool_name",
    ["ListWgInstancesTool", "ListWgPeersTool", "ReconcileWgTool"],
)
@pytest.mark.asyncio
async def test_a_transport_error_carrying_a_key_is_redacted(tool_name, caplog) -> None:
    """The error branch returned the transport's text verbatim and logged it.

    Derived rather than written down, so this file carries no literal a reader
    could mistake for key material.
    """
    import base64
    import hashlib
    import logging

    import opnsense_mcp.tools.wireguard as wg

    key = base64.b64encode(hashlib.sha256(b"redaction probe").digest()).decode()
    assert key.endswith("=") and len(key) == 44

    tool = getattr(wg, tool_name)(ExplodingClient(f'API error: {{"privkey": "{key}"}}'))
    with caplog.at_level(logging.DEBUG, logger=wg.__name__):
        result = await tool.execute({})

    assert result["status"] == "error"
    assert key not in json.dumps(result)
    assert wg.REDACTED in result["error"]
    assert key not in caplog.text


def test_the_redactor_sees_the_escaped_spelling_a_php_body_arrives_in() -> None:
    """`json_encode` escapes '/', so a key can arrive as `a\\/b` and slip past a
    character class that stops at the backslash."""
    import base64
    import hashlib

    from opnsense_mcp.tools.wireguard import REDACTED, redact_keys

    key = next(
        candidate
        for candidate in (
            base64.b64encode(hashlib.sha256(f"slash {n}".encode()).digest()).decode()
            for n in range(200)
        )
        if "/" in candidate
    )

    assert redact_keys(f'{{"privkey": "{key}"}}') == f'{{"privkey": "{REDACTED}"}}'
    # The escaped spelling must be redacted too. Asserting only that the plain
    # key is absent proves nothing here: the escaped text does not contain it
    # either way, so the assertion passes with the unescape removed.
    escaped = key.replace("/", "\\/")
    assert redact_keys(f'{{"privkey": "{escaped}"}}') == f'{{"privkey": "{REDACTED}"}}'
    assert redact_keys("nothing key-shaped here") == "nothing key-shaped here"


@pytest.mark.asyncio
async def test_list_instances_returns_every_instance() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})

    assert result["status"] == "success"
    assert len(result["instances"]) == 3


@pytest.mark.asyncio
async def test_list_instances_never_returns_a_private_key() -> None:
    """No key field survives the allowlist, and no key value appears anywhere.

    Asserted on the keys and on the secret's own value rather than on the
    substring "privkey", which `has_privkey` legitimately contains.
    """
    import json as _json

    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    secret = fixture("wg_searchserver_rows")["rows"][0]["privkey"]
    assert secret, "fixture no longer carries the field being guarded"

    result = await ListWgInstancesTool(instance_client()).execute({})
    text = _json.dumps(result)

    for instance in result["instances"]:
        assert "privkey" not in instance
        assert "pubkey" not in instance
    assert secret not in text
    assert all(i["has_privkey"] is True for i in result["instances"])


@pytest.mark.asyncio
async def test_list_instances_reports_a_dangling_peer_rather_than_dropping_it() -> None:
    """One instance names a peer uuid that no client record matches.

    Search reports one peer, get reports zero, and getClient on the uuid returns
    an empty array. All three answer HTTP 200 with no error, so a join that
    assumes 1:1 loses the reference silently.
    """
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    wg1 = next(i for i in result["instances"] if i["name"] == "wg1RemoteLabUsers")

    assert wg1["peer_uuids"] == ["9d08d591-4556-4df2-bf87-dcf1679e2776"]
    assert wg1["dangling_peers"] == ["9d08d591-4556-4df2-bf87-dcf1679e2776"]


@pytest.mark.asyncio
async def test_membership_survives_a_missing_resolved_key() -> None:
    """`%peers` is absent, not empty, on the instance whose peer resolves to
    nothing. Indexing it raises on exactly the instance most worth reporting."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    wg1 = next(i for i in result["instances"] if i["name"] == "wg1RemoteLabUsers")

    assert wg1["peer_names"] == []
    assert wg1["peer_uuids"]


@pytest.mark.asyncio
async def test_only_the_enabled_instance_reports_running() -> None:
    """Disabled instances are absent from every runtime view, so absence has two
    causes and only the config's `enabled` separates them."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    by_name = {i["name"]: i for i in result["instances"]}

    assert by_name["wg0HomeVpn"]["running"] is True
    assert by_name["wg1RemoteLabUsers"]["running"] is False
    assert by_name["wg1RemoteLabUsers"]["enabled"] == "0"
    assert all(i["running_disagrees"] is False for i in result["instances"])


@pytest.mark.asyncio
async def test_a_running_signal_the_service_grid_contradicts_is_reported() -> None:
    """`running` is read out of a row id from `/api/core/service/search`, which
    no fixture captures. A change in that id format reports every instance as
    stopped and nothing in the row says so; the kernel interface row's `status`
    is the one independent signal, so a disagreement is reported rather than
    resolved silently."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    # The id without the `wireguard/` prefix: the shape the parser assumes,
    # spelled the other plausible way.
    client = instance_client(
        **{
            "core/service/search": {
                "rows": [
                    {
                        "id": "6975c926-5a06-4b5c-aa6e-86e14f39cd76",
                        "running": 1,
                        "name": "wireguard",
                    }
                ],
                "total": 1,
            }
        }
    )
    result = await ListWgInstancesTool(client).execute({})
    wg0 = next(i for i in result["instances"] if i["name"] == "wg0HomeVpn")

    assert wg0["running"] is False
    assert wg0["device_status"] == "up"
    assert wg0["running_disagrees"] is True


@pytest.mark.asyncio
async def test_the_site_to_site_instance_is_labelled_with_its_evidence() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    s2s = next(i for i in result["instances"] if i["name"] == "wg2SiteToSite")

    # Every instance, not only the one that is genuinely site-to-site: a shape
    # function that returns a constant satisfies a single-instance assertion.
    assert {i["name"]: i["shape"] for i in result["instances"]} == {
        "wg0HomeVpn": "road_warrior",
        "wg1RemoteLabUsers": "unknown",
        "wg2SiteToSite": "site_to_site",
    }
    assert "disableroutes=1" in s2s["shape_evidence"]
    assert any(e.startswith("gateway=") for e in s2s["shape_evidence"])


@pytest.mark.asyncio
async def test_an_instance_can_be_selected_by_uuid() -> None:
    """The schema declares `uuid` as well as `name`. An undeclared selector is
    accepted and ignored, so asking for one instance returns every one."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute(
        {"uuid": "6975c926-5a06-4b5c-aa6e-86e14f39cd76"}
    )

    assert [i["name"] for i in result["instances"]] == ["wg0HomeVpn"]
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_a_truncated_listing_is_refused_rather_than_returned() -> None:
    """Asserted on the structure, not the wording: a refusal that also hands
    back the partial view it refused satisfies a message check."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    client = instance_client(searchServer={"rows": [], "total": 3})
    result = await ListWgInstancesTool(client).execute({})

    assert result["status"] == "error"
    assert "instances" not in result
    assert "count" not in result


@pytest.mark.asyncio
async def test_no_listing_call_sends_a_rowcount() -> None:
    """Sending one is what makes total exceed the rows returned.

    Every tool, and the filtered peer call as well: that is the only path that
    builds a non-empty body, and it is where a `rowCount` would be added.
    """
    from opnsense_mcp.tools.wireguard import (
        ListWgInstancesTool,
        ListWgPeersTool,
        ReconcileWgTool,
    )

    runs = [
        (ListWgInstancesTool, instance_client(), {}),
        (ListWgPeersTool, instance_client(), {}),
        (ListWgPeersTool, instance_client(), {"instance": "wg0HomeVpn"}),
        (ReconcileWgTool, reconcile_client(), {}),
    ]
    seen = 0
    for tool, client, params in runs:
        await tool(client).execute(params)
        assert client.calls
        for _method, _endpoint, body in client.calls:
            assert "rowCount" not in (body or {})
            seen += 1
    assert seen >= len(runs)


@pytest.mark.asyncio
async def test_list_peers_returns_every_peer() -> None:
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})

    assert result["status"] == "success"
    assert len(result["peers"]) == 11


def test_an_interface_row_is_not_reported_as_a_peer() -> None:
    """service/show returns one array with two row schemas keyed by `type`.

    The interface row carries a plausible name and peer-status 'offline', so a
    normalizer that skips the type check reports the instance itself as an extra
    permanently-offline peer.

    Asserted on `runtime_by_peer` rather than on the tool's output. The tool
    lists config rows and joins runtime onto them by name, so an unfiltered
    interface row lands in the runtime map with nothing to match it and the
    tool's peer names do not change: the leak is only visible one layer down.
    """
    from opnsense_mcp.tools.wireguard import runtime_by_peer

    rows = fixture("wg_service_show_rows")["rows"]
    interfaces = [r for r in rows if r.get("type") == "interface"]
    assert interfaces, "fixture no longer carries the interface row being guarded"

    runtime = runtime_by_peer(rows)

    assert [r["name"] for r in interfaces] == ["wg0HomeVpn"]
    assert "wg0HomeVpn" not in runtime
    assert len(runtime) == len(rows) - len(interfaces)


@pytest.mark.asyncio
async def test_a_peer_that_never_connected_is_not_reported_as_connected() -> None:
    """Every never-connected peer carries non-zero transfer-tx against zero rx,
    so a `tx > 0` health check calls all of them healthy. Only the handshake
    separates 'never connected' from 'connected and now idle'."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})
    by_name = {p["name"]: p for p in result["peers"]}

    quiet = by_name["peerB"]
    assert quiet["runtime"]["transfer_tx"] > 0
    assert quiet["runtime"]["connected"] is False

    live = by_name["peerA"]
    assert live["runtime"]["connected"] is True


@pytest.mark.asyncio
async def test_a_peer_on_a_disabled_instance_reports_no_runtime_with_a_reason() -> None:
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})
    s2s = next(p for p in result["peers"] if p["name"] == "wg2SiteToSite")

    assert s2s["runtime"] is None
    # Which reason, not merely that there is one. Both reasons are truthy
    # strings, so `assert runtime_absent` passes whichever branch produced it.
    assert s2s["runtime_absent_reason"] == "instance_disabled"
    assert s2s["runtime_absent"]


@pytest.mark.asyncio
async def test_a_peer_the_kernel_does_not_hold_says_so_rather_than_disabled() -> None:
    """The mirror case: an enabled instance whose peer has no kernel row."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    clients = fixture("wg_searchclient_rows")
    ghost = {
        **clients["rows"][0],
        "uuid": "1c0ffee0-0000-4000-8000-00000000beef",
        "name": "peerNeverLoaded",
        "servers": "6975c926-5a06-4b5c-aa6e-86e14f39cd76",
        "%servers": "wg0HomeVpn",
        "tunneladdress": "192.168.10.99/32",
    }
    payload = {"rows": [*clients["rows"], ghost], "total": clients["total"] + 1}

    result = await ListWgPeersTool(instance_client(searchClient=payload)).execute({})
    row = next(p for p in result["peers"] if p["name"] == "peerNeverLoaded")

    assert row["runtime"] is None
    assert row["runtime_absent_reason"] == "no_kernel_peer"


@pytest.mark.asyncio
async def test_the_kernel_sentinel_for_no_endpoint_is_not_reported_as_one() -> None:
    """`wg show` writes "(none)" for a peer it has never heard from, and a
    non-empty string reads as an endpoint to every caller. The one runtime
    field whose non-emptiness would otherwise prove nothing."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    raw = {
        row["name"]: row.get("endpoint")
        for row in fixture("wg_service_show_rows")["rows"]
        if row.get("type") == "peer"
    }
    assert raw["peerB"] == "(none)", "fixture no longer carries the sentinel"

    result = await ListWgPeersTool(instance_client()).execute({})
    by_name = {p["name"]: p for p in result["peers"]}

    assert by_name["peerB"]["runtime"]["endpoint"] == ""
    assert by_name["peerA"]["runtime"]["endpoint"] == raw["peerA"]


@pytest.mark.asyncio
async def test_peers_can_be_filtered_by_instance_and_the_filter_is_verified() -> None:
    """A 200 is not evidence a filter applied: unknown parameters are accepted
    and ignored on every grid. The filter key is `servers`, and it must be an
    array; a bare string returns HTTP 500.

    Asserted on the resolved uuid rather than on the key's type, because `[]` is
    a list too and is what a name lookup that resolved nothing sends.
    """
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    client = instance_client()
    await ListWgPeersTool(client).execute({"instance": "wg0HomeVpn"})

    bodies = [body for _m, endpoint, body in client.calls if "searchClient" in endpoint]
    assert [b["servers"] for b in bodies] == [["6975c926-5a06-4b5c-aa6e-86e14f39cd76"]]


@pytest.mark.asyncio
async def test_a_filter_the_grid_ignored_still_narrows_the_answer() -> None:
    """FakeClient answers by endpoint and ignores the body, which is exactly the
    grid that accepts a filter parameter and applies nothing. The filtered count
    has to differ from the unfiltered one, or the tool is reporting every peer
    on the firewall as one instance's."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    everything = await ListWgPeersTool(instance_client()).execute({})
    filtered = await ListWgPeersTool(instance_client()).execute(
        {"instance": "wg2SiteToSite"}
    )

    assert everything["count"] == 11
    assert filtered["count"] == 1
    assert [p["name"] for p in filtered["peers"]] == ["wg2SiteToSite"]


@pytest.mark.asyncio
async def test_an_instance_name_that_resolves_to_nothing_is_refused() -> None:
    """An empty `servers` array is the idiom for no filter, so sending one for a
    name that matched no instance asks for every peer on the box and reports the
    answer as that instance's peers."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    client = instance_client()
    result = await ListWgPeersTool(client).execute({"instance": "wg9NoSuchInstance"})

    assert result["status"] == "error"
    assert "peers" not in result
    bodies = [body for _m, endpoint, body in client.calls if "searchClient" in endpoint]
    assert not [b for b in bodies if (b or {}).get("servers") == []]


@pytest.mark.asyncio
async def test_list_peers_never_returns_key_material() -> None:
    """No key field survives the allowlist, and no key value appears anywhere.

    Asserted on the keys and on the secrets' own values rather than on the
    substring "psk", which `has_psk` legitimately contains.
    """
    import json as _json

    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    secrets = {
        row[field]
        for row in fixture("wg_searchclient_rows")["rows"]
        for field in ("pubkey", "psk", "privkey")
        if row.get(field)
    }
    secrets |= {
        row["public-key"]
        for row in fixture("wg_service_show_rows")["rows"]
        if row.get("public-key")
    }
    assert secrets, "fixtures no longer carry the fields being guarded"

    result = await ListWgPeersTool(instance_client()).execute({})
    text = _json.dumps(result)

    for peer in result["peers"]:
        assert "privkey" not in peer
        assert "psk" not in peer
        assert "pubkey" not in peer
        assert "public-key" not in (peer["runtime"] or {})
    for secret in secrets:
        assert secret not in text


def _two_peers_named_the_same() -> dict:
    """The captured state plus a second peerA, on a second enabled instance.

    Peer names are unique per instance at most. Both sides of the join used to
    key on the name alone, so the second row overwrote the first.
    """
    servers = fixture("wg_searchserver_rows")
    servers["rows"] = [
        dict(s, enabled="1", tunneladdress="192.168.11.1/24", peers="deadbeef-0000")
        if s["name"] == "wg1RemoteLabUsers"
        else s
        for s in servers["rows"]
    ]
    clients = fixture("wg_searchclient_rows")
    twin = {
        **clients["rows"][0],
        "uuid": "deadbeef-0000",
        "name": "peerA",
        "servers": "00524b42-93b5-455f-982f-8c7c4174ab73",
        "%servers": "wg1RemoteLabUsers",
        "tunneladdress": "192.168.11.7/32",
    }
    clients = {"rows": [*clients["rows"], twin], "total": clients["total"] + 1}
    show = fixture("wg_service_show_rows")
    kernel_twin = {
        **next(r for r in show["rows"] if r.get("name") == "peerA"),
        "if": "wg1",
        "ifname": "wg1RemoteLabUsers",
        "endpoint": "203.0.113.9:51820",
        "allowed-ips": "192.168.11.7/32",
    }
    show = {"rows": [*show["rows"], kernel_twin], "total": show["total"] + 1}
    return {"searchServer": servers, "searchClient": clients, "service/show": show}


@pytest.mark.asyncio
async def test_two_peers_of_the_same_name_keep_their_own_runtime() -> None:
    """Keyed on the name alone, the wg0 peer was handed the wg1 peer's live
    handshake, endpoint and counters, on a device it is not on."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(
        instance_client(**_two_peers_named_the_same())
    ).execute({})
    rows = {p["uuid"]: p for p in result["peers"] if p["name"] == "peerA"}

    assert len(rows) == 2
    original = rows["29ef8042-324a-44fa-b2d3-68da44727b23"]
    twin = rows["deadbeef-0000"]
    assert original["runtime"]["device"] == "wg0"
    assert original["runtime"]["kernel_allowed_ips"] == ["192.168.10.3/32"]
    assert original["runtime"]["endpoint"] == "172.20.8.13:64651"
    assert twin["runtime"]["device"] == "wg1"
    assert twin["runtime"]["kernel_allowed_ips"] == ["192.168.11.7/32"]


@pytest.mark.asyncio
async def test_two_peers_of_the_same_name_are_not_reported_as_drift() -> None:
    """Each kernel row was compared against whichever config row survived the
    name-keyed map, so a correct peer read as drift."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(
        reconcile_client(**_two_peers_named_the_same())
    ).execute({})
    rows = [
        r
        for r in result["results"]
        if r["check"] == "kernel_matches_config" and r["peer"] == "peerA"
    ]

    assert len(rows) == 2
    assert {r["outcome"] for r in rows} == {"current"}


def test_classify_entry_calls_a_host_route_inside_its_network_current() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])

    assert classify_entry("192.168.10.7/32", nets)[0] == "current"
    assert classify_entry("fd0b:cafe:f::2/128", nets)[0] == "current"


def test_classify_entry_calls_a_host_route_outside_its_network_drifted() -> None:
    """The case the tool exists for: a peer left on a prefix the instance no
    longer carries."""
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])

    outcome, detail = classify_entry("2001:db8:5eed:b7ef::80/128", nets)

    assert outcome == "drifted"
    assert "2001:db8:5eed:b7ef::80/128" in detail


def test_classify_entry_calls_a_wider_network_a_routed_prefix() -> None:
    """The site-to-site remote LAN sits outside the tunnel network and is
    correct. Containment alone would call it drift, so prefix width is what
    separates an address on the tunnel from a network routed through it."""
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["172.20.181.2/24"])

    assert classify_entry("192.168.99.0/24", nets)[0] == "routed_prefix"
    assert classify_entry("172.20.181.1/32", nets)[0] == "current"


def test_classify_entry_reports_a_family_the_instance_does_not_carry() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.11.1"])

    assert classify_entry("fd0b:cafe:f::2/128", nets)[0] == "no_interface"


def test_classify_entry_cannot_judge_a_tunnel_address_with_no_prefix_length() -> None:
    """A bare address states an address, not a network. Read as a /32 it makes
    every peer of that instance a host route outside its own tunnel, which is
    drift manufactured from a healthy config."""
    from opnsense_mcp.tools.wireguard import bare_networks, classify_entry, networks_of

    entries = ["192.168.11.1"]
    nets, bare = networks_of(entries), bare_networks(entries)

    assert classify_entry("192.168.11.5/32", nets, bare)[0] == "no_prefix_length"
    assert classify_entry("192.168.11.1/32", nets, bare)[0] == "current"

    # An instance that also carries a real network is judged against that one.
    both = ["192.168.11.1", "192.168.10.1/24"]
    assert (
        classify_entry("192.168.11.5/32", networks_of(both), bare_networks(both))[0]
        == "drifted"
    )


def test_classify_entry_reports_an_unreadable_address() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    assert classify_entry("not-an-address", networks_of(["192.168.10.1/24"]))[0] == (
        "unreadable_address"
    )


@pytest.mark.asyncio
async def test_reconcile_reports_no_drift_on_the_captured_state() -> None:
    """Every peer on the box is currently inside its instance network. A tool
    that manufactures drift here is worse than one that finds none."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})

    assert result["status"] == "success"
    assert result["counts"]["drifted"] == 0


@pytest.mark.asyncio
async def test_the_site_to_site_remote_lan_is_not_reported_as_drift() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    entries = [
        r
        for r in result["results"]
        if r["check"] == "peer_containment" and r["entry"] == "192.168.99.0/24"
    ]

    assert entries, "the site-to-site remote LAN is missing from the report"
    assert entries[0]["outcome"] == "routed_prefix"


@pytest.mark.asyncio
async def test_reconcile_status_says_the_audit_ran_not_what_it_found() -> None:
    """A run that finds problems still ran. Severity belongs in the payload,
    or a caller cannot tell a finding from a failure to look."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})

    assert result["status"] == "success"
    assert "counts" in result


@pytest.mark.asyncio
async def test_the_counts_are_the_rows_they_summarise() -> None:
    """`counts` is what a caller reads to decide whether there is drift, and a
    constant `{"current": 0, "drifted": 0}` satisfies both `drifted == 0` and
    `"counts" in result`. Asserted against the rows, and by name on every
    outcome the captured state produces."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})

    tallied = collections.Counter(r["outcome"] for r in result["results"])
    tallied.setdefault("current", 0)
    tallied.setdefault("drifted", 0)

    assert result["checked"] == len(result["results"])
    assert result["counts"] == dict(tallied)
    assert result["counts"] == {
        "current": 26,
        "routed_prefix": 1,
        "unaccounted_address": 1,
        "instance_disabled": 4,
        "stale_route": 2,
        "route_covered_by_prefix": 1,
        "dangling_peer": 1,
        "drifted": 0,
    }


@pytest.mark.asyncio
async def test_no_peer_of_an_instance_with_a_bare_address_is_reported_as_drift() -> (
    None
):
    """wg1RemoteLabUsers carries `192.168.11.1`, with no prefix length, as its
    whole tunnel address. Read as a /32, every peer of it is a host route
    outside its own tunnel and a healthy road-warrior instance produces one
    fabricated drift finding per peer.

    `enabled` stays at the captured `0`: containment joins on membership and
    never reads it, so one client row is all that stands between this and a
    wrong report. Today that row does not exist, which is the only reason the
    captured state looks clean."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    clients = fixture("wg_searchclient_rows")
    lab = {
        **clients["rows"][0],
        "uuid": "4b0d2c17-8f31-4a55-9d20-1f6a7c3e5b8a",
        "name": "labUserA",
        "servers": "00524b42-93b5-455f-982f-8c7c4174ab73",
        "%servers": "wg1RemoteLabUsers",
        "tunneladdress": "192.168.11.5/32",
    }
    payload = {"rows": [*clients["rows"], lab], "total": clients["total"] + 1}

    result = await ReconcileWgTool(reconcile_client(searchClient=payload)).execute({})
    rows = [r for r in result["results"] if r.get("peer") == "labUserA"]

    assert [r["outcome"] for r in rows] == ["no_prefix_length"]
    assert result["counts"]["drifted"] == 0


@pytest.mark.asyncio
async def test_reconcile_never_returns_key_material() -> None:
    """The one tool that holds all four raw payloads at once: instance rows
    carrying `privkey`, peer rows carrying `psk`, and kernel rows carrying
    `public-key`. Every finding is a free-form detail string built from row
    content, so this is where a whole row reaches the output."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    secrets = {
        row[field]
        for name in ("wg_searchserver_rows", "wg_searchclient_rows")
        for row in fixture(name)["rows"]
        for field in ("privkey", "pubkey", "psk")
        if row.get(field)
    }
    secrets |= {
        row["public-key"]
        for row in fixture("wg_service_show_rows")["rows"]
        if row.get("public-key")
    }
    assert secrets, "fixtures no longer carry the fields being guarded"

    result = await ReconcileWgTool(reconcile_client()).execute({})
    text = json.dumps(result)

    for secret in secrets:
        assert secret not in text
    for field in ("privkey", "pubkey", "psk", "public-key"):
        assert f'"{field}"' not in text


@pytest.mark.asyncio
async def test_reconcile_calls_only_the_four_read_endpoints() -> None:
    """An allowlist, not a list of write verbs.

    A blacklist of `/add`, `/set`, `/del` and friends says nothing about
    `service/restart`, which drops every peer session on the box and is the
    call this report-only tool most needs never to make.
    """
    from opnsense_mcp.tools.wireguard import (
        INTERFACES,
        WG_CLIENT,
        WG_SERVER,
        WG_SERVICE,
        ReconcileWgTool,
    )

    client = reconcile_client()
    await ReconcileWgTool(client).execute({})

    allowed = {
        WG_SERVER["search"],
        WG_CLIENT["search"],
        WG_SERVICE["show"],
        INTERFACES,
    }
    assert client.calls
    assert {endpoint for _m, endpoint, _b in client.calls} <= allowed


@pytest.mark.asyncio
async def test_an_address_no_config_accounts_for_is_reported() -> None:
    """The captured device holds an address that neither the instance's tunnel
    address nor the interface assignment claims."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [
        r
        for r in result["results"]
        if r["check"] == "address_liveness" and r["outcome"] == "unaccounted_address"
    ]

    assert [r["entry"] for r in rows] == ["2001:db8:5eed:b50f::1/64"]


@pytest.mark.asyncio
async def test_the_check_is_not_keyed_on_what_a_prefix_looks_like() -> None:
    """The delegated prefix is live and nine interfaces track it. A rule keyed
    on the prefix would flag all of them and miss the real defect, so a device
    whose config claims its address is current whatever the prefix is."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    fixture_rows = fixture("wg_interfaces_info_wg0")
    device = fixture_rows["rows"][0]
    device["ipv6"] = [{"ipaddr": "2001:db8:5eed:b50f::1/64"}]
    # The captured shape: the address bare, its width in its own key.
    device["config"] = dict(
        device["config"], ipaddrv6="2001:db8:5eed:b50f::1", subnetv6="64"
    )

    result = await ReconcileWgTool(
        reconcile_client(interfaces_info=fixture_rows)
    ).execute({})

    assert not [r for r in result["results"] if r["outcome"] == "unaccounted_address"]
    # And the same address is not simultaneously a stale route. Check B read
    # the interface assignment while check C read only the tunnel address, so
    # one state produced two opposite verdicts in one report.
    assert not [
        r
        for r in result["results"]
        if r["outcome"] == "stale_route" and r["entry"] == "2001:db8:5eed:b50f::/64"
    ]


def test_an_assignment_keeps_its_prefix_length_in_its_own_key() -> None:
    """`interfaces_info` sends `ipaddr` bare with the width under `subnet`.

    Read as an address alone, an assignment becomes a /32 and a second address
    in the same subnet — an ipalias VIP is the usual one — is reported as
    accounted for by nothing.
    """
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    device = {
        "device": "wg9",
        "config": {"if": "wg9", "ipaddr": "192.0.2.1", "subnet": "24"},
    }

    assert [str(n) for n in ReconcileWgTool._config_networks(device, [])] == [
        "192.0.2.0/24"
    ]

    servers = {
        "rows": [
            {
                "uuid": "9999",
                "name": "wg9Probe",
                "enabled": "1",
                "interface": "wg9",
                "tunneladdress": "192.0.2.1/24",
                "peers": "",
            }
        ],
        "total": 1,
    }
    devices = {
        "rows": [
            {
                **device,
                "routes": [],
                # The VIP: a second address inside the assigned subnet.
                "ipv4": [{"ipaddr": "192.0.2.1/24"}, {"ipaddr": "192.0.2.200/24"}],
                "ipv6": [],
            }
        ],
        "total": 1,
    }
    rows = ReconcileWgTool(None)._address_liveness(servers["rows"], devices["rows"])

    assert [r["outcome"] for r in rows] == ["current", "current"]


@pytest.mark.asyncio
async def test_a_route_with_no_allowed_ip_behind_it_is_reported() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r["outcome"] == "stale_route"]

    assert "2001:db8:5eed:b7ef::80" in {r["entry"] for r in rows}


@pytest.mark.asyncio
async def test_an_allowed_ip_a_wider_route_covers_says_which_route() -> None:
    """The mirror-image direction, and the distinction the wording used to lose.

    `fd0b:cafe:f::2/128` has no route of its own and is reachable anyway: the
    tunnel's own connected /64 is on the same device and crypto-routing
    dispatches on the allowed IP. Reporting it as "no route reaches it" states
    a reachability conclusion the comparison never tested, and every IPv6 peer
    on the instance adds one more of them.
    """
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    covered = {
        r["entry"]: r
        for r in result["results"]
        if r["outcome"] == "route_covered_by_prefix"
    }

    assert "fd0b:cafe:f::2/128" in covered
    assert covered["fd0b:cafe:f::2/128"]["covered_by"] == ["fd0b:cafe:f::/64"]
    assert not [r for r in result["results"] if r["outcome"] == "missing_route"]


@pytest.mark.asyncio
async def test_an_allowed_ip_no_route_covers_is_still_reported_as_missing() -> None:
    """The other half: nothing on the device reaches it, so the row stands."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    devices = fixture("wg_interfaces_info_wg0")
    devices["rows"][0]["routes"] = [
        r for r in devices["rows"][0]["routes"] if r != "fd0b:cafe:f::/64"
    ]

    result = await ReconcileWgTool(reconcile_client(interfaces_info=devices)).execute(
        {}
    )
    rows = [r for r in result["results"] if r["outcome"] == "missing_route"]

    assert "fd0b:cafe:f::2/128" in {r["entry"] for r in rows}


@pytest.mark.asyncio
async def test_kernel_and_config_allowed_ips_compare_as_sets() -> None:
    """The kernel emits v6 first and the config preserves entry order, so a
    string comparator passes all nine single-stack peers and fails only on the
    dual-stack one."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [
        r
        for r in result["results"]
        if r["check"] == "kernel_matches_config" and r["peer"] == "dualStackPeer"
    ]

    assert rows and rows[0]["outcome"] == "current"


@pytest.mark.asyncio
async def test_a_disabled_instance_absent_from_the_kernel_is_not_a_fault() -> None:
    """Disabled instances are absent from every runtime view with no
    placeholder, so absence has two causes and only `enabled` separates them."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r.get("instance") == "wg2SiteToSite"]

    # Per check. `any(... == "instance_disabled")` was satisfied by either of
    # the two checks, so losing the gate in one of them changed nothing here.
    assert {r["check"]: r["outcome"] for r in rows} == {
        "address_liveness": "instance_disabled",
        "route_crosscheck": "instance_disabled",
    }
    assert len(rows) == 2


# --- outcomes the captured state never produces ----------------------------
#
# Five reconcile branches emit nothing against the fixtures, so each could be
# deleted outright with the whole suite green. Each is a few hand-built rows
# away, driven through the check method rather than through a fixture that
# cannot hold the state.


def _reconcile() -> object:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    return ReconcileWgTool(None)


def test_an_enabled_instance_with_no_device_is_reported_absent() -> None:
    server = {
        "uuid": "1",
        "name": "wg9Probe",
        "enabled": "1",
        "interface": "wg9",
        "tunneladdress": "192.0.2.1/24",
    }
    rows = _reconcile()._address_liveness([server], [])

    assert [r["outcome"] for r in rows] == ["device_absent"]
    assert "wg9" in rows[0]["detail"]


def test_a_configured_address_the_device_does_not_hold_is_reported() -> None:
    server = {
        "uuid": "1",
        "name": "wg9Probe",
        "enabled": "1",
        "interface": "wg9",
        "tunneladdress": "192.0.2.1/24,fd0b:9::1/64",
    }
    device = {"device": "wg9", "config": {}, "ipv4": [], "ipv6": [], "routes": []}
    rows = _reconcile()._address_liveness([server], [device])

    assert [r["outcome"] for r in rows] == ["missing_address", "missing_address"]
    assert {r["entry"] for r in rows} == {"192.0.2.1/24", "fd0b:9::1/64"}


def test_an_address_the_device_reports_unreadably_is_reported() -> None:
    server = {
        "uuid": "1",
        "name": "wg9Probe",
        "enabled": "1",
        "interface": "wg9",
        "tunneladdress": "",
    }
    device = {
        "device": "wg9",
        "config": {},
        "ipv4": [{"ipaddr": "not-an-address"}],
        "ipv6": [],
        "routes": [],
    }
    rows = _reconcile()._address_liveness([server], [device])

    assert [r["outcome"] for r in rows] == ["unreadable_address"]


def test_a_link_local_address_is_not_a_finding() -> None:
    """Every WireGuard device carries one and no config ever accounts for it,
    so without the skip each one is a permanent unaccounted_address. No
    captured device holds an fe80 address, so nothing else exercises it."""
    server = {
        "uuid": "1",
        "name": "wg9Probe",
        "enabled": "1",
        "interface": "wg9",
        "tunneladdress": "192.0.2.1/24",
    }
    device = {
        "device": "wg9",
        "config": {},
        "ipv4": [{"ipaddr": "192.0.2.1/24"}],
        "ipv6": [{"ipaddr": "fe80::1/64"}],
        "routes": [],
    }
    rows = _reconcile()._address_liveness([server], [device])

    assert [r["outcome"] for r in rows] == ["current"]


def test_a_peer_belonging_to_no_instance_is_one_finding_not_one_per_address() -> None:
    """The summary row used to be emitted on top of a `no_interface` row per
    address, so one membership problem read as N+1 problems and inflated both
    `checked` and the counts by N."""
    peer = {
        "uuid": "orphan",
        "name": "orphanPeer",
        "servers": "",
        "tunneladdress": "192.168.77.5/32,192.168.77.6/32",
    }
    rows = _reconcile()._peer_containment([], [peer])

    assert len(rows) == 2
    assert {r["outcome"] for r in rows} == {"no_interface"}
    # And the detail does not blame an instance that does not exist.
    assert all("belongs to no instance" in r["detail"] for r in rows)


def test_a_kernel_peer_no_config_row_matches_is_reported() -> None:
    ghost = {
        "type": "peer",
        "if": "wg0",
        "name": "ghostPeer",
        "allowed-ips": "192.168.10.44/32",
    }
    rows = _reconcile()._route_crosscheck([], [ghost], [], [])

    assert [r["outcome"] for r in rows] == ["dangling_peer"]
    assert "ghostPeer" in rows[0]["detail"]


def test_an_instance_naming_a_peer_that_does_not_exist_is_reported() -> None:
    """The other direction, and the one the captured state holds: an instance
    names a peer uuid no client record has. Only the kernel side was checked,
    so the live case produced no finding at all."""
    server = {
        "uuid": "1",
        "name": "wg9Probe",
        "enabled": "1",
        "interface": "wg9",
        "tunneladdress": "192.0.2.1/24",
        "peers": "no-such-uuid",
    }
    rows = _reconcile()._peer_containment([server], [])

    assert [r["outcome"] for r in rows] == ["dangling_peer"]
    assert rows[0]["peer_uuid"] == "no-such-uuid"


def test_a_kernel_peer_whose_allowed_ips_disagree_with_its_config_is_drift() -> None:
    """The verdict the tool exists for. Every captured peer agrees, so the
    comparison could be replaced by the constant "current" with the whole
    suite green."""
    kernel = {
        "type": "peer",
        "if": "wg9",
        "name": "peerZ",
        "allowed-ips": "192.0.2.7/32",
    }
    config = {
        "uuid": "z",
        "name": "peerZ",
        "servers": "1",
        "tunneladdress": "192.0.2.8/32",
    }
    server = {"uuid": "1", "name": "wg9Probe", "enabled": "1", "interface": "wg9"}
    rows = _reconcile()._route_crosscheck(
        [],
        [kernel],
        [],
        [config],
    )

    # Without the server row the peer's device is unknown, so it reads as
    # dangling; the drift verdict needs both sides on the same device.
    assert [r["outcome"] for r in rows] == ["dangling_peer"]

    rows = _reconcile()._route_crosscheck([server], [kernel], [], [config])
    drift = [r for r in rows if r["check"] == "kernel_matches_config"]

    assert [r["outcome"] for r in drift] == ["drifted"]
    assert "192.0.2.7/32" in drift[0]["detail"]
    assert "192.0.2.8/32" in drift[0]["detail"]


def test_two_unreadable_allowed_ips_do_not_compare_equal() -> None:
    """Both sides parsed to None and the sets matched, so the one case nobody
    can judge was reported as agreement."""
    kernel = {
        "type": "peer",
        "if": "wg9",
        "name": "peerZ",
        "allowed-ips": "192.0.2.7/32,kernel-junk",
    }
    config = {
        "uuid": "z",
        "name": "peerZ",
        "servers": "1",
        "tunneladdress": "192.0.2.7/32,config-junk",
    }
    server = {"uuid": "1", "name": "wg9Probe", "enabled": "1", "interface": "wg9"}
    rows = [
        r
        for r in _reconcile()._route_crosscheck([server], [kernel], [], [config])
        if r["check"] == "kernel_matches_config"
    ]

    assert [r["outcome"] for r in rows] == ["unreadable_address"]
    assert "kernel-junk" in rows[0]["detail"]
    assert "config-junk" in rows[0]["detail"]
    # And the string 'None' never reaches a detail: no field on the firewall
    # ever held it.
    assert "None" not in rows[0]["detail"]


def test_the_wireguard_group_exposes_every_tool() -> None:
    from opnsense_mcp.utils.tool_groups import GROUPS

    description, actions = GROUPS["wireguard"]

    assert description
    assert actions == {
        "list_instances": "list_wg_instances",
        "list_peers": "list_wg_peers",
        "reconcile": "reconcile_wg",
    }


def test_no_wireguard_member_declares_a_field_named_action() -> None:
    """The group pops `action` to pick the member, so a member declaring its own
    would never receive one."""
    from opnsense_mcp.tools.wireguard import (
        ListWgInstancesTool,
        ListWgPeersTool,
        ReconcileWgTool,
    )

    for tool in (ListWgInstancesTool, ListWgPeersTool, ReconcileWgTool):
        assert "action" not in tool.input_schema["properties"]


def test_every_wireguard_tool_is_registered() -> None:
    from opnsense_mcp.utils.registry import TOOL_CLASSES

    names = {getattr(cls, "name", "") for cls in TOOL_CLASSES}

    assert {"list_wg_instances", "list_wg_peers", "reconcile_wg"} <= names
