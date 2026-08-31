"""WireGuard parsing, tested against responses captured from 26.7.3.

Every test here pins a way the API can be misread while raising nothing. The
search grid and the get node tree share field names and disagree on types for
four of them; a peer's Allowed-IPs live in a field called `tunneladdress` while
a field named `allowed_ips` exists only on servers and is empty on every row;
and both read paths hand back the instance private key unasked.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from opnsense_mcp.tools.wireguard import (
    TruncatedListing,
    get_path,
    is_host_route,
    networks_of,
    public_instance,
    public_peer,
    record_or_none,
    rows_or_refuse,
    selected_keys,
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
    with pytest.raises(TruncatedListing):
        rows_or_refuse({"rows": [{"uuid": "a"}], "total": 9}, "instances")


def test_rows_or_refuse_refuses_a_payload_that_is_not_a_search_result() -> None:
    with pytest.raises(TruncatedListing):
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


def test_selected_keys_ignores_unselected_options_and_the_empty_key() -> None:
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
    assert selected_keys(node) == ["a"]
    assert selected_keys({}) == []
    assert selected_keys("not a node map") == []


def test_the_dangling_instance_has_no_selected_peers() -> None:
    """The live disagreement, straight from the fixture."""
    record = record_or_none(fixture("wg_getserver_dangling"), "server")
    assert record is not None
    assert len(record["peers"]) == 11
    assert selected_keys(record["peers"]) == []


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


def test_public_peer_omits_every_key_field() -> None:
    row = rows_or_refuse(fixture("wg_searchclient_rows"), "peers")[0]
    public = public_peer(row)
    assert "privkey" not in public
    assert "psk" not in public
    assert "pubkey" not in public


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


@pytest.mark.asyncio
async def test_the_site_to_site_instance_is_labelled_with_its_evidence() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    s2s = next(i for i in result["instances"] if i["name"] == "wg2SiteToSite")

    assert s2s["shape"] == "site_to_site"
    assert s2s["shape_evidence"], "a label without its evidence is a guess"


@pytest.mark.asyncio
async def test_a_truncated_listing_is_refused_rather_than_returned() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    client = instance_client(searchServer={"rows": [], "total": 3})
    result = await ListWgInstancesTool(client).execute({})

    assert result["status"] == "error"
    assert "truncated" in result["error"]


@pytest.mark.asyncio
async def test_no_listing_call_sends_a_rowcount() -> None:
    """Sending one is what makes total exceed the rows returned."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    client = instance_client()
    await ListWgInstancesTool(client).execute({})

    for _method, _endpoint, body in client.calls:
        assert "rowCount" not in (body or {})


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

    Asserted on `runtime_by_name` rather than on the tool's output. The tool
    lists config rows and joins runtime onto them by name, so an unfiltered
    interface row lands in the runtime map with nothing to match it and the
    tool's peer names do not change: the leak is only visible one layer down.
    """
    from opnsense_mcp.tools.wireguard import runtime_by_name

    rows = fixture("wg_service_show_rows")["rows"]
    interfaces = [r for r in rows if r.get("type") == "interface"]
    assert interfaces, "fixture no longer carries the interface row being guarded"

    runtime = runtime_by_name(rows)

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
    assert s2s["runtime_absent"]


@pytest.mark.asyncio
async def test_peers_can_be_filtered_by_instance_and_the_filter_is_verified() -> None:
    """A 200 is not evidence a filter applied: unknown parameters are accepted
    and ignored on every grid. The filter key is `servers`, and it must be an
    array; a bare string returns HTTP 500."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    client = instance_client()
    await ListWgPeersTool(client).execute({"instance": "wg0HomeVpn"})

    bodies = [body for _m, endpoint, body in client.calls if "searchClient" in endpoint]
    assert any(isinstance((b or {}).get("servers"), list) for b in bodies)


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
async def test_reconcile_makes_no_write_call() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    client = reconcile_client()
    await ReconcileWgTool(client).execute({})

    for method, endpoint, _body in client.calls:
        assert method == "POST"
        assert not any(
            verb in endpoint
            for verb in ("/add", "/set", "/del", "/toggle", "/apply", "/reconfigure")
        )


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
    device["config"] = dict(device["config"], ipaddrv6="2001:db8:5eed:b50f::1/64")

    result = await ReconcileWgTool(
        reconcile_client(interfaces_info=fixture_rows)
    ).execute({})

    assert not [r for r in result["results"] if r["outcome"] == "unaccounted_address"]


@pytest.mark.asyncio
async def test_a_route_with_no_allowed_ip_behind_it_is_reported() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r["outcome"] == "stale_route"]

    assert "2001:db8:5eed:b7ef::80" in {r["entry"] for r in rows}


@pytest.mark.asyncio
async def test_an_allowed_ip_with_no_route_is_reported() -> None:
    """The mirror-image defect. Checking one direction finds the stale route and
    misses the missing one, and the captured state holds one of each."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
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

    assert all(r["outcome"] != "drifted" for r in rows)
    assert any(r["outcome"] == "instance_disabled" for r in rows)


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
