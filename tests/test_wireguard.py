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
