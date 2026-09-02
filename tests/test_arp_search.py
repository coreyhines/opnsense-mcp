"""The ARP/NDP search path, against the shapes the firewall really sends (#40).

Three separate defects lived here, and none of them made a call fail:

1. the filter was sent as a GET `search` parameter, which the endpoint ignores
2. the result was read from a `data` key the response does not carry
3. a query the tables did match was handed to `resolve_host_info` anyway, which
   answers with one host

The first two cancelled out. An always-empty read fell through to fetching the
whole table and filtering it in the client, so searches worked -- via two full
fetches and a client-side scan -- and nothing pointed at the endpoint. The third
then reduced a prefix query matching nine neighbours to one, and reported the
other eight as absent.

Captured live off OPNsense 26.7.3 and sanitised:

    POST /api/diagnostics/interface/search_ndp {"searchPhrase": "<ula prefix>"}
      -> total 9, rows 9
    GET  /api/diagnostics/interface/search_ndp?search=<ula prefix>
      -> total 278, rows 278      # the whole table; the parameter is ignored

so `total` on the GET is the count of every neighbour on the box, which is what
"the filter did nothing" looks like from the outside.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.utils.api import OPNsenseClient, _matching_neighbours

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"

ARP_GRID = json.loads((FIXTURES / "diagnostics_search_arp_rows.json").read_text())
NDP_GRID = json.loads((FIXTURES / "diagnostics_search_ndp_rows.json").read_text())

# The prefix the NDP capture answers, taken from the capture so the test cannot
# drift from the fixture it asserts against.
NDP_PREFIX = NDP_GRID["rows"][0]["ip"].rsplit(":", 4)[0] + ":"


class RecordingClient(OPNsenseClient):
    """A client that records requests and replays canned responses.

    Subclasses the real client rather than duck-typing one, so the methods
    under test are the shipped ones and a change to their signature breaks
    this file rather than silently bypassing it.
    """

    def __init__(self, responses: dict[str, Any], tables: dict[str, Any] | None = None):
        self.requests: list[dict[str, Any]] = []
        self._responses = responses
        self._tables = tables or {}

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        self.requests.append(
            {"method": method, "endpoint": endpoint, "params": params, "json": json}
        )
        if endpoint not in self._responses:
            raise RuntimeError(f"no canned response for {endpoint}")
        response = self._responses[endpoint]
        if isinstance(response, Exception):
            raise response
        return response

    async def get_arp_table(self) -> list[dict[str, Any]]:
        return self._tables.get("arp", [])

    async def get_ndp_table(self) -> list[dict[str, Any]]:
        return self._tables.get("ndp", [])

    _get_arp_table = get_arp_table
    _get_ndp_table = get_ndp_table


def _client(**kwargs: Any) -> RecordingClient:
    return RecordingClient(**kwargs)


# --- the request that is actually sent -------------------------------------


@pytest.mark.asyncio
async def test_the_search_is_posted_with_searchphrase_not_got_with_search() -> None:
    """Defect 1. A GET `search` is ignored and answers with the whole table.

    Asserted on the request rather than on the result, because the result was
    right for the wrong reason: the client-side fallback covered for it.
    """
    client = _client(
        responses={"/api/diagnostics/interface/search_ndp": NDP_GRID},
    )

    await client.search_ndp_table(NDP_PREFIX)

    assert len(client.requests) == 1
    sent = client.requests[0]
    assert sent["method"] == "POST"
    assert sent["json"]["searchPhrase"] == NDP_PREFIX
    assert sent["params"] is None, "a GET parameter here is the ignored one"


@pytest.mark.asyncio
async def test_the_search_asks_for_every_matching_row() -> None:
    """A paged answer to a filter is the defect relocated, not removed."""
    client = _client(responses={"/api/diagnostics/interface/search_arp": ARP_GRID})

    await client.search_arp_table("172.20.5.")

    assert client.requests[0]["json"]["rowCount"] == -1


@pytest.mark.asyncio
async def test_rows_is_the_key_the_endpoint_sends() -> None:
    """Defect 2. `data` is absent from every response the firewall sends."""
    assert "data" not in NDP_GRID, "the fixture no longer captures the real shape"

    client = _client(responses={"/api/diagnostics/interface/search_ndp": NDP_GRID})

    found = await client.search_ndp_table(NDP_PREFIX)

    assert len(found) == len(NDP_GRID["rows"]) == 9
    assert {entry["ip"] for entry in found} == {row["ip"] for row in NDP_GRID["rows"]}


@pytest.mark.asyncio
async def test_a_wildcard_search_never_reaches_the_search_endpoint() -> None:
    """'*' means the whole table, which has its own endpoint."""
    client = _client(responses={}, tables={"arp": ARP_GRID["rows"]})

    found = await client.search_arp_table("*")

    assert client.requests == []
    assert len(found) == len(ARP_GRID["rows"])


# --- the fallback, and when it is allowed to run ---------------------------


@pytest.mark.asyncio
async def test_a_firmware_without_the_endpoint_still_answers() -> None:
    """The local scan is kept for firmware that 404s, and reached only then."""
    client = _client(
        responses={
            "/api/diagnostics/interface/search_ndp": RuntimeError("404 Not Found")
        },
        tables={"ndp": NDP_GRID["rows"]},
    )

    found = await client.search_ndp_table(NDP_PREFIX)

    assert len(found) == 9


@pytest.mark.asyncio
async def test_an_empty_grid_is_an_answer_not_a_reason_to_scan_the_table() -> None:
    """Treating empty rows as "the endpoint failed" is what hid defects 1 and 2.

    The table here holds a row the query matches. If the empty grid were
    discarded, the scan would find it and this test would report one match --
    which is exactly how the broken version passed for years.
    """
    client = _client(
        responses={
            "/api/diagnostics/interface/search_ndp": {
                "total": 0,
                "rowCount": 0,
                "current": 1,
                "rows": [],
            }
        },
        tables={"ndp": NDP_GRID["rows"]},
    )

    assert await client.search_ndp_table(NDP_PREFIX) == []


# --- the defect the issue was filed about ----------------------------------


@pytest.mark.asyncio
async def test_a_prefix_query_returns_every_match_not_the_first() -> None:
    """Defect 3, and the reported symptom.

    Nine neighbours carry this prefix. The tool reported one -- the firewall's
    own address, which is simply `rows[0]` -- because a query the table had
    already matched was sent to `resolve_host_info`, whose job is to name a
    single host.

    Falsify by resolving before searching again: this returns 1.
    """

    class Client:
        def __init__(self) -> None:
            self.resolved: list[str] = []

        async def search_arp_table(self, query: str) -> list[dict[str, Any]]:
            return []

        async def search_ndp_table(self, query: str) -> list[dict[str, Any]]:
            if query == NDP_PREFIX:
                return NDP_GRID["rows"]
            # What resolving collapses to: one address, one row.
            return [row for row in NDP_GRID["rows"] if row["ip"] == query]

        async def resolve_host_info(self, query: str) -> dict[str, Any]:
            self.resolved.append(query)
            first = NDP_GRID["rows"][0]
            return {"ip": None, "mac": first["mac"], "ndp": first}

    client = Client()
    result = await ARPTool(client).execute({"search": NDP_PREFIX})

    assert result["status"] == "success"
    assert len(result["ndp"]) == 9
    assert client.resolved == [], "the resolver ran on a query the table matched"


@pytest.mark.asyncio
async def test_a_hostname_the_tables_do_not_match_is_still_resolved() -> None:
    """The behaviour the resolver is there for, so the fix cannot be "never
    resolve"."""
    target = NDP_GRID["rows"][3]

    class Client:
        async def search_arp_table(self, query: str) -> list[dict[str, Any]]:
            return []

        async def search_ndp_table(self, query: str) -> list[dict[str, Any]]:
            return [row for row in NDP_GRID["rows"] if row["ip"] == query]

        async def resolve_host_info(self, query: str) -> dict[str, Any]:
            assert query == "printer"
            return {"ip": None, "mac": None, "ndp": target}

    result = await ARPTool(Client()).execute({"search": "printer"})

    assert [entry["ip"] for entry in result["ndp"]] == [target["ip"]]


@pytest.mark.asyncio
async def test_a_whole_address_that_matches_nothing_is_not_resolved() -> None:
    """An address needs no resolving, so a miss on one means genuinely absent.

    Sending it to the resolver would let a DNS or DHCP record answer a question
    that was asked of the neighbour tables.
    """

    class Client:
        def __init__(self) -> None:
            self.resolved: list[str] = []

        async def search_arp_table(self, query: str) -> list[dict[str, Any]]:
            return []

        async def search_ndp_table(self, query: str) -> list[dict[str, Any]]:
            return []

        async def resolve_host_info(self, query: str) -> dict[str, Any]:
            self.resolved.append(query)
            return {}

    for query in ("172.20.5.99", "2001:db8::99", "52:54:00:11:22:33"):
        client = Client()
        result = await ARPTool(client).execute({"search": query})
        assert result["arp"] == [] and result["ndp"] == []
        assert client.resolved == [], f"{query} was sent to the resolver"


# --- the fallback predicate ------------------------------------------------


def test_the_local_scan_matches_a_partial_address_and_a_whole_one() -> None:
    rows = NDP_GRID["rows"]
    whole = rows[0]["ip"]

    assert len(_matching_neighbours(rows, NDP_PREFIX)) == 9
    assert [e["ip"] for e in _matching_neighbours(rows, whole)] == [whole]


def test_the_local_scan_does_not_match_a_longer_address_by_prefix() -> None:
    """`172.20.5.1` matching `172.20.5.10` is the read-back mistake this repo has
    already paid for once."""
    table = [
        {"ip": "172.20.5.1", "mac": "52:54:00:00:00:01", "intf": "em0"},
        {"ip": "172.20.5.10", "mac": "52:54:00:00:00:02", "intf": "em0"},
    ]

    assert [e["ip"] for e in _matching_neighbours(table, "172.20.5.1")] == [
        "172.20.5.1"
    ]


def test_the_local_scan_searches_the_columns_the_endpoint_searches() -> None:
    """The firewall's grid searches every rendered column. A fallback that
    matched fewer would answer the same query differently depending on
    firmware."""
    rows = NDP_GRID["rows"]
    description = rows[0]["intf_description"]

    assert description, "the fixture no longer carries an interface description"
    assert _matching_neighbours(rows, description)
    assert _matching_neighbours(rows, rows[0]["intf"])
