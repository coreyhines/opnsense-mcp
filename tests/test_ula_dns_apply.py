"""Executing a `plan_dns_ula` mapping: add, read back, then delete.

The ordering is the whole safety property. `plan_dns_ula` proposes a ULA
address for every AAAA host override under a delegated prefix and changes
nothing; `apply_dns_ula` is what carries that mapping out. On this firewall one
VLAN alone is 54 records, so the interesting cases are not "does one record
move" but "what does a caller learn when record 31 of 54 fails".

The first test in this file is the one a happy-path suite would never write:
the add returns a uuid, the read-back does not find the record, and the delete
must not be issued. Everything else here exists so that test cannot be made to
pass by accident.

The Unbound response shapes are the ones the firewall really emits, not
invented ones: `getHostOverride` roots at `host` and renders `rr` and `aliases`
as MVC enum objects (see
`tests/fixtures/opnsense-26.7.3/unbound_gethostoverride.json`), while
`searchHostOverride` returns flat rows under `rows`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.ula_dns_apply import (
    OUTCOME_FAILED,
    OUTCOME_MOVED,
    OUTCOME_NOT_ATTEMPTED,
    OUTCOME_SKIPPED,
    OUTCOME_WOULD_MOVE,
    REASON_ALREADY_MOVED,
    REASON_DRIFTED,
    REASON_GUA_MISSING,
    REASON_INVALID_RECORD,
    REASON_KEEP_GUA,
    REASON_NO_OP_MOVE,
    REASON_READBACK_FAILED,
    ApplyDnsUlaTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "opnsense-26.7.3"

# The live getHostOverride capture. Loaded rather than retyped so that if the
# real shape drifts (root key, enum rendering) these tests notice.
CAPTURED_HOST = json.loads((FIXTURES_DIR / "unbound_gethostoverride.json").read_text())

NAS_UUID = "11111111-1111-1111-1111-111111111111"
MEDIA_UUID = "22222222-2222-2222-2222-222222222222"
PRINT_UUID = "33333333-3333-3333-3333-333333333333"
WWW_UUID = "44444444-4444-4444-4444-444444444444"

DOMAIN = "example.test"

GUA_NAS = "2001:db8:1e5:b502::19"
GUA_MEDIA = "2001:db8:1e5:b502::20"
GUA_PRINT = "2001:db8:1e5:b502::21"
GUA_WWW = "2001:db8:1e5:b502::80"

ULA_NAS = "fd0b:1e5:b502:2::19"
ULA_MEDIA = "fd0b:1e5:b502:2::20"
ULA_PRINT = "fd0b:1e5:b502:2::21"


def _host(uuid: str, hostname: str, server: str, rr: str = "AAAA") -> dict[str, str]:
    """A flat host override row, the shape searchHostOverride returns."""
    return {
        "uuid": uuid,
        "enabled": "1",
        "hostname": hostname,
        "domain": DOMAIN,
        "rr": rr,
        "server": server,
        "description": f"{hostname} host",
        "mxprio": "",
        "mx": "",
        "ttl": "",
        "txtdata": "",
        "addptr": "1",
    }


def _plan_record(
    uuid: str, hostname: str, current: str, proposed: str | None
) -> dict[str, Any]:
    """One entry of `plan_dns_ula`'s `records` list."""
    return {
        "uuid": uuid,
        "hostname": hostname,
        "domain": DOMAIN,
        "current": current,
        "proposed": proposed,
        "keep_gua": proposed is None,
    }


class _Unbound:
    """An in-memory Unbound host-override store that records every call.

    Stateful rather than a canned-response map, because resumability is only
    testable if a second run sees what the first run did.
    """

    def __init__(self, hosts: list[dict[str, str]]) -> None:
        """Seed the store and reset the call log."""
        self.hosts: dict[str, dict[str, str]] = {h["uuid"]: dict(h) for h in hosts}
        self.calls: list[dict[str, Any]] = []
        self._next = 0
        # Injected faults.
        self.swallow_add = False
        self.fail_add_after = None
        self.fail_delete_after = None
        self._adds = 0
        self._deletes = 0

    # -- helpers ---------------------------------------------------------
    def endpoints(self) -> list[str]:
        """Every endpoint touched, in order."""
        return [call["endpoint"] for call in self.calls]

    def writes(self) -> list[str]:
        """Every endpoint that changes firewall state, in order."""
        return [
            endpoint
            for endpoint in self.endpoints()
            if "addHostOverride" in endpoint
            or "delHostOverride" in endpoint
            or "service/reconfigure" in endpoint
        ]

    def index_of(self, fragment: str) -> int:
        """Position of the first call whose endpoint contains *fragment*."""
        for position, endpoint in enumerate(self.endpoints()):
            if fragment in endpoint:
                return position
        raise AssertionError(f"no call to {fragment!r} in {self.endpoints()}")

    def _node(self, host: dict[str, str]) -> dict[str, Any]:
        """Render a stored row the way getHostOverride renders it."""
        node = json.loads(json.dumps(CAPTURED_HOST["host"]))
        node["enabled"] = host["enabled"]
        node["hostname"] = host["hostname"]
        node["domain"] = host["domain"]
        node["server"] = host["server"]
        node["description"] = host["description"]
        for name, option in node["rr"].items():
            option["selected"] = 1 if name == host["rr"] else 0
        return node

    # -- transport -------------------------------------------------------
    async def request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        """Stand in for `OPNsenseClient._make_request`."""
        self.calls.append(
            {
                "method": method,
                "endpoint": endpoint,
                "json": kwargs.get("json"),
                "call_class": kwargs.get("call_class"),
            }
        )

        if "searchHostOverride" in endpoint:
            rows = [dict(host) for host in self.hosts.values()]
            return {"rows": rows, "total": len(rows)}

        if "getHostOverride" in endpoint:
            uuid = endpoint.rsplit("/", 1)[-1]
            host = self.hosts.get(uuid)
            # OPNsense answers an unknown uuid with an empty list, not a 404.
            return {"host": self._node(host)} if host else []

        if "addHostOverride" in endpoint:
            self._adds += 1
            if self.fail_add_after is not None and self._adds > self.fail_add_after:
                raise RuntimeError("addHostOverride refused: validation failed")
            self._next += 1
            uuid = f"new-{self._next}"
            payload = dict((kwargs.get("json") or {}).get("host") or {})
            if not self.swallow_add:
                self.hosts[uuid] = {"uuid": uuid, **payload}
            return {"result": "saved", "uuid": uuid}

        if "delHostOverride" in endpoint:
            self._deletes += 1
            if (
                self.fail_delete_after is not None
                and self._deletes > self.fail_delete_after
            ):
                raise RuntimeError("delHostOverride refused")
            self.hosts.pop(endpoint.rsplit("/", 1)[-1], None)
            return {"result": "deleted"}

        if "service/reconfigure" in endpoint:
            return {"status": "ok"}

        return {"result": "ok"}


def _client(store: _Unbound) -> OPNsenseClient:
    """A client whose every request is served by *store*."""
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)
    client._make_request = AsyncMock(side_effect=store.request)
    return client


def _one_record_setup() -> tuple[_Unbound, list[dict[str, Any]]]:
    """One movable AAAA record, present on the firewall exactly as planned."""
    store = _Unbound([_host(NAS_UUID, "nas", GUA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]
    return store, plan


def _result_for(result: dict[str, Any], uuid: str) -> dict[str, Any]:
    """The per-record result whose planned uuid is *uuid*."""
    return next(entry for entry in result["results"] if entry["uuid"] == uuid)


# --- 1. the delete is gated on the read-back, not on the add returning ok ----


@pytest.mark.asyncio
async def test_read_back_failure_does_not_issue_the_delete() -> None:
    """The add returns a uuid; the record is not there. Nothing gets deleted.

    This is the failure CLAUDE.md already paid for once: an apply that
    returned ok was treated as evidence the system reached the state. Here the
    add is accepted and the ULA record does not exist, so the GUA record is the
    only answer left for that name. Deleting it would take the name off the
    network entirely.
    """
    store, plan = _one_record_setup()
    store.swallow_add = True

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert not [e for e in store.endpoints() if "delHostOverride" in e]
    assert NAS_UUID in store.hosts

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_FAILED
    assert entry["reason"] == REASON_READBACK_FAILED
    assert entry["added"] is True
    assert entry["verified"] is False
    assert entry["deleted"] is False
    assert result["status"] == "partial_failure"
    assert result["stopped_at"]["uuid"] == NAS_UUID


@pytest.mark.asyncio
async def test_read_back_of_the_wrong_address_also_blocks_the_delete() -> None:
    """A record that exists but answers with something else is not verified.

    A read-back that only checked existence would pass here. The check is on
    the address, compared as a parsed address rather than as a substring.
    """
    store, plan = _one_record_setup()

    async def request(method: str, endpoint: str, **kwargs: Any) -> Any:
        response = await store.request(method, endpoint, **kwargs)
        if "getHostOverride/new-" in endpoint:
            response["host"]["server"] = GUA_NAS
        return response

    client = _client(store)
    client._make_request = AsyncMock(side_effect=request)

    result = await ApplyDnsUlaTool(client).execute({"records": plan, "dry_run": False})

    assert not [e for e in store.endpoints() if "delHostOverride" in e]
    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_FAILED
    assert entry["reason"] == REASON_READBACK_FAILED
    assert entry["verified"] is False


# --- 2. dry run ------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_issues_no_write_requests() -> None:
    """Nothing is added, deleted or reconfigured, and it says what it would do."""
    store, plan = _one_record_setup()

    result = await ApplyDnsUlaTool(_client(store)).execute({"records": plan})

    assert store.writes() == []
    assert store.hosts[NAS_UUID]["server"] == GUA_NAS
    assert result["status"] == "success"
    assert result["dry_run"] is True
    assert result["applied"] is False
    assert result["changed"] == 0

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_WOULD_MOVE
    assert entry["to"] == ULA_NAS
    assert result["counts"][OUTCOME_WOULD_MOVE] == 1


@pytest.mark.asyncio
async def test_dry_run_is_the_default_when_the_key_is_omitted() -> None:
    """Omitting `dry_run` must not write. The schema says so; so does this."""
    store, plan = _one_record_setup()

    result = await ApplyDnsUlaTool(_client(store)).execute({"records": plan})

    assert result["dry_run"] is True
    assert store.writes() == []


@pytest.mark.asyncio
async def test_the_schema_declares_the_dry_run_default() -> None:
    """A caller reading only the schema must be able to predict the default."""
    prop = ApplyDnsUlaTool(None).input_schema["properties"]["dry_run"]

    assert prop["default"] is True


@pytest.mark.asyncio
async def test_execute_reads_no_key_the_schema_omits() -> None:
    """The repo-wide check only walks registered tools; this one is not yet."""
    from tests._schema_ast import execute_ast, param_keys_read

    tool = ApplyDnsUlaTool(None)
    declared = set(tool.input_schema["properties"])
    execute = execute_ast(tool)

    assert execute is not None
    assert param_keys_read(execute) <= declared


# --- 3. the order of a normal move -----------------------------------------


@pytest.mark.asyncio
async def test_a_move_is_add_then_read_back_then_delete_in_that_order() -> None:
    """Call order is the tool's main safety property, so it is asserted directly."""
    store, plan = _one_record_setup()

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    add = store.index_of("addHostOverride")
    read_back = store.index_of("getHostOverride/new-1")
    delete = store.index_of(f"delHostOverride/{NAS_UUID}")
    reconfigure = store.index_of("service/reconfigure")

    assert add < read_back < delete < reconfigure

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_MOVED
    assert entry["added"] is True
    assert entry["verified"] is True
    assert entry["deleted"] is True
    assert entry["ula_uuid"] == "new-1"
    assert result["status"] == "success"
    assert result["applied"] is True
    assert result["changed"] == 1
    assert store.hosts["new-1"]["server"] == ULA_NAS
    assert NAS_UUID not in store.hosts


@pytest.mark.asyncio
async def test_the_new_record_keeps_the_old_record_s_other_fields() -> None:
    """The ULA record is the GUA record with a different address, not a stub."""
    store, plan = _one_record_setup()

    await ApplyDnsUlaTool(_client(store)).execute({"records": plan, "dry_run": False})

    added = next(call for call in store.calls if "addHostOverride" in call["endpoint"])[
        "json"
    ]["host"]

    assert added["server"] == ULA_NAS
    assert added["hostname"] == "nas"
    assert added["domain"] == DOMAIN
    assert added["rr"] == "AAAA"
    assert added["description"] == "nas host"
    assert added["enabled"] == "1"
    assert "uuid" not in added


@pytest.mark.asyncio
async def test_unbound_is_reconfigured_once_for_the_whole_run() -> None:
    """One reload for 54 records, not 108. The reasoning is in the tool docstring."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host(MEDIA_UUID, "media", GUA_MEDIA),
            _host(PRINT_UUID, "printer", GUA_PRINT),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
        _plan_record(PRINT_UUID, "printer", GUA_PRINT, ULA_PRINT),
    ]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    reconfigures = [e for e in store.endpoints() if "service/reconfigure" in e]

    assert len(reconfigures) == 1
    assert store.endpoints()[-1] == reconfigures[0]
    assert result["reconfigure"] == {"ran": True, "ok": True}
    assert result["changed"] == 3


# --- 4. drift --------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_drifted_record_is_skipped_and_says_what_it_found() -> None:
    """The plan may be days old. A record that moved since is not the plan's."""
    store = _Unbound([_host(NAS_UUID, "nas", "2001:db8:1e5:b502::99")])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert store.writes() == []
    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_DRIFTED
    assert entry["expected"] == GUA_NAS
    assert entry["found"] == "2001:db8:1e5:b502::99"
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_a_renamed_record_is_drift_too() -> None:
    """The uuid is stable across a rename, so the address alone is not enough."""
    store = _Unbound([_host(NAS_UUID, "storage", GUA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert store.writes() == []
    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_DRIFTED
    assert entry["found_fqdn"] == f"storage.{DOMAIN}"


@pytest.mark.asyncio
async def test_a_drifted_record_is_not_rewritten_to_match_the_plan() -> None:
    """Refusing means leaving it alone, not correcting it."""
    store = _Unbound([_host(NAS_UUID, "nas", "2001:db8:1e5:b502::99")])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    await ApplyDnsUlaTool(_client(store)).execute({"records": plan, "dry_run": False})

    assert store.hosts[NAS_UUID]["server"] == "2001:db8:1e5:b502::99"
    assert not [e for e in store.endpoints() if "setHostOverride" in e]


# --- 5. resumability -------------------------------------------------------


@pytest.mark.asyncio
async def test_a_second_run_skips_rather_than_double_creating() -> None:
    """Running it twice is how an operator recovers; it must be a no-op."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host(MEDIA_UUID, "media", GUA_MEDIA),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
    ]
    tool = ApplyDnsUlaTool(_client(store))

    first = await tool.execute({"records": plan, "dry_run": False})
    assert first["changed"] == 2

    before = dict(store.hosts)
    store.calls.clear()
    second = await tool.execute({"records": plan, "dry_run": False})

    assert store.writes() == []
    assert store.hosts == before
    assert second["status"] == "success"
    assert second["changed"] == 0
    assert second["applied"] is False
    assert second["counts"][OUTCOME_SKIPPED] == 2
    for uuid in (NAS_UUID, MEDIA_UUID):
        assert _result_for(second, uuid)["reason"] == REASON_ALREADY_MOVED


@pytest.mark.asyncio
async def test_a_run_interrupted_between_add_and_delete_finishes_the_move() -> None:
    """The ULA record already exists and the GUA one still does: finish it.

    This is exactly the state a crash after the add leaves behind. The delete
    is still gated on a read-back, which the existing record satisfies, so no
    second copy is created.
    """
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host("half-done-uuid", "nas", ULA_NAS),
        ]
    )
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert not [e for e in store.endpoints() if "addHostOverride" in e]
    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_MOVED
    assert entry["added"] is False
    assert entry["resumed"] is True
    assert entry["verified"] is True
    assert entry["deleted"] is True
    assert entry["ula_uuid"] == "half-done-uuid"
    assert NAS_UUID not in store.hosts


@pytest.mark.asyncio
async def test_a_record_the_plan_names_but_the_firewall_lost_is_a_skip() -> None:
    """Not an error: someone may have deleted it by hand between plan and apply."""
    store = _Unbound([_host(MEDIA_UUID, "media", GUA_MEDIA)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_GUA_MISSING
    assert result["status"] == "success"


# --- 6. partial failure ----------------------------------------------------


@pytest.mark.asyncio
async def test_a_failure_partway_leaves_earlier_records_applied() -> None:
    """No rollback. The result says what landed, what failed, what was not tried."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host(MEDIA_UUID, "media", GUA_MEDIA),
            _host(PRINT_UUID, "printer", GUA_PRINT),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
        _plan_record(PRINT_UUID, "printer", GUA_PRINT, ULA_PRINT),
    ]
    store.fail_add_after = 1

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert result["status"] == "partial_failure"
    assert _result_for(result, NAS_UUID)["outcome"] == OUTCOME_MOVED
    assert _result_for(result, MEDIA_UUID)["outcome"] == OUTCOME_FAILED
    assert _result_for(result, PRINT_UUID)["outcome"] == OUTCOME_NOT_ATTEMPTED
    assert result["stopped_at"]["uuid"] == MEDIA_UUID
    assert result["stopped_at"]["index"] == 1
    assert result["counts"][OUTCOME_NOT_ATTEMPTED] == 1

    # The first record really moved and stayed moved.
    assert NAS_UUID not in store.hosts
    assert store.hosts["new-1"]["server"] == ULA_NAS
    # The third was never touched.
    assert store.hosts[PRINT_UUID]["server"] == GUA_PRINT


@pytest.mark.asyncio
async def test_what_landed_before_the_failure_is_still_reconfigured() -> None:
    """A record written but never served is a third state; reload what landed."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host(MEDIA_UUID, "media", GUA_MEDIA),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
    ]
    store.fail_add_after = 1

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert result["reconfigure"]["ran"] is True
    assert result["changed"] == 1
    assert store.endpoints()[-1].endswith("unbound/service/reconfigure")


@pytest.mark.asyncio
async def test_a_failed_delete_reports_the_add_that_did_land() -> None:
    """Both records exist. Saying only "failed" would hide a duplicate answer."""
    store, plan = _one_record_setup()
    store.fail_delete_after = 0

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_FAILED
    assert entry["added"] is True
    assert entry["verified"] is True
    assert entry["deleted"] is False
    assert result["status"] == "partial_failure"
    assert NAS_UUID in store.hosts
    assert "new-1" in store.hosts


@pytest.mark.asyncio
async def test_nothing_after_the_stop_is_reported_as_skipped() -> None:
    """`not_attempted` and `skipped` are different facts and stay different."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", GUA_NAS),
            _host(MEDIA_UUID, "media", GUA_MEDIA),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
    ]
    store.fail_add_after = 0

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert result["counts"][OUTCOME_SKIPPED] == 0
    assert result["counts"][OUTCOME_NOT_ATTEMPTED] == 1
    assert result["counts"][OUTCOME_FAILED] == 1


# --- 7. a run that changes nothing still ran -------------------------------


@pytest.mark.asyncio
async def test_a_run_where_every_record_skips_is_success() -> None:
    """Severity goes in the payload. 54 skips is a successful run, not an error."""
    store = _Unbound(
        [
            _host(NAS_UUID, "nas", "2001:db8:1e5:b502::99"),
            _host(MEDIA_UUID, "media", "2001:db8:1e5:b502::98"),
        ]
    )
    plan = [
        _plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS),
        _plan_record(MEDIA_UUID, "media", GUA_MEDIA, ULA_MEDIA),
    ]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert result["status"] == "success"
    assert result["changed"] == 0
    assert result["applied"] is False
    assert result["counts"][OUTCOME_SKIPPED] == 2
    assert result["counts"][OUTCOME_MOVED] == 0
    assert result["reconfigure"]["ran"] is False
    assert store.writes() == []


@pytest.mark.asyncio
async def test_keep_gua_records_are_skipped_without_being_read() -> None:
    """A name the outside world resolves keeps its delegated address."""
    store = _Unbound([_host(WWW_UUID, "www", GUA_WWW)])
    plan = [_plan_record(WWW_UUID, "www", GUA_WWW, None)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert store.writes() == []
    assert not [e for e in store.endpoints() if f"getHostOverride/{WWW_UUID}" in e]
    entry = _result_for(result, WWW_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_KEEP_GUA
    assert result["status"] == "success"


# --- 8. input handling -----------------------------------------------------


@pytest.mark.asyncio
async def test_no_records_is_an_input_error_not_a_silent_success() -> None:
    """An empty apply is almost always a caller mistake, so it says so."""
    store = _Unbound([])

    result = await ApplyDnsUlaTool(_client(store)).execute({"dry_run": False})

    assert result["status"] == "error"
    assert store.calls == []


@pytest.mark.asyncio
async def test_a_malformed_plan_entry_is_skipped_not_guessed_at() -> None:
    """A missing proposed address is not something to recompute here."""
    store = _Unbound([_host(NAS_UUID, "nas", GUA_NAS)])
    plan = [
        {"uuid": NAS_UUID, "hostname": "nas", "domain": DOMAIN, "current": GUA_NAS},
        {"uuid": "", "hostname": "x", "domain": DOMAIN, "current": "", "proposed": ""},
    ]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert store.writes() == []
    assert result["status"] == "success"
    assert result["counts"][OUTCOME_SKIPPED] == 2
    assert _result_for(result, NAS_UUID)["reason"] == REASON_INVALID_RECORD
    assert _result_for(result, "")["reason"] == REASON_INVALID_RECORD


@pytest.mark.asyncio
async def test_a_proposed_address_that_is_not_an_address_is_skipped() -> None:
    """The plan is input, not gospel; an unparseable target is never written."""
    store = _Unbound([_host(NAS_UUID, "nas", GUA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, "fd0b::1%$(reboot)")]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    assert store.writes() == []
    assert _result_for(result, NAS_UUID)["reason"] == REASON_INVALID_RECORD


@pytest.mark.asyncio
async def test_no_client_is_an_error() -> None:
    """The registry can hand a tool a null client; every tool answers the same."""
    result = await ApplyDnsUlaTool(None).execute({"records": []})

    assert result["status"] == "error"


# --- 8. a record must never be its own replacement ---------------------------
#
# Found by adversarial review, not by this suite. The tool deleted a name's
# only AAAA record and reported `outcome: moved`, `verified: true`,
# `changed: 1`. Every existing safety property held while it happened: the
# read-back genuinely found the right name at the right address, because the
# record it read back was the record it was about to delete.
#
# Reachable through the documented two-tool workflow, since `plan_dns_ula`
# accepted identical prefixes and planned every record onto the address it
# already held. Three gates now, at each layer that could reintroduce it
# alone.


@pytest.mark.asyncio
async def test_a_record_planned_onto_its_own_address_is_never_deleted() -> None:
    """Gate one: the plan record itself is a no-op and is refused as one."""
    store = _Unbound([_host(NAS_UUID, "nas", GUA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, GUA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_NO_OP_MOVE
    # The point of the test: the answer is still there.
    assert NAS_UUID in store.hosts
    assert store.hosts[NAS_UUID]["server"] == GUA_NAS
    assert not any(f"delHostOverride/{NAS_UUID}" in call for call in store.endpoints())
    assert result["changed"] == 0


@pytest.mark.asyncio
async def test_a_record_that_drifted_onto_its_target_is_never_deleted() -> None:
    """A record already at its target survives.

    Written to exercise gate two, and it does not: removing gate two leaves
    this green, because the pre-existing drift check refuses the record first
    (the firewall holds an address the plan did not record). Kept as a
    regression test for the outcome that matters -- the answer is still there
    -- with its real coverage stated rather than implied.

    Gate two is therefore belt-and-braces against a path no current test
    reaches. It stays because the index is keyed on live addresses and the
    drift check is the only thing standing in front of it.
    """
    # Plan says GUA -> ULA. The firewall already holds the ULA.
    store = _Unbound([_host(NAS_UUID, "nas", ULA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, ULA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute(
        {"records": plan, "dry_run": False}
    )

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert NAS_UUID in store.hosts
    assert not any(f"delHostOverride/{NAS_UUID}" in call for call in store.endpoints())


@pytest.mark.asyncio
async def test_the_dry_run_also_refuses_a_self_move() -> None:
    """A dry run that showed `would_move` was the reason review missed this."""
    store = _Unbound([_host(NAS_UUID, "nas", GUA_NAS)])
    plan = [_plan_record(NAS_UUID, "nas", GUA_NAS, GUA_NAS)]

    result = await ApplyDnsUlaTool(_client(store)).execute({"records": plan})

    entry = _result_for(result, NAS_UUID)
    assert entry["outcome"] == OUTCOME_SKIPPED
    assert entry["reason"] == REASON_NO_OP_MOVE
