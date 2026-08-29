"""Router advertisements, host overrides, ULA planning and the apply step.

Together with the NPT and VIP tools these cover the firewall side of moving a
network from a delegated GUA to a stable ULA:

    VIP     puts the ULA on each LAN interface
    RA      advertises it, and later deprecates the GUA
    Unbound answers with it internally
    NPT     translates it to the delegated prefix on the way out

`plan_dns_ula` is read-only on purpose. Rewriting 150 AAAA records is not
something to do from a single tool call, and some of them must stay GUA because
the outside world resolves them.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.ula_migration import (
    REASON_DEPRECATE_NOT_SUPPORTED,
    ApplyUlaTool,
    ListRouterAdvertsTool,
    PlanDnsUlaTool,
    SetHostOverrideTool,
    SetRouterAdvertTool,
)
from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.ra_daemon import (
    DAEMON_DNSMASQ,
    DAEMON_RADVD,
    REASON_BOTH_SERVING,
    REASON_DNSMASQ_SERVING,
)

RA_UUID = "3204fed6-b745-4b7c-8d83-8c4ddb076048"
HOST_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

RA_ROWS = {
    "rows": [
        {
            "uuid": RA_UUID,
            "interface": "opt2",
            "mode": "managed",
            "enabled": "0",
            "AdvPreferredLifetime": "",
            "AdvValidLifetime": "",
            "DeprecatePrefix": "",
            "RDNSS": "2001:db8:1e5:b7e2::2",
        }
    ],
    "total": 1,
}

# radvd entry with enabled=1 (actually serving)
RA_ROWS_ENABLED = {
    "rows": [
        {
            "uuid": RA_UUID,
            "interface": "opt2",
            "mode": "managed",
            "enabled": "1",
            "AdvPreferredLifetime": "",
            "AdvValidLifetime": "",
            "DeprecatePrefix": "",
        }
    ],
    "total": 1,
}

RA_ENTRY = {
    "entry": {
        "interface": {"opt2": {"selected": 1, "value": "VLAN2"}},
        "mode": {
            "managed": {"selected": 1, "value": "Managed"},
            "unmanaged": {"selected": 0, "value": "Unmanaged"},
        },
        "enabled": "0",
        "AdvPreferredLifetime": "",
        "AdvValidLifetime": "",
        "DeprecatePrefix": "0",
        "RDNSS": "2001:db8:1e5:b7e2::2",
        "MaxRtrAdvInterval": "600",
    }
}

RA_ENTRY_ENABLED = {
    "entry": {
        "interface": {"opt2": {"selected": 1, "value": "VLAN2"}},
        "mode": {
            "managed": {"selected": 1, "value": "Managed"},
            "unmanaged": {"selected": 0, "value": "Unmanaged"},
        },
        "enabled": "1",
        "AdvPreferredLifetime": "",
        "AdvValidLifetime": "",
        "DeprecatePrefix": "0",
        "MaxRtrAdvInterval": "600",
    }
}

# dnsmasq v6 range on opt2 with RA serving
DNSMASQ_RANGE_ROWS = {
    "rows": [
        {
            "uuid": "dnsmasq-range-uuid",
            "interface": "opt2",
            "start_addr": "::100",
            "end_addr": "::1ff",
            "constructor": "opt2",
            "ra_mode": "slaac",
        }
    ],
    "total": 1,
}

DNSMASQ_RANGE_ROWS_EMPTY = {"rows": [], "total": 0}

# Interface states for classification
INTERFACE_STATES = [
    {"identifier": "opt2", "device": "vlan2", "enabled": True},
    {"identifier": "opt3", "device": "vlan3", "enabled": True},
]

HOST_OVERRIDES = {
    "rows": [
        {
            "uuid": HOST_UUID,
            "hostname": "nas",
            "domain": "example.test",
            "rr": "AAAA",
            "server": "2001:db8:1e5:b502::19",
            "enabled": "1",
            "description": "",
        },
        {
            "uuid": "web-uuid",
            "hostname": "www",
            "domain": "example.test",
            "rr": "AAAA",
            "server": "2001:db8:1e5:b502::80",
            "enabled": "1",
            "description": "public site",
        },
        {
            "uuid": "v4-uuid",
            "hostname": "printer",
            "domain": "example.test",
            "rr": "A",
            "server": "172.20.2.50",
            "enabled": "1",
            "description": "",
        },
    ],
    "total": 3,
}

GET_HOST = {
    "host": {
        "hostname": "nas",
        "domain": "example.test",
        "rr": {
            "AAAA": {"selected": 1, "value": "AAAA"},
            "A": {"selected": 0, "value": "A"},
        },
        "server": "2001:db8:1e5:b502::19",
        "description": "storage",
        "enabled": "1",
        "ttl": "",
        "mx": "",
        "mxprio": "",
        "aliases": "",
        "addptr": "0",
        "txtdata": "",
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
    """Stub client for existing tests, now with classification support.

    Provides empty dnsmasq ranges and interface states that allow radvd writes.
    Tests that need specific classification behavior should use _stub_with_dnsmasq.
    """
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append({"endpoint": endpoint, "json": kwargs.get("json")})
        # Classification endpoints: return data that allows radvd writes
        if "search_range" in endpoint:
            return DNSMASQ_RANGE_ROWS_EMPTY
        if "overview/export" in endpoint:
            return INTERFACE_STATES
        for key, value in responses.items():
            if key in endpoint:
                return value
        return {"result": "saved", "status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- router advertisements -------------------------------------------------


@pytest.mark.asyncio
async def test_list_router_adverts_projects_fields() -> None:
    client = _client()
    _stub(client, {"search_entry": RA_ROWS})

    result = await ListRouterAdvertsTool(client).execute({})

    assert result["count"] == 1
    assert result["entries"][0]["interface"] == "opt2"
    assert result["entries"][0]["mode"] == "managed"


@pytest.mark.asyncio
async def test_set_router_advert_preserves_untouched_fields() -> None:
    """radvd entries carry many fields; a partial POST would blank them."""
    client = _client()
    # Use enabled entry so radvd is classified as serving
    calls = _stub(
        client, {"get_entry": RA_ENTRY_ENABLED, "search_entry": RA_ROWS_ENABLED}
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "enabled": True}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "set_entry" in c["endpoint"])["json"]["entry"]
    assert payload["enabled"] == "1"
    assert payload["MaxRtrAdvInterval"] == "600"
    assert payload["mode"] == "managed"


@pytest.mark.asyncio
async def test_set_router_advert_can_deprecate_the_old_prefix() -> None:
    """Preferred lifetime 0 is how clients stop sourcing from the old prefix.

    Deprecation via radvd works when radvd serves (not dnsmasq).
    """
    client = _client()
    # Use enabled entry so radvd is classified as serving
    calls = _stub(
        client, {"get_entry": RA_ENTRY_ENABLED, "search_entry": RA_ROWS_ENABLED}
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "preferred_lifetime": 0, "deprecate_prefix": True}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "set_entry" in c["endpoint"])["json"]["entry"]
    assert payload["AdvPreferredLifetime"] == "0"
    assert payload["DeprecatePrefix"] == "1"


@pytest.mark.asyncio
async def test_set_router_advert_requires_a_uuid() -> None:
    client = _client()

    result = await SetRouterAdvertTool(client).execute({"enabled": True})

    assert result["status"] == "error"
    assert "uuid" in result["error"]


# --- host overrides --------------------------------------------------------


@pytest.mark.asyncio
async def test_set_host_override_requires_a_uuid() -> None:
    """This edits an existing record; creating is what mkdns is for."""
    client = _client()

    result = await SetHostOverrideTool(client).execute({"server": "fd0b:b022::1"})

    assert result["status"] == "error"
    assert "uuid" in result["error"]


@pytest.mark.asyncio
async def test_set_host_override_never_infers_the_record_type() -> None:
    """Guessing rr from the address shape would silently rewrite record types."""
    client = _client()
    calls = _stub(client, {"getHostOverride": GET_HOST})

    await SetHostOverrideTool(client).execute(
        {"uuid": HOST_UUID, "server": "fd0b:b022:1e5:2::19"}
    )

    payload = next(c for c in calls if "setHostOverride" in c["endpoint"])["json"][
        "host"
    ]
    assert payload["rr"] == "AAAA"
    assert payload["server"] == "fd0b:b022:1e5:2::19"


@pytest.mark.asyncio
async def test_set_host_override_preserves_description_and_flags() -> None:
    client = _client()
    calls = _stub(client, {"getHostOverride": GET_HOST})

    await SetHostOverrideTool(client).execute(
        {"uuid": HOST_UUID, "server": "fd0b:b022::19"}
    )

    payload = next(c for c in calls if "setHostOverride" in c["endpoint"])["json"][
        "host"
    ]
    assert payload["description"] == "storage"
    assert payload["hostname"] == "nas"
    assert payload["domain"] == "example.test"


# --- planning --------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_dns_ula_proposes_ula_keeping_host_bits() -> None:
    """The interface id is what makes the mapping predictable."""
    client = _client()
    _stub(client, {"searchHostOverride": HOST_OVERRIDES})

    result = await PlanDnsUlaTool(client).execute(
        {"gua_prefix": "2001:db8:1e5:b502::/64", "ula_prefix": "fd0b:b022:1e5:2::/64"}
    )

    assert result["status"] == "success"
    nas = next(r for r in result["records"] if r["hostname"] == "nas")
    assert nas["current"] == "2001:db8:1e5:b502::19"
    assert nas["proposed"] == "fd0b:b022:1e5:2::19"


@pytest.mark.asyncio
async def test_plan_dns_ula_ignores_records_outside_the_prefix() -> None:
    """A records and other prefixes are not part of this migration."""
    client = _client()
    _stub(client, {"searchHostOverride": HOST_OVERRIDES})

    result = await PlanDnsUlaTool(client).execute(
        {"gua_prefix": "2001:db8:1e5:b502::/64", "ula_prefix": "fd0b:b022:1e5:2::/64"}
    )

    assert "printer" not in [r["hostname"] for r in result["records"]]


@pytest.mark.asyncio
async def test_plan_dns_ula_flags_names_that_must_stay_gua() -> None:
    """Anything the outside world resolves keeps its GUA and its DDNS."""
    client = _client()
    _stub(client, {"searchHostOverride": HOST_OVERRIDES})

    result = await PlanDnsUlaTool(client).execute(
        {
            "gua_prefix": "2001:db8:1e5:b502::/64",
            "ula_prefix": "fd0b:b022:1e5:2::/64",
            "public_names": ["www.example.test"],
        }
    )

    www = next(r for r in result["records"] if r["hostname"] == "www")
    assert www["keep_gua"] is True
    assert www["proposed"] is None
    nas = next(r for r in result["records"] if r["hostname"] == "nas")
    assert nas["keep_gua"] is False


@pytest.mark.asyncio
async def test_plan_dns_ula_changes_nothing() -> None:
    """It is a plan; the caller decides what to apply."""
    client = _client()
    calls = _stub(client, {"searchHostOverride": HOST_OVERRIDES})

    await PlanDnsUlaTool(client).execute(
        {"gua_prefix": "2001:db8:1e5:b502::/64", "ula_prefix": "fd0b:b022:1e5:2::/64"}
    )

    # Match command names, not substrings: "settings" contains "set".
    mutating = ("setHostOverride", "addHostOverride", "delHostOverride", "reconfigure")
    assert not [c for c in calls if any(m in c["endpoint"] for m in mutating)]


@pytest.mark.asyncio
async def test_plan_dns_ula_rejects_mismatched_prefix_lengths() -> None:
    client = _client()
    _stub(client, {"searchHostOverride": HOST_OVERRIDES})

    result = await PlanDnsUlaTool(client).execute(
        {"gua_prefix": "2001:db8:1e5:b502::/64", "ula_prefix": "fd0b:b022:1e5::/48"}
    )

    assert result["status"] == "error"
    assert "length" in result["error"]


# --- apply -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_ula_is_a_dry_run_by_default() -> None:
    """The dangerous polarity lives here and only here."""
    client = _client()
    calls = _stub(client, {})

    result = await ApplyUlaTool(client).execute({})

    assert result["applied"] is False
    assert result["dry_run"] is True
    assert not calls


@pytest.mark.asyncio
async def test_apply_ula_runs_domains_in_order() -> None:
    """NPT before RA: advertising a prefix whose translation is not live yet
    black-holes anything that believes the advertisement."""
    client = _client()
    # Provide radvd serving so the RA domain reconfigures radvd
    calls = _stub(client, {"search_entry": RA_ROWS_ENABLED})

    result = await ApplyUlaTool(client).execute({"dry_run": False})

    assert result["applied"] is True
    assert result["done"] == ["vip", "npt", "ra", "unbound"]
    order = [c["endpoint"] for c in calls]
    # NPT (firewall filter apply) before RA (radvd reconfigure)
    filter_idx = next(i for i, ep in enumerate(order) if "firewall/filter/apply" in ep)
    radvd_idx = next(
        i for i, ep in enumerate(order) if "radvd/service/reconfigure" in ep
    )
    assert filter_idx < radvd_idx


@pytest.mark.asyncio
async def test_apply_ula_accepts_a_subset_in_canonical_order() -> None:
    client = _client()
    _stub(client, {})

    result = await ApplyUlaTool(client).execute(
        {"dry_run": False, "domains": ["vip", "npt"]}
    )

    assert result["done"] == ["vip", "npt"]


@pytest.mark.asyncio
async def test_apply_ula_rejects_an_unknown_domain() -> None:
    client = _client()
    _stub(client, {})

    result = await ApplyUlaTool(client).execute(
        {"dry_run": False, "domains": ["vip", "elsewhere"]}
    )

    assert result["status"] == "error"
    assert "elsewhere" in result["error"]


@pytest.mark.asyncio
async def test_apply_ula_reports_where_it_stopped() -> None:
    """No rollback: the caller needs to know what did and did not land."""
    client = _client()

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "radvd" in endpoint:
            raise RuntimeError("radvd reconfigure failed")
        return {"status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)

    result = await ApplyUlaTool(client).execute({"dry_run": False})

    assert result["status"] == "partial_failure"
    assert result["done"] == ["vip", "npt"]
    assert result["failed"] == "ra"
    assert result["remaining"] == ["unbound"]
    assert "radvd reconfigure failed" in result["error"]


# --- daemon routing (bucket B4) --------------------------------------------


def _stub_with_dnsmasq(
    client: OPNsenseClient,
    radvd_rows: dict[str, Any],
    dnsmasq_rows: dict[str, Any],
    ra_entry: dict[str, Any],
    interface_states: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Stub the client to return dnsmasq ranges and interface states."""
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append(
            {"method": method, "endpoint": endpoint, "json": kwargs.get("json")}
        )
        if "search_entry" in endpoint:
            return radvd_rows
        if "search_range" in endpoint:
            return dnsmasq_rows
        if "get_entry" in endpoint:
            return ra_entry
        if "overview/export" in endpoint:
            return interface_states
        return {"result": "saved", "status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


@pytest.mark.asyncio
async def test_set_router_advert_refuses_when_dnsmasq_serves() -> None:
    """With dnsmasq serving, set_router_advert does NOT issue a radvd write."""
    client = _client()
    calls = _stub_with_dnsmasq(
        client,
        RA_ROWS,  # radvd disabled
        DNSMASQ_RANGE_ROWS,  # dnsmasq serving
        RA_ENTRY,
        INTERFACE_STATES,
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "enabled": True}
    )

    # Refused, not error
    assert result["status"] == "refused"
    assert result["interface"] == "opt2"
    assert REASON_DNSMASQ_SERVING in result["reason_codes"]

    # Falsification: no set_entry call was made
    set_calls = [c for c in calls if "set_entry" in c["endpoint"]]
    assert set_calls == [], "radvd set_entry should not have been called"


@pytest.mark.asyncio
async def test_set_router_advert_refuses_when_both_serve() -> None:
    """Both radvd and dnsmasq serving → refused with code present."""
    client = _client()
    calls = _stub_with_dnsmasq(
        client,
        RA_ROWS_ENABLED,  # radvd enabled
        DNSMASQ_RANGE_ROWS,  # dnsmasq also serving
        RA_ENTRY_ENABLED,
        INTERFACE_STATES,
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "enabled": True}
    )

    assert result["status"] == "refused"
    assert REASON_BOTH_SERVING in result["reason_codes"]

    # No write
    set_calls = [c for c in calls if "set_entry" in c["endpoint"]]
    assert set_calls == []


@pytest.mark.asyncio
async def test_set_router_advert_deprecate_refused_names_missing_capability() -> None:
    """Deprecate request when dnsmasq serves names the missing field."""
    client = _client()
    _stub_with_dnsmasq(
        client,
        RA_ROWS,  # radvd disabled
        DNSMASQ_RANGE_ROWS,  # dnsmasq serving
        RA_ENTRY,
        INTERFACE_STATES,
    )

    # Request deprecation via preferred_lifetime=0
    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "preferred_lifetime": 0}
    )

    assert result["status"] == "refused"
    assert REASON_DEPRECATE_NOT_SUPPORTED in result["reason_codes"]
    assert result.get("missing_capability") == "preferred_lifetime"


@pytest.mark.asyncio
async def test_set_router_advert_deprecate_prefix_refused_names_missing_capability() -> (
    None
):
    """Deprecate request via deprecate_prefix=True when dnsmasq serves."""
    client = _client()
    _stub_with_dnsmasq(
        client,
        RA_ROWS,  # radvd disabled
        DNSMASQ_RANGE_ROWS,  # dnsmasq serving
        RA_ENTRY,
        INTERFACE_STATES,
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "deprecate_prefix": True}
    )

    assert result["status"] == "refused"
    assert REASON_DEPRECATE_NOT_SUPPORTED in result["reason_codes"]
    assert "preferred_lifetime" in result.get("missing_capability", "")


@pytest.mark.asyncio
async def test_set_router_advert_succeeds_when_radvd_serves() -> None:
    """When radvd serves, the write proceeds and reports the daemon."""
    client = _client()
    calls = _stub_with_dnsmasq(
        client,
        RA_ROWS_ENABLED,  # radvd enabled
        DNSMASQ_RANGE_ROWS_EMPTY,  # no dnsmasq range
        RA_ENTRY_ENABLED,
        INTERFACE_STATES,
    )

    result = await SetRouterAdvertTool(client).execute(
        {"uuid": RA_UUID, "enabled": True}
    )

    assert result["status"] == "success"
    assert result.get("daemon") == DAEMON_RADVD

    # Verify the set_entry call was made
    set_calls = [c for c in calls if "set_entry" in c["endpoint"]]
    assert len(set_calls) == 1


@pytest.mark.asyncio
async def test_apply_ula_routes_ra_to_dnsmasq_when_serving() -> None:
    """When dnsmasq serves RA, apply_ula reconfigures dnsmasq, not radvd."""
    client = _client()
    calls = _stub_with_dnsmasq(
        client,
        RA_ROWS,  # radvd disabled
        DNSMASQ_RANGE_ROWS,  # dnsmasq serving
        RA_ENTRY,
        INTERFACE_STATES,
    )

    result = await ApplyUlaTool(client).execute({"dry_run": False, "domains": ["ra"]})

    assert result["status"] == "success"
    assert result["applied"] is True
    assert "ra" in result["done"]

    # Check that dnsmasq reconfigure was called, not radvd
    reconfigure_calls = [c for c in calls if "reconfigure" in c["endpoint"]]
    dnsmasq_reconfigure = [c for c in reconfigure_calls if "dnsmasq" in c["endpoint"]]
    radvd_reconfigure = [c for c in reconfigure_calls if "radvd" in c["endpoint"]]

    assert len(dnsmasq_reconfigure) == 1
    assert len(radvd_reconfigure) == 0


@pytest.mark.asyncio
async def test_apply_ula_routes_ra_to_radvd_when_serving() -> None:
    """When radvd serves RA, apply_ula reconfigures radvd."""
    client = _client()
    calls = _stub_with_dnsmasq(
        client,
        RA_ROWS_ENABLED,  # radvd enabled
        DNSMASQ_RANGE_ROWS_EMPTY,  # no dnsmasq
        RA_ENTRY_ENABLED,
        INTERFACE_STATES,
    )

    result = await ApplyUlaTool(client).execute({"dry_run": False, "domains": ["ra"]})

    assert result["status"] == "success"
    assert result["applied"] is True

    reconfigure_calls = [c for c in calls if "reconfigure" in c["endpoint"]]
    radvd_reconfigure = [c for c in reconfigure_calls if "radvd" in c["endpoint"]]

    assert len(radvd_reconfigure) == 1


@pytest.mark.asyncio
async def test_apply_ula_reports_verification_failure() -> None:
    """apply_ula reports applied=false when post-apply read finds mismatches."""
    client = _client()
    call_count = {"search_entry": 0}

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "search_entry" in endpoint:
            call_count["search_entry"] += 1
            if call_count["search_entry"] == 1:
                # Before apply: radvd enabled
                return RA_ROWS_ENABLED
            # After apply: radvd disabled (simulating unexpected state change)
            return RA_ROWS
        if "search_range" in endpoint:
            return DNSMASQ_RANGE_ROWS_EMPTY
        if "overview/export" in endpoint:
            return INTERFACE_STATES
        return {"status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)

    result = await ApplyUlaTool(client).execute({"dry_run": False, "domains": ["ra"]})

    # The verification failed: daemon changed from radvd to none
    assert result["status"] == "warning"
    assert result["applied"] is False
    assert result["failed"] == "ra"
    assert "ra_result" in result
    assert result["ra_result"]["verified"] is False
    assert "mismatches" in result["ra_result"]
