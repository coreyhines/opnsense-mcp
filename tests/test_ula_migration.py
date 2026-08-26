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
    ApplyUlaTool,
    ListRouterAdvertsTool,
    PlanDnsUlaTool,
    SetHostOverrideTool,
    SetRouterAdvertTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

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
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append({"endpoint": endpoint, "json": kwargs.get("json")})
        for key, value in responses.items():
            if key in endpoint:
                return value
        return {"result": "saved"}

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
    calls = _stub(client, {"get_entry": RA_ENTRY, "search_entry": RA_ROWS})

    await SetRouterAdvertTool(client).execute({"uuid": RA_UUID, "enabled": True})

    payload = next(c for c in calls if "set_entry" in c["endpoint"])["json"]["entry"]
    assert payload["enabled"] == "1"
    assert payload["MaxRtrAdvInterval"] == "600"
    assert payload["mode"] == "managed"


@pytest.mark.asyncio
async def test_set_router_advert_can_deprecate_the_old_prefix() -> None:
    """Preferred lifetime 0 is how clients stop sourcing from the old prefix."""
    client = _client()
    calls = _stub(client, {"get_entry": RA_ENTRY, "search_entry": RA_ROWS})

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
    calls = _stub(client, {})

    result = await ApplyUlaTool(client).execute({"dry_run": False})

    assert result["applied"] is True
    assert result["done"] == ["vip", "npt", "ra", "unbound"]
    order = [c["endpoint"] for c in calls]
    assert order.index("/api/firewall/filter/apply") < order.index(
        "/api/radvd/service/reconfigure"
    )


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
