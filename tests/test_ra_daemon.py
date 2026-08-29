"""Tests for pure RA-daemon classification (no I/O)."""

from __future__ import annotations

from opnsense_mcp.utils.ra_daemon import (
    DAEMON_BOTH,
    DAEMON_DNSMASQ,
    DAEMON_NONE,
    DAEMON_RADVD,
    REASON_BOTH_SERVING,
    REASON_DNSMASQ_SERVING,
    REASON_NEITHER,
    REASON_RADVD_DISABLED,
    REASON_RADVD_INTERFACE_DOWN,
    REASON_RADVD_INTERFACE_STATE_UNKNOWN,
    REASON_RADVD_SERVING,
    RaVerdict,
    classify_ra_daemons,
)


def _radvd(interface: str, *, enabled: str | bool | None = "1") -> dict:
    """Build a search_entry-shaped radvd row."""
    return {
        "uuid": f"ra-{interface}",
        "interface": interface,
        "enabled": enabled,
        "mode": "unmanaged",
    }


def _v6_range(
    interface: str,
    *,
    constructor: str | None = None,
    ra_mode: str = "slaac",
    start_addr: str = "::1000",
) -> dict:
    """Build a search_range-shaped dnsmasq row for a v6 range."""
    return {
        "uuid": f"range-{interface}",
        "interface": interface,
        "start_addr": start_addr,
        "end_addr": "::2000",
        "constructor": constructor if constructor is not None else interface,
        "ra_mode": ra_mode,
    }


def _v4_range(interface: str) -> dict:
    """Build a v4 range that must never count as dnsmasq RA."""
    return {
        "uuid": f"v4-{interface}",
        "interface": interface,
        "start_addr": "198.51.100.100",
        "end_addr": "198.51.100.200",
        "constructor": interface,
        "ra_mode": "slaac",
    }


def test_dnsmasq_only_interface() -> None:
    """A v6 range with constructor and non-off-link ra_mode serves via dnsmasq."""
    result = classify_ra_daemons(
        radvd_rows=[],
        dnsmasq_range_rows=[_v6_range("opt13")],
        interface_states={"opt13": True},
    )
    assert "opt13" in result
    verdict = result["opt13"]
    assert isinstance(verdict, RaVerdict)
    assert verdict.daemon == DAEMON_DNSMASQ
    assert verdict.dnsmasq_serving is True
    assert verdict.radvd_serving is False
    assert REASON_DNSMASQ_SERVING in verdict.reason_codes
    assert verdict.severity == "ok"


def test_radvd_enabled_but_interface_down_is_not_radvd() -> None:
    """Enabled radvd on an admin-down interface does not count as serving."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt2", enabled="1")],
        dnsmasq_range_rows=[],
        interface_states={"opt2": False},
    )
    verdict = result["opt2"]
    assert verdict.daemon == DAEMON_NONE
    assert verdict.radvd_serving is False
    assert verdict.interface_up is False
    assert REASON_RADVD_INTERFACE_DOWN in verdict.reason_codes
    assert REASON_NEITHER in verdict.reason_codes


def test_radvd_disabled_plus_dnsmasq_range_is_dnsmasq() -> None:
    """Disabled radvd plus a serving dnsmasq range → dnsmasq."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt13", enabled="0")],
        dnsmasq_range_rows=[_v6_range("opt13")],
        interface_states={"opt13": True},
    )
    verdict = result["opt13"]
    assert verdict.daemon == DAEMON_DNSMASQ
    assert verdict.dnsmasq_serving is True
    assert verdict.radvd_serving is False
    assert REASON_RADVD_DISABLED in verdict.reason_codes
    assert REASON_DNSMASQ_SERVING in verdict.reason_codes


def test_both_serving() -> None:
    """Enabled radvd on an up interface plus dnsmasq RA → both (misconfiguration)."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt5", enabled="1")],
        dnsmasq_range_rows=[_v6_range("opt5")],
        interface_states={"opt5": True},
    )
    verdict = result["opt5"]
    assert verdict.daemon == DAEMON_BOTH
    assert verdict.radvd_serving is True
    assert verdict.dnsmasq_serving is True
    assert REASON_BOTH_SERVING in verdict.reason_codes
    assert verdict.severity == "warning"


def test_neither() -> None:
    """No radvd and no qualifying dnsmasq range → none."""
    result = classify_ra_daemons(
        radvd_rows=[],
        dnsmasq_range_rows=[_v4_range("opt9")],
        interface_states={"opt9": True},
    )
    verdict = result["opt9"]
    assert verdict.daemon == DAEMON_NONE
    assert verdict.radvd_serving is False
    assert verdict.dnsmasq_serving is False
    assert REASON_NEITHER in verdict.reason_codes


def test_interface_states_none_does_not_silently_produce_radvd() -> None:
    """Without interface_states, enabled radvd must not be classified as radvd."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt2", enabled="1")],
        dnsmasq_range_rows=[],
        interface_states=None,
    )
    verdict = result["opt2"]
    assert verdict.daemon != DAEMON_RADVD
    assert verdict.daemon == DAEMON_NONE
    assert verdict.radvd_serving is False
    assert verdict.interface_up is None
    assert REASON_RADVD_INTERFACE_STATE_UNKNOWN in verdict.reason_codes


def test_radvd_only_when_enabled_and_up() -> None:
    """Enabled radvd on an up interface with no dnsmasq RA → radvd."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt7", enabled="1")],
        dnsmasq_range_rows=[],
        interface_states={"opt7": True},
    )
    verdict = result["opt7"]
    assert verdict.daemon == DAEMON_RADVD
    assert verdict.radvd_serving is True
    assert verdict.dnsmasq_serving is False
    assert REASON_RADVD_SERVING in verdict.reason_codes
    assert verdict.severity == "ok"


def test_radvd_enabled_false_and_empty_are_not_serving() -> None:
    """enabled in (False, '', None) never counts as radvd serving."""
    for enabled in (False, "", None):
        result = classify_ra_daemons(
            radvd_rows=[_radvd("opt8", enabled=enabled)],
            dnsmasq_range_rows=[],
            interface_states={"opt8": True},
        )
        verdict = result["opt8"]
        assert verdict.radvd_serving is False
        assert verdict.daemon == DAEMON_NONE
        assert REASON_RADVD_DISABLED in verdict.reason_codes


def test_off_link_ra_mode_is_not_dnsmasq_serving() -> None:
    """ra_mode off-link means the v6 range does not serve RA."""
    result = classify_ra_daemons(
        radvd_rows=[],
        dnsmasq_range_rows=[_v6_range("opt13", ra_mode="off-link")],
        interface_states={"opt13": True},
    )
    verdict = result["opt13"]
    assert verdict.dnsmasq_serving is False
    assert verdict.daemon == DAEMON_NONE


def test_empty_constructor_is_not_dnsmasq_serving() -> None:
    """A v6 range without constructor does not serve RA via dnsmasq."""
    result = classify_ra_daemons(
        radvd_rows=[],
        dnsmasq_range_rows=[_v6_range("opt13", constructor="")],
        interface_states={"opt13": True},
    )
    verdict = result["opt13"]
    assert verdict.dnsmasq_serving is False
    assert verdict.daemon == DAEMON_NONE


def test_colon_in_v4_description_does_not_make_v6() -> None:
    """v6 is only start_addr beginning with ::, not any colon in the row."""
    row = {
        "uuid": "tricky",
        "interface": "opt3",
        "start_addr": "172.20.3.100",
        "end_addr": "172.20.3.200",
        "constructor": "opt3",
        "ra_mode": "slaac",
        "description": "vlan:lab",
    }
    result = classify_ra_daemons(
        radvd_rows=[],
        dnsmasq_range_rows=[row],
        interface_states={"opt3": True},
    )
    assert result["opt3"].dnsmasq_serving is False
    assert result["opt3"].daemon == DAEMON_NONE


def test_classify_returns_union_of_interfaces() -> None:
    """Every interface named in either input appears in the result."""
    result = classify_ra_daemons(
        radvd_rows=[_radvd("opt1", enabled="0")],
        dnsmasq_range_rows=[_v6_range("opt2")],
        interface_states={"opt1": True, "opt2": True},
    )
    assert set(result) == {"opt1", "opt2"}
    assert result["opt1"].daemon == DAEMON_NONE
    assert result["opt2"].daemon == DAEMON_DNSMASQ
