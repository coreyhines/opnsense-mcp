import pytest

from opnsense_mcp.utils.dhcp_provider import (
    provider_supports_host_move,
    require_host_provider,
)


class _Supports:
    name = "dnsmasq"
    HOST_MOVE_SUPPORTED = True


class _NoSupport:
    name = "isc"
    HOST_MOVE_SUPPORTED = False


def test_provider_supports_host_move():
    assert provider_supports_host_move(_Supports()) is True
    assert provider_supports_host_move(_NoSupport()) is False


def test_require_host_provider_raises_for_unsupported():
    with pytest.raises(ValueError, match="host move"):
        require_host_provider(_NoSupport())


def test_require_host_provider_returns_supported():
    p = _Supports()
    assert require_host_provider(p) is p
