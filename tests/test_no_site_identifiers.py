"""Guard against real network identifiers reaching a published copy.

Fixtures come off a live firewall, so every capture reintroduces the risk. The
2026-08-25 sanitisation pass covered one fixture directory and missed the rest,
which sat in a public repository for two months. This is the check that would
have caught it.

The check is structural rather than a denylist. A denylist needs the real values
to compare against, which cannot live in the repository without defeating the
point, and it only ever catches identifiers somebody thought to list. Asserting
the inverse — that every address present is one of the ranges reserved for
documentation — needs no secret and catches values nobody anticipated,
including whatever the next capture drags in.

Consequence worth knowing: this fails on a *new* real address, not on a
specific known one. The fix is always to run
`scripts/sanitize_site_identifiers.py`, never to widen the allowlist, unless
the value genuinely belongs to one of the exempt categories below.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Captured data, prose, test values, and the example addresses tool schemas
# show the model. Mirrors INCLUDE_ROOTS in the sanitiser.
SCANNED_ROOTS = ("tests", "docs", "examples", "opnsense_mcp")

SKIP_PARTS = frozenset({".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"})
SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff2"})

SKIP_FILES = frozenset(
    {
        # Asserts on values in deploy/, which is out of scope for sanitisation
        # because its hostnames are functional defaults, not captured data.
        "tests/test_deploy_lib.py",
        # This file. It has to contain real-looking addresses to prove the
        # discriminator can tell them apart.
        "tests/test_no_site_identifiers.py",
        # A vendor OUI database. Its columns produce dotted-quad lookalikes, and
        # nothing in it describes this site.
        "opnsense_mcp/utils/data/oui.csv",
    }
)

# Reserved for documentation and examples: RFC 5737, RFC 3849, plus the site's
# chosen fictional ULA. Anything outside these is presumed real.
ALLOWED_V4 = tuple(
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
ALLOWED_V6 = (ipaddress.ip_network("2001:db8::/32"), ipaddress.ip_network("fd0b::/16"))

# The fictional private range this project standardised on, plus the ranges that
# read as generic examples anywhere in the industry rather than as one site's
# addressing.
ALLOWED_PRIVATE_V4 = tuple(
    ipaddress.ip_network(net) for net in ("172.16.0.0/12", "192.168.0.0/16")
)

# 10.0.0.0/8 is deliberately absent. That is where this site actually addresses,
# so allowing it would blind the check to the leak it exists to prevent, which
# is precisely what went unnoticed for two months.

# Globally-known public resolvers. Real addresses, but they name a public
# service rather than anything about this site, and tests need a plausible
# upstream to point at.
ALLOWED_PUBLIC_HOSTS = frozenset(
    {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
)

V4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Groups may be empty, so `::` compression is matched. Requiring non-empty
# groups misses almost every address written the way people actually write
# them, including the real delegated prefix; the self-test below is what caught
# that. Anything the regex over-matches, such as a MAC or a timestamp, fails
# IPv6 parsing and is dropped.
V6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")


def _scanned_files() -> list[pathlib.Path]:
    """Every text file the sanitiser is responsible for."""
    found: list[pathlib.Path] = []
    for root in SCANNED_ROOTS:
        for path in (REPO_ROOT / root).rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            if path.relative_to(REPO_ROOT).as_posix() in SKIP_FILES:
                continue
            found.append(path)
    return sorted(found)


def _is_exempt_v4(address: ipaddress.IPv4Address) -> bool:
    """Addresses that identify nothing about a site."""
    return (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or str(address).endswith(".255")  # broadcast
        or address in ipaddress.ip_network("255.255.0.0/16")  # netmasks
    )


# The all-zero base of a well-known block, written as vocabulary rather than as
# an address: "a stable fd00::/8 prefix" names the ULA range the way 10.0.0.0/8
# names an RFC 1918 one.
V6_BLOCK_LABELS = frozenset({"fd00::", "fc00::", "2001:db8::", "fe80::"})

SUFFIX_ONLY = ipaddress.ip_network("::/64")


def _is_exempt_v6(address: ipaddress.IPv6Address) -> bool:
    """Same, for v6. Link-local is exempt as an address but not as a MAC.

    An EUI-64 link-local embeds a hardware MAC, so it is handled by the
    sanitiser rather than waved through here.

    Addresses inside ::/64 are host suffixes, not addresses: this codebase
    moves hosts between prefixes by suffix, so "::13" appears throughout and
    identifies nothing on its own.
    """
    return (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address in SUFFIX_ONLY
        or str(address) in V6_BLOCK_LABELS
    )


def _offending_v4(text: str) -> list[str]:
    """Every IPv4 address in `text` that is neither documentation nor exempt."""
    bad = []
    for candidate in V4.findall(text):
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue  # version strings and the like
        if _is_exempt_v4(address) or candidate in ALLOWED_PUBLIC_HOSTS:
            continue
        if any(address in net for net in ALLOWED_V4 + ALLOWED_PRIVATE_V4):
            continue
        bad.append(candidate)
    return bad


def _offending_v6(text: str) -> list[str]:
    """Every IPv6 address in `text` that is neither documentation nor exempt."""
    bad = []
    for candidate in V6.findall(text):
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue  # MAC addresses and timestamps share this shape
        if _is_exempt_v6(address):
            continue
        if any(address in net for net in ALLOWED_V6):
            continue
        bad.append(candidate)
    return bad


@pytest.mark.parametrize("path", _scanned_files(), ids=lambda p: str(p.name))
def test_addresses_are_documentation_ranges_only(path: pathlib.Path) -> None:
    """No file carries an address outside the ranges reserved for examples."""
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        pytest.skip("not a text file")

    offenders = sorted(set(_offending_v4(text) + _offending_v6(text)))
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} contains addresses outside the "
        f"documentation ranges: {', '.join(offenders)}. "
        f"Run scripts/sanitize_site_identifiers.py rather than widening the "
        f"allowlist."
    )


def test_the_check_would_catch_a_real_address() -> None:
    """A gate that never fires is indistinguishable from one that works.

    This pins the discriminator itself, so a future change that quietly widens
    the allowlist to everything gets caught.
    """
    assert _offending_v4("connect to 68.47.7.163 for the WAN") == ["68.47.7.163"]
    assert _offending_v4("host 10.0.8.50 on the lab net") == ["10.0.8.50"]
    assert _offending_v6("2601:441:8483:b508::1 is the gateway") == [
        "2601:441:8483:b508::1"
    ]

    assert _offending_v4("203.0.113.1 and 172.20.8.50 and 127.0.0.1") == []
    assert _offending_v6("2001:db8:5eed:b508::1 and fd0b:b022:101::1") == []
