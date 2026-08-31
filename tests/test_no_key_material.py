"""Guard against a WireGuard key reaching the repository.

The API returns instance private keys in cleartext on every read path, unasked,
so a capture taken the obvious way contains one. The identifier check matches
addresses and hostnames and would not notice.

The check is structural: a 44-character base64 string that decodes to exactly
32 bytes is a Curve25519 key, whatever it is called. The placeholder fixtures
use is deliberately all one character, so it is excluded by the entropy floor
rather than by being named here.
"""

from __future__ import annotations

import base64
import binascii
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCANNED_ROOTS = ("tests", "docs", "examples", "opnsense_mcp", "scripts", "deploy")
SKIP_PARTS = frozenset({".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"})
SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff2"})

B64_32 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def _looks_like_a_key(candidate: str) -> bool:
    """True for 32 bytes of base64 that is not a repeated-character placeholder."""
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 32:
        return False
    # A placeholder is one character repeated. A real key is not.
    return len(set(candidate[:43])) > 4


def _scanned_files() -> list[pathlib.Path]:
    found = []
    for root in SCANNED_ROOTS:
        for path in (REPO_ROOT / root).rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            found.append(path)
    return sorted(found)


@pytest.mark.parametrize("path", _scanned_files(), ids=lambda p: p.name)
def test_no_curve25519_key_material_is_committed(path: pathlib.Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    offenders = [c for c in B64_32.findall(text) if _looks_like_a_key(c)]
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} contains what decodes to a 32-byte key. "
        f"Replace it with a same-length placeholder; do not widen this check."
    )


def test_the_check_would_catch_a_real_key() -> None:
    """Recorded so the check's own reach is known rather than assumed."""
    real = base64.b64encode(bytes(range(32))).decode()
    assert _looks_like_a_key(real)

    placeholder = "A" * 43 + "="
    assert not _looks_like_a_key(placeholder)

    assert not _looks_like_a_key("A" * 43 + "!")
    assert not _looks_like_a_key(base64.b64encode(b"short").decode())
