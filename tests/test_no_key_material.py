"""Guard against a WireGuard key reaching the repository.

The API returns instance private keys in cleartext on every read path, unasked,
so a capture taken the obvious way contains one. The identifier check matches
addresses and hostnames and would not notice.

The check is structural: a 44-character base64 string that decodes to exactly
32 bytes is a Curve25519 key, whatever it is called. The placeholder fixtures
use is deliberately all one character, so it is excluded by the entropy floor
rather than by being named here.

The walk starts at the repository root rather than at a list of directories.
An include list of six subdirectories exempted every root-level file, which is
where a throwaway capture script and the JSON it writes land, and it exempts
whatever top-level directory is added next.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
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


def offenders_in(text: str) -> list[str]:
    """The whole scanner: what the pattern extracts and the predicate keeps.

    One function, so the reach test below exercises the pattern too. The pattern
    decides what the predicate ever sees, so a pattern narrowed to nothing makes
    every file pass while a predicate-only reach test still reports the check as
    sound.

    PHP's `json_encode` escapes a forward slash, so a captured key containing
    one arrives as `a\\/b` and is split by the character class. Undoing that
    escape first is cheaper than a pattern that tolerates it.
    """
    return [c for c in B64_32.findall(text.replace("\\/", "/")) if _looks_like_a_key(c)]


def _is_nested_checkout(path: pathlib.Path) -> bool:
    """True when *path* is a git checkout in its own right.

    A worktree created under the repository (agents put them in
    `.claude/worktrees/`) is a whole second copy of the tree. Walking into one
    doubles every parametrised case and makes the count depend on what happens
    to be left lying around, and a stale copy can fail the suite over a key that
    no longer exists in git, which is unfindable from the failure message.

    Detected by the `.git` entry every checkout carries rather than by name, so
    a nested clone or a worktree somewhere else is pruned too.
    """
    return (path / ".git").exists()


def _scanned_files() -> list[pathlib.Path]:
    """Every file in the repository, pruning what cannot hold readable text."""
    found = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        here = pathlib.Path(dirpath)
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_PARTS and not _is_nested_checkout(here / name)
        ]
        for filename in filenames:
            path = here / filename
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            found.append(path)
    return sorted(found)


def _identifier(path: pathlib.Path) -> str:
    """A test id that says where the file is.

    Seven basenames repeat across the repository, `README.md` among them, and a
    basename id renders them as `README.md0` and `README.md1`.
    """
    return path.relative_to(REPO_ROOT).as_posix()


@pytest.mark.parametrize("path", _scanned_files(), ids=_identifier)
def test_no_curve25519_key_material_is_committed(path: pathlib.Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    assert not offenders_in(text), (
        f"{path.relative_to(REPO_ROOT)} contains what decodes to a 32-byte key. "
        f"Replace it with a same-length placeholder; do not widen this check."
    )


def test_the_walk_reaches_the_repository_root() -> None:
    """An empty parameter set skips rather than fails, so a walk that found
    nothing would read as a clean run. The root is named because that is the
    part an include list left out."""
    scanned = {_identifier(path) for path in _scanned_files()}

    assert scanned
    assert "README.md" in scanned
    assert "benchmark_performance.py" in scanned
    assert "tests/test_no_key_material.py" in scanned


def _synthetic_key(seed: bytes) -> str:
    """A 44-character base64 value with a real key's shape, derived from a hash.

    Derived rather than written down, so this file carries no literal a reader
    could mistake for key material and the guard does not flag itself.
    """
    return base64.b64encode(hashlib.sha256(seed).digest()).decode()


def test_the_check_would_catch_a_real_key() -> None:
    """Recorded so the check's own reach is known rather than assumed."""
    real = base64.b64encode(bytes(range(32))).decode()
    assert _looks_like_a_key(real)

    placeholder = "A" * 43 + "="
    assert not _looks_like_a_key(placeholder)

    assert not _looks_like_a_key("A" * 43 + "!")
    assert not _looks_like_a_key(base64.b64encode(b"short").decode())


def test_the_scanner_finds_a_key_in_every_spelling_one_would_arrive_in() -> None:
    """End to end, pattern included.

    Narrowing the pattern's quantifier from 43 to 44 characters extracts nothing
    from any of these, which is a hole the predicate alone cannot see.
    """
    key = _synthetic_key(b"reach probe")

    assert offenders_in(f'{{"privkey": "{key}"}}') == [key]
    assert offenders_in(f"PrivateKey = {key}") == [key]
    assert offenders_in(f'SERVER_KEYS = ["{key}"]') == [key]
    assert offenders_in(f"the key is {key}, apparently") == [key]

    placeholder = "A" * 43 + "="
    assert offenders_in(f'{{"privkey": "{placeholder}"}}') == []


def test_the_scanner_is_not_defeated_by_an_escaped_slash() -> None:
    """A PHP-encoded capture writes `/` as `\\/`, which splits the character
    class in two and leaves neither half 43 characters long."""
    key = next(
        candidate
        for candidate in (_synthetic_key(f"slash {n}".encode()) for n in range(200))
        if "/" in candidate
    )

    escaped = key.replace("/", "\\/")
    assert offenders_in(f'{{"privkey": "{escaped}"}}') == [key]


def test_a_nested_checkout_is_not_scanned() -> None:
    """A worktree under the repository must not be walked.

    Agents create worktrees in `.claude/worktrees/`. Each is a second copy of
    the whole tree, so walking one doubled the parametrised suite from 2,125
    cases to 4,231 and made the count depend on leftover state. Worse, a stale
    copy carrying a key the main tree no longer has fails this check over a file
    that `git ls-files` cannot find.
    """
    nested = REPO_ROOT / ".claude" / "worktrees" / "_probe_nested_checkout"
    nested.mkdir(parents=True, exist_ok=False)
    planted = nested / "planted.txt"
    try:
        # What a real worktree carries: a `.git` file pointing at the parent.
        (nested / ".git").write_text("gitdir: /nowhere\n")
        planted.write_text(base64.b64encode(hashlib.sha256(b"probe").digest()).decode())

        # The planted value must be the thing the check would otherwise catch,
        # or this test passes because the file is uninteresting rather than
        # because it was pruned.
        assert offenders_in(planted.read_text()), "the planted value is not key-shaped"

        assert planted not in set(_scanned_files())
    finally:
        # Gated on the mkdir above having succeeded, which exist_ok=False
        # guarantees: this only ever removes a directory this test created.
        for path in (planted, nested / ".git"):
            if path.exists():
                path.unlink()
        nested.rmdir()
