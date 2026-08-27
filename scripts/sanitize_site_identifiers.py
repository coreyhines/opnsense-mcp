#!/usr/bin/env python3
"""Rewrite site-identifying values in fixtures, tests and docs to fictional ones.

Fixtures are captured from a live firewall, so every capture drags in the real
WAN address, the delegated IPv6 prefix, internal subnets, hardware MACs and the
site domain. This rewrites them to the fictional equivalents recorded in
`tests/fixtures/opnsense-26.7.2/README.md`, so those values never reach a
published copy of the repository.

**The real values are not in this file, and must never be.** An earlier version
held them inline, which meant the script itself leaked everything it existed to
remove. They live in a rules file that git ignores; run with no rules file to
see its shape.

The mapping is deterministic and structure-preserving: two different real values
never collapse onto one fictional value, subnet relationships survive, and
address shapes stay valid, so tests that assert on the values keep working.

`deploy/` is in scope for addresses. Its hostnames were the functional part and
have since been parameterised, so nothing there depends on a real value any
more; the addresses that remained were prompt examples, overridable defaults
and commented-out samples.

Usage:
    python3 scripts/sanitize_site_identifiers.py --check   # report, change nothing
    python3 scripts/sanitize_site_identifiers.py           # rewrite in place
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys

# Directories holding captured data, prose, test values, or the example
# addresses tool schemas show the model. `opnsense_mcp` is included because
# those schema examples end up in the published tool surface.
INCLUDE_ROOTS = ("tests", "docs", "examples", "opnsense_mcp", "scripts", "deploy")

SKIP_PARTS = frozenset(
    {".git", ".venv", "node_modules", "__pycache__", ".ruff_cache", ".pytest_cache"}
)
SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff2"})

# Files that must keep real-looking values to do their job. Rewriting one of
# these does not just churn text, it inverts what the file asserts: the gate's
# self-test ended up claiming documentation addresses were offenders. This is
# the same trap as the script sanitising itself, one file further out.
SKIP_FILES = frozenset(
    {
        # Asserts on values in deploy/lib.sh; rewriting it leaves the test
        # disagreeing with the code it covers.
        "tests/test_deploy_lib.py",
        # Proves the site-identifier gate can tell a real address from a
        # documentation one, so it has to contain both.
        "tests/test_no_site_identifiers.py",
    }
)

DEFAULT_RULES_PATH = ".site-identifiers.json"
RULES_ENV_VAR = "SITE_IDENTIFIER_RULES"

RULES_HELP = f"""\
No rules file found.

Real site identifiers must not live in the repository, so this script reads them
from a file git ignores. Create {DEFAULT_RULES_PATH} (or point
${RULES_ENV_VAR} at one elsewhere) shaped like:

  {{
    "regex_rules": [
      {{"pattern": "<regex matching a real value>",
       "replacement": "<fictional equivalent, backreferences allowed>",
       "note": "why this rule exists"}}
    ],
    "literals": {{"<real domain>": "frobozz.example"}},
    "sanitize_macs": true
  }}

Rules apply in order: regex, then literals, then MAC and EUI-64 handling.
"""

# A MAC's first three bytes name the hardware vendor, so they identify the kit on
# the network. Everything is remapped onto the locally-administered QEMU prefix,
# which is unmistakably synthetic. This rule is generic, so it stays here.
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
FAKE_OUI = "52:54:00"

# EUI-64 link-local addresses embed the MAC, leaking it a second time in a
# different shape, so they are rewritten through the same mapping.
EUI64_LL = re.compile(
    r"\bfe80::([0-9a-f]{1,4}):([0-9a-f]{1,4})ff:fe([0-9a-f]{1,2}):([0-9a-f]{1,4})\b",
    re.IGNORECASE,
)

SELF = pathlib.Path(__file__).resolve()


def _is_synthetic_mac(mac: str) -> bool:
    """Is this address already fictional?

    Bit 0x02 of the first byte marks a MAC as locally administered, which no
    manufacturer assigns. That makes it the exact discriminator wanted here:
    universally-administered addresses name real hardware and have to go,
    locally-administered ones are invented and must be left alone. Rewriting
    them anyway broke tests that assert on placeholder values like
    aa:bb:cc:dd:ee:ff, which is how this rule was found.
    """
    first = int(mac.split(":")[0], 16)
    return bool(first & 0x02) or mac.lower() in {
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
    }


def _fake_mac(real: str) -> str:
    """Map a real MAC onto 52:54:00:xx:xx:xx, keeping distinct inputs distinct."""
    if _is_synthetic_mac(real):
        return real
    digest = hashlib.sha256(real.lower().encode()).digest()
    return f"{FAKE_OUI}:{digest[0]:02x}:{digest[1]:02x}:{digest[2]:02x}"


def _mac_from_eui64(match: re.Match[str]) -> str:
    """Recover the MAC an EUI-64 link-local address encodes.

    EUI-64 interleaves the six MAC bytes around a literal ff:fe and flips the
    universal/local bit of the first one, so that bit is flipped back here.
    """
    head, third, fourth, tail = match.groups()
    head_value, tail_value = int(head, 16), int(tail, 16)
    return ":".join(
        f"{byte:02x}"
        for byte in (
            (head_value >> 8) ^ 0x02,
            head_value & 0xFF,
            int(third, 16),
            int(fourth, 16),
            tail_value >> 8,
            tail_value & 0xFF,
        )
    )


def _fake_link_local(match: re.Match[str]) -> str:
    """Rebuild a link-local address around the sanitised MAC.

    Goes through the real MAC so a device appearing both as a MAC and as a
    link-local address gets one fictional identity, not two.
    """
    real = _mac_from_eui64(match)
    if _is_synthetic_mac(real):
        return match.group(0)
    fake = [int(byte, 16) for byte in _fake_mac(real).split(":")]
    return (
        f"fe80::{fake[0] ^ 0x02:x}{fake[1]:02x}:{fake[2]:02x}ff:"
        f"fe{fake[3]:02x}:{fake[4]:02x}{fake[5]:02x}"
    )


def load_rules(path: pathlib.Path) -> dict:
    """Read and compile the rules file."""
    raw = json.loads(path.read_text())
    return {
        "regex": [
            (re.compile(rule["pattern"], re.IGNORECASE), rule["replacement"])
            for rule in raw.get("regex_rules", [])
        ],
        "literals": raw.get("literals", {}),
        "macs": raw.get("sanitize_macs", True),
    }


def sanitize(text: str, rules: dict) -> str:
    """Apply every replacement to a blob of text."""
    for pattern, replacement in rules["regex"]:
        text = pattern.sub(replacement, text)
    for real, fake in rules["literals"].items():
        text = text.replace(real, fake)
    if rules["macs"]:
        # Link-local first, so the embedded form is handled by the rule that
        # understands its shape rather than by the bare MAC rule.
        text = EUI64_LL.sub(_fake_link_local, text)
        text = MAC.sub(lambda m: _fake_mac(m.group(0)), text)
    return text


def target_files() -> list[pathlib.Path]:
    """Every text file under the included roots, excluding this script."""
    found: list[pathlib.Path] = []
    for root in INCLUDE_ROOTS:
        for path in pathlib.Path(root).rglob("*"):
            if not path.is_file() or path.resolve() == SELF:
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            if path.as_posix() in SKIP_FILES:
                continue
            found.append(path)
    return sorted(found)


def main() -> int:
    """Rewrite, or report what would be rewritten."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report files that would change, and exit non-zero if any would",
    )
    parser.add_argument(
        "--rules",
        default=os.environ.get(RULES_ENV_VAR, DEFAULT_RULES_PATH),
        help=f"path to the rules file (default {DEFAULT_RULES_PATH}, "
        f"or ${RULES_ENV_VAR})",
    )
    args = parser.parse_args()

    rules_path = pathlib.Path(args.rules)
    if not rules_path.is_file():
        # Silently doing nothing would look exactly like a clean tree.
        print(RULES_HELP, file=sys.stderr)
        return 2
    rules = load_rules(rules_path)

    changed: list[pathlib.Path] = []
    for path in target_files():
        try:
            original = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        cleaned = sanitize(original, rules)
        if cleaned == original:
            continue
        changed.append(path)
        if not args.check:
            path.write_text(cleaned)

    verb = "would change" if args.check else "rewrote"
    for path in changed:
        print(f"  {verb}: {path}")
    print(f"{len(changed)} files {verb}")
    return 1 if (args.check and changed) else 0


if __name__ == "__main__":
    sys.exit(main())
