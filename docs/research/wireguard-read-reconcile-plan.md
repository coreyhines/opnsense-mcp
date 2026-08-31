# WireGuard read and reconcile (WG-1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the firewall's WireGuard instances and peers as MCP reads, and a
`reconcile` that reports where the stored config and the running kernel disagree.

**Architecture:** One module, `opnsense_mcp/tools/wireguard.py`, holding a shared
base plus three tool classes, presented as one `wireguard` group. Every read goes
through the search grids, never the get node trees, because the two return
different types for the same field names. Pure parsing helpers are module-level
functions so they can be tested against captured responses without a client.

**Tech Stack:** Python 3.12, `uv`, pytest, ruff. No new dependencies.

**Spec:** `docs/research/wireguard-read-reconcile-design.md`

## Global Constraints

- Nothing in this plan writes to the firewall. No `add*`, `set*`, `del*`,
  `toggle*`, `apply`, `reconfigure` or service control call appears anywhere.
- `privkey` and `psk` never appear in tool output. The read path is an
  allowlist, so a field added upstream is omitted rather than leaked.
- `wg2SiteToSite` is a deliberately disabled reference specimen. It is read and
  never modified, and never enabled.
- Endpoint spelling is camelCase throughout (`searchServer`, `searchClient`).
  snake_case resolves to the same route; do not add fallback logic.
- `rowCount` is never sent. Every listing asserts `len(rows) == total`.
- Addresses and names below are the sanitised forms that will exist in the
  fixtures. `docs/` and `tests/` are both scanned by
  `tests/test_no_site_identifiers.py`.

---

## File structure

| File | Responsibility |
|---|---|
| `opnsense_mcp/tools/wireguard.py` | endpoints, parsing helpers, three tool classes |
| `tests/test_wireguard.py` | helper and tool behaviour against captured fixtures |
| `tests/test_no_key_material.py` | repo-wide guard: no committed WireGuard key |
| `tests/fixtures/opnsense-26.7.3/wg_*.json` | captured responses, sanitised |
| `opnsense_mcp/utils/registry.py` | register the three tools |
| `opnsense_mcp/utils/tool_groups.py` | present them as the `wireguard` group |

Parsing helpers live at module level rather than on the base class. They take a
dict and return a value, so every one of them is testable against a fixture with
no client, no async, and no mock.

---

### Task 1: Fixtures, sanitisation, and the key-material guard

Nothing can be tested until captured responses exist in the repository, and
nothing may be committed until the sanitiser knows about the site's current
prefixes. This task does both and adds the guard that catches the failure the
existing checks cannot see.

**Files:**
- Create: `tests/fixtures/opnsense-26.7.3/wg_searchserver_rows.json`
- Create: `tests/fixtures/opnsense-26.7.3/wg_searchclient_rows.json`
- Create: `tests/fixtures/opnsense-26.7.3/wg_service_show_rows.json`
- Create: `tests/fixtures/opnsense-26.7.3/wg_getserver_dangling.json`
- Create: `tests/fixtures/opnsense-26.7.3/wg_interfaces_info_wg0.json`
- Create: `tests/test_no_key_material.py`
- Modify: `.site-identifiers.json` (git-ignored; a local edit, not committed)

**Interfaces:**
- Consumes: nothing.
- Produces: the five fixture paths above, loaded by every later task.

- [ ] **Step 1: Add the missing sanitiser rules**

`.site-identifiers.json` is git-ignored and holds the real values. Its existing
ULA rule predates the site's current prefix and does not match it, so a captured
fixture would reach the identifier check unsanitised.

Add to `regex_rules`. Read the site's ULA `/48` off the `tunneladdress` field
of the enabled instance in the `searchServer` capture from step 2, and substitute
its first three groups for `<ula-48>` below (the pattern captures the fourth):

```json
{
  "note": "site ULA; maps into fd0b::/16, which the identifier check allows",
  "pattern": "\\b<ula-48>:([0-9a-f]{1,4})\\b",
  "replacement": "fd0b:cafe:\\1"
},
{
  "note": "site-to-site tunnel net; 10/8 is deliberately not allow-listed",
  "pattern": "\\b10\\.181\\.0\\.(\\d{1,3})\\b",
  "replacement": "172.20.181.\\1"
}
```

Add to `literals`, so peer and instance names do not identify people:

```json
"freeblizzS2S": "wg2SiteToSite",
"trogdor": "dualStackPeer",
"coreyIphone": "peerA",
"coreyIpad": "peerB",
"nilaIphone": "peerC",
"sulaIphone": "peerD",
"jamesIphone": "peerE",
"jamesIpad": "peerF",
"macbookProArista": "peerG",
"dadiPad": "peerH",
"sulalaptop": "peerI"
```

- [ ] **Step 2: Capture the five responses**

Read-only. Run each against the firewall and save the `response` object (not the
probe wrapper) as the fixture file.

```
POST /api/wireguard/server/searchServer          {}   -> wg_searchserver_rows.json
POST /api/wireguard/client/searchClient          {}   -> wg_searchclient_rows.json
POST /api/wireguard/service/show                 {}   -> wg_service_show_rows.json
POST /api/wireguard/server/getServer/<uuid>      {}   -> wg_getserver_dangling.json
POST /api/interfaces/overview/interfaces_info    {}   -> wg_interfaces_info_wg0.json
```

For the last one, keep only the row whose `device` is `wg0`, wrapped as
`{"rows": [ ... ], "total": 1, "rowCount": 1, "current": 1}`. The full response
carries every interface on the box and nothing here needs them.

`<uuid>` is the uuid of `wg1RemoteLabUsers`, taken from the `searchServer`
capture. It must be that instance specifically. It is the
one whose `peers` node map holds eleven keys with zero selected while its search
row claims one peer, which is the disagreement two later tests pin.

- [ ] **Step 3: Replace key material with same-length placeholders**

Every `privkey`, `pubkey`, `psk` and `public-key` value becomes a 44-character
placeholder, so the shape stays honest and the secret does not exist in the
repository:

```python
import json, pathlib, re

PLACEHOLDER = "A" * 43 + "="
KEYS = {"privkey", "pubkey", "psk", "public-key"}

def scrub(node):
    if isinstance(node, dict):
        return {k: (PLACEHOLDER if k in KEYS and v else scrub(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [scrub(v) for v in node]
    return node

for path in pathlib.Path("tests/fixtures/opnsense-26.7.3").glob("wg_*.json"):
    path.write_text(json.dumps(scrub(json.loads(path.read_text())), indent=2) + "\n")
```

- [ ] **Step 4: Run the sanitiser and verify**

```bash
uv run python scripts/sanitize_site_identifiers.py && uv run pytest tests/test_no_site_identifiers.py -q
```

Expected: PASS. If it names an address, add a rule to `.site-identifiers.json`
and run again. Never widen the allowlist in the test.

- [ ] **Step 5: Write the failing key-material test**

`tests/test_no_site_identifiers.py` matches addresses and hostnames. Nothing
matches a base64 key, so a committed private key would pass every check in the
repository today.

```python
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
```

- [ ] **Step 6: Run it**

```bash
uv run pytest tests/test_no_key_material.py -q
```

Expected: PASS, including on the fixtures written in step 3. If a fixture fails,
step 3 missed a field name; add it to `KEYS` and rerun step 3.

- [ ] **Step 7: Commit**

```bash
git add tests/fixtures/opnsense-26.7.3/wg_*.json tests/test_no_key_material.py && git commit -m "Add WireGuard fixtures and a key-material guard"
```

---

### Task 2: Module skeleton and parsing helpers

Every failure the spec names is in parsing, not in transport, so the helpers are
built and tested first against the fixtures with no client involved.

**Files:**
- Create: `opnsense_mcp/tools/wireguard.py`
- Create: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: the fixtures from Task 1.
- Produces: `WG_SERVER`, `WG_CLIENT`, `WG_SERVICE`, `CORE_SERVICE`, `INTERFACES`;
  `TruncatedListing`; `rows_or_refuse(payload, what) -> list[dict]`;
  `record_or_none(payload, key) -> dict | None`;
  `get_path(base, uuid) -> str`; `split_list(value) -> list[str]`;
  `selected_keys(node) -> list[str]`; `is_host_route(entry) -> bool`;
  `networks_of(entries) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]`;
  `public_instance(row, **extra) -> dict`; `public_peer(row, **extra) -> dict`;
  `_WgToolBase` with `_no_client()` and `async _search(endpoint, body=None)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_wireguard.py`:

```python
"""WireGuard parsing, tested against responses captured from 26.7.3.

Every test here pins a way the API can be misread while raising nothing. The
search grid and the get node tree share field names and disagree on types for
four of them; a peer's Allowed-IPs live in a field called `tunneladdress` while
a field named `allowed_ips` exists only on servers and is empty on every row;
and both read paths hand back the instance private key unasked.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from opnsense_mcp.tools.wireguard import (
    TruncatedListing,
    get_path,
    is_host_route,
    networks_of,
    public_instance,
    public_peer,
    record_or_none,
    rows_or_refuse,
    selected_keys,
    split_list,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def test_rows_or_refuse_returns_every_row_when_the_page_is_whole() -> None:
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    assert len(rows) == 3
    assert {r["name"] for r in rows} == {
        "wg0HomeVpn",
        "wg1RemoteLabUsers",
        "wg2SiteToSite",
    }


def test_rows_or_refuse_refuses_a_truncated_page() -> None:
    """A short page must refuse, never return quietly.

    `rowCount` is deliberately never sent, so total and len(rows) agree. If that
    default ever changes, a caller acting on a partial view is the failure this
    prevents.
    """
    with pytest.raises(TruncatedListing):
        rows_or_refuse({"rows": [{"uuid": "a"}], "total": 9}, "instances")


def test_rows_or_refuse_refuses_a_payload_that_is_not_a_search_result() -> None:
    with pytest.raises(TruncatedListing):
        rows_or_refuse([], "instances")


def test_record_or_none_treats_an_empty_array_as_not_found() -> None:
    """An unknown uuid answers HTTP 200 with `[]`, not a 404."""
    assert record_or_none([], "server") is None
    assert record_or_none({"server": {"name": "x"}}, "server") == {"name": "x"}


def test_get_path_refuses_an_empty_uuid() -> None:
    """getServer with no uuid answers 200 with a blank new-instance template.

    A path built by concatenation with an empty uuid would read that template
    and report it as a real record.
    """
    with pytest.raises(ValueError):
        get_path("/api/wireguard/server/getServer", "")
    assert get_path("/api/wireguard/server/getServer", "abc").endswith("/abc")


def test_split_list_strips_the_space_the_resolved_form_uses() -> None:
    """Raw lists join on ',' and resolved ones on ', '."""
    assert split_list("a,b,c") == ["a", "b", "c"]
    assert split_list("peerA, peerB, peerC") == ["peerA", "peerB", "peerC"]
    assert split_list("") == []
    assert split_list(None) == []


def test_selected_keys_ignores_unselected_options_and_the_empty_key() -> None:
    """Membership is the selected flag, never the keys.

    The node map enumerates every peer on the box. An empty list is encoded as
    one selected node with an empty key, so a length check cannot tell empty
    from one entry.
    """
    node = {
        "a": {"value": "peerA", "selected": 1},
        "b": {"value": "peerB", "selected": 0},
        "": {"value": "", "selected": 1},
    }
    assert selected_keys(node) == ["a"]
    assert selected_keys({}) == []
    assert selected_keys("not a node map") == []


def test_the_dangling_instance_has_no_selected_peers() -> None:
    """The live disagreement, straight from the fixture."""
    record = record_or_none(fixture("wg_getserver_dangling"), "server")
    assert record is not None
    assert len(record["peers"]) == 11
    assert selected_keys(record["peers"]) == []


def test_is_host_route_uses_the_family_maximum() -> None:
    assert is_host_route("192.168.10.2/32")
    assert is_host_route("fd0b:cafe:f::2/128")
    assert is_host_route("192.168.11.1")  # no prefix length is a host route
    assert not is_host_route("192.168.99.0/24")
    assert not is_host_route("fd0b:cafe:f::/64")


def test_networks_of_reads_the_network_not_the_address() -> None:
    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])
    assert [str(n) for n in nets] == ["192.168.10.0/24", "fd0b:cafe:f::/64"]
    assert networks_of(["nonsense"]) == []


def test_public_instance_omits_every_key_field() -> None:
    """The allowlist, checked on the row the API really sends."""
    row = next(
        r
        for r in rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
        if r["name"] == "wg0HomeVpn"
    )
    assert row["privkey"], "fixture no longer carries the field being guarded"

    public = public_instance(row)

    assert "privkey" not in public
    assert "pubkey" not in public
    assert public["has_privkey"] is True
    assert json.dumps(public).find(row["privkey"]) == -1


def test_public_peer_omits_every_key_field() -> None:
    row = rows_or_refuse(fixture("wg_searchclient_rows"), "peers")[0]
    public = public_peer(row)
    assert "privkey" not in public
    assert "psk" not in public
    assert "pubkey" not in public


def test_every_instance_normalizes_to_a_non_empty_tunnel_address() -> None:
    """The assertion whose absence let the any->any defect ship."""
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    for row in rows:
        public = public_instance(row)
        assert public["tunnel_addresses"], f"empty for {public['name']!r}"


def test_every_peer_normalizes_to_a_non_empty_allowed_ips() -> None:
    """Read from `tunneladdress`. The field named `allowed_ips` is a server
    field and is empty on every row, so reaching for the obvious name yields an
    always-empty column and a green suite."""
    rows = rows_or_refuse(fixture("wg_searchclient_rows"), "peers")
    for row in rows:
        public = public_peer(row)
        assert public["allowed_ips"], f"empty for {public['name']!r}"


def test_the_server_field_named_allowed_ips_is_empty_on_every_row() -> None:
    """Recorded so nobody reaches for it later believing it holds something."""
    rows = rows_or_refuse(fixture("wg_searchserver_rows"), "instances")
    assert all(row.get("allowed_ips", "") == "" for row in rows)
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q
```

Expected: collection error, `ModuleNotFoundError: opnsense_mcp.tools.wireguard`.

- [ ] **Step 3: Write the module**

Create `opnsense_mcp/tools/wireguard.py`:

```python
"""WireGuard instances, peers, and drift between config and the running kernel.

Field names come from the firmware model (`OPNsense/Wireguard/Server.xml` and
`Client.xml`) and were confirmed against captured responses, because the two
read paths disagree in ways a normalizer cannot notice. `dns`, `tunneladdress`,
`carp_depend_on` and `peers` are comma-joined strings in a search row and
`{key: {value, selected}}` maps in a get, while the other eighteen fields are
identical in both. So everything here lists from the search grid, and uses a get
only to read one record.

Two names are traps worth stating once. A peer's server-side Allowed-IPs live in
`tunneladdress`; the field literally named `allowed_ips` exists only on servers
and is empty on every row. And `endpoint` means a live `host:port` on a runtime
peer row, the listen port on a runtime interface row, and an empty string on
every config row.

Nothing here writes.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)

WG_SERVER = {
    "search": "/api/wireguard/server/searchServer",
    "get": "/api/wireguard/server/getServer",
}
WG_CLIENT = {
    "search": "/api/wireguard/client/searchClient",
    "get": "/api/wireguard/client/getClient",
}
WG_SERVICE = {"show": "/api/wireguard/service/show"}
CORE_SERVICE = "/api/core/service/search"
INTERFACES = "/api/interfaces/overview/interfaces_info"

# Both read paths return the instance private key in cleartext, so the public
# shape is an allowlist: a field added upstream is omitted rather than leaked.
INSTANCE_PUBLIC = (
    "uuid",
    "name",
    "enabled",
    "instance",
    "interface",
    "port",
    "mtu",
    "gateway",
    "disableroutes",
)
PEER_PUBLIC = ("uuid", "name", "enabled", "keepalive")


class TruncatedListing(Exception):
    """A search returned fewer rows than it says exist."""


def rows_or_refuse(payload: Any, what: str) -> list[dict[str, Any]]:
    """Rows from a search payload, refusing anything short of the whole set.

    `rowCount` is deliberately never sent, and omitting it returns every row, so
    `total` and the row count agree. Asserting that turns a future change in the
    default into a failure rather than a silently short list.
    """
    if not isinstance(payload, dict):
        raise TruncatedListing(
            f"the {what} listing returned {type(payload).__name__}, not a search result"
        )
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise TruncatedListing(f"the {what} listing carries no rows")
    total = payload.get("total")
    if isinstance(total, int) and total != len(rows):
        raise TruncatedListing(
            f"the {what} listing is truncated ({len(rows)} of {total}); refusing "
            f"rather than acting on a partial view"
        )
    return [row for row in rows if isinstance(row, dict)]


def record_or_none(payload: Any, key: str) -> dict[str, Any] | None:
    """The record under *key*, or None.

    An unknown uuid answers HTTP 200 with `[]`: an empty array, not an object
    and not a 404. Nothing in the transport can see that.
    """
    if not isinstance(payload, dict):
        return None
    record = payload.get(key)
    return record if isinstance(record, dict) else None


def get_path(base: str, uuid: str) -> str:
    """The per-record path, refusing an empty uuid.

    `getServer` with no uuid answers 200 with a fully-formed blank template for
    a new instance, so concatenating an empty uuid reads the template and
    reports it as a record.
    """
    if not uuid:
        raise ValueError(
            "uuid is required; an empty uuid reads a blank new-instance template "
            "at HTTP 200"
        )
    return f"{base}/{uuid}"


def split_list(value: Any) -> list[str]:
    """Split a comma-joined list field.

    Raw uuid lists join on ',' and their %-prefixed resolved twins join on ', ',
    so a shared splitter has to strip or every name after the first keeps a
    leading space.
    """
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def selected_keys(node: Any) -> list[str]:
    """Option keys a node map marks selected, dropping the empty-key entry.

    The map enumerates every candidate on the box with membership carried only
    by the flag, so the keys alone report every peer as belonging to every
    instance. An empty list is encoded as one selected node with an empty key,
    which is why the key is checked as well as the flag.
    """
    if not isinstance(node, dict):
        return []
    return [
        key
        for key, option in node.items()
        if key and isinstance(option, dict) and str(option.get("selected", "0")) == "1"
    ]


def is_host_route(entry: str) -> bool:
    """True when the entry addresses one host rather than a network."""
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return network.prefixlen == network.max_prefixlen


def networks_of(entries: list[str]) -> list[Any]:
    """The networks a list of interface-style addresses belongs to.

    An entry with no prefix length becomes a host network, which is what the
    firewall means by it: one instance carries a bare address as its whole
    tunnel address.
    """
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_interface(entry).network)
        except ValueError:
            logger.debug("unreadable tunnel address %r", entry)
    return networks


def public_instance(row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """One instance as a caller sees it. Allowlisted; no key material."""
    public: dict[str, Any] = {field: row.get(field, "") for field in INSTANCE_PUBLIC}
    public["tunnel_addresses"] = split_list(row.get("tunneladdress"))
    public["dns"] = split_list(row.get("dns"))
    public["peer_uuids"] = split_list(row.get("peers"))
    # `%peers` is emitted only when a name differs from the uuid, and is absent
    # rather than empty when nothing resolves. Display only.
    public["peer_names"] = split_list(row.get("%peers", ""))
    public["has_privkey"] = bool(row.get("privkey"))
    public.update(extra)
    return public


def public_peer(row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """One peer as a caller sees it. Allowlisted; no key material."""
    public: dict[str, Any] = {field: row.get(field, "") for field in PEER_PUBLIC}
    # Server-side Allowed-IPs. Not `allowed_ips`, which is a server field and is
    # empty on every row.
    public["allowed_ips"] = split_list(row.get("tunneladdress"))
    public["instance_uuids"] = split_list(row.get("servers"))
    public["instance_names"] = split_list(row.get("%servers", ""))
    public["has_psk"] = bool(row.get("psk"))
    public.update(extra)
    return public


class _WgToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _search(
        self, endpoint: str, body: dict[str, Any] | None = None
    ) -> Any:
        """POST a search with no `rowCount`, so the whole set comes back."""
        return await self.client._make_request(
            "POST", endpoint, json=body if body is not None else {}
        )
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_wireguard.py -q && uv run ruff check opnsense_mcp/tools/wireguard.py
```

Expected: PASS, clean.

- [ ] **Step 5: Falsify three of them**

Confirm each test fails for its own reason, then revert each change:

1. In `selected_keys`, return `list(node)`. Expected:
   `test_selected_keys_ignores_unselected_options_and_the_empty_key` and
   `test_the_dangling_instance_has_no_selected_peers` fail.
2. In `public_peer`, read `row.get("allowed_ips")` instead of
   `row.get("tunneladdress")`. Expected:
   `test_every_peer_normalizes_to_a_non_empty_allowed_ips` fails.
3. In `split_list`, drop the `.strip()`. Expected:
   `test_split_list_strips_the_space_the_resolved_form_uses` fails.

```bash
git checkout opnsense_mcp/tools/wireguard.py
```

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/tools/wireguard.py tests/test_wireguard.py && git commit -m "Add WireGuard parsing helpers"
```

---

### Task 3: list_wg_instances

**Files:**
- Modify: `opnsense_mcp/tools/wireguard.py`
- Modify: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: everything from Task 2.
- Produces: `ListWgInstancesTool` with `name = "list_wg_instances"`, and
  `instance_shape(row, peers) -> tuple[str, list[str]]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wireguard.py`:

```python
class FakeClient:
    """Answers each endpoint from a fixture, and records what was asked.

    A dict of endpoint substring to payload rather than a mock, so a test that
    changes which endpoint a tool calls fails on the missing key instead of
    silently receiving a default.
    """

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, object]] = []

    async def _make_request(self, method, endpoint, json=None, **kwargs):
        self.calls.append((method, endpoint, json))
        for fragment, payload in self.responses.items():
            if fragment in endpoint:
                return payload
        raise AssertionError(f"unexpected endpoint {endpoint}")


def instance_client(**overrides):
    responses = {
        "searchServer": fixture("wg_searchserver_rows"),
        "searchClient": fixture("wg_searchclient_rows"),
        "service/show": fixture("wg_service_show_rows"),
        "core/service/search": {
            "rows": [
                {
                    "id": "wireguard/6975c926-5a06-4b5c-aa6e-86e14f39cd76",
                    "running": 1,
                    "name": "wireguard",
                }
            ],
            "total": 1,
        },
    }
    responses.update(overrides)
    return FakeClient(responses)


@pytest.mark.asyncio
async def test_list_instances_returns_every_instance() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})

    assert result["status"] == "success"
    assert len(result["instances"]) == 3


@pytest.mark.asyncio
async def test_list_instances_never_returns_a_private_key() -> None:
    import json as _json

    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    text = _json.dumps(result)

    assert "privkey" not in text
    assert "pubkey" not in text
    assert all(i["has_privkey"] is True for i in result["instances"])


@pytest.mark.asyncio
async def test_list_instances_reports_a_dangling_peer_rather_than_dropping_it() -> None:
    """One instance names a peer uuid that no client record matches.

    Search reports one peer, get reports zero, and getClient on the uuid returns
    an empty array. All three answer HTTP 200 with no error, so a join that
    assumes 1:1 loses the reference silently.
    """
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    wg1 = next(i for i in result["instances"] if i["name"] == "wg1RemoteLabUsers")

    assert wg1["peer_uuids"] == ["9d08d591-4556-4df2-bf87-dcf1679e2776"]
    assert wg1["dangling_peers"] == ["9d08d591-4556-4df2-bf87-dcf1679e2776"]


@pytest.mark.asyncio
async def test_membership_survives_a_missing_resolved_key() -> None:
    """`%peers` is absent, not empty, on the instance whose peer resolves to
    nothing. Indexing it raises on exactly the instance most worth reporting."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    wg1 = next(i for i in result["instances"] if i["name"] == "wg1RemoteLabUsers")

    assert wg1["peer_names"] == []
    assert wg1["peer_uuids"]


@pytest.mark.asyncio
async def test_only_the_enabled_instance_reports_running() -> None:
    """Disabled instances are absent from every runtime view, so absence has two
    causes and only the config's `enabled` separates them."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    by_name = {i["name"]: i for i in result["instances"]}

    assert by_name["wg0HomeVpn"]["running"] is True
    assert by_name["wg1RemoteLabUsers"]["running"] is False
    assert by_name["wg1RemoteLabUsers"]["enabled"] == "0"


@pytest.mark.asyncio
async def test_the_site_to_site_instance_is_labelled_with_its_evidence() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    result = await ListWgInstancesTool(instance_client()).execute({})
    s2s = next(i for i in result["instances"] if i["name"] == "wg2SiteToSite")

    assert s2s["shape"] == "site_to_site"
    assert s2s["shape_evidence"], "a label without its evidence is a guess"


@pytest.mark.asyncio
async def test_a_truncated_listing_is_refused_rather_than_returned() -> None:
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    client = instance_client(searchServer={"rows": [], "total": 3})
    result = await ListWgInstancesTool(client).execute({})

    assert result["status"] == "error"
    assert "truncated" in result["error"]


@pytest.mark.asyncio
async def test_no_listing_call_sends_a_rowcount() -> None:
    """Sending one is what makes total exceed the rows returned."""
    from opnsense_mcp.tools.wireguard import ListWgInstancesTool

    client = instance_client()
    await ListWgInstancesTool(client).execute({})

    for _method, _endpoint, body in client.calls:
        assert "rowCount" not in (body or {})
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q -k instances
```

Expected: `ImportError: cannot import name 'ListWgInstancesTool'`.

- [ ] **Step 3: Implement**

Append to `opnsense_mcp/tools/wireguard.py`:

```python
def instance_shape(
    row: dict[str, Any], peers: list[dict[str, Any]]
) -> tuple[str, list[str]]:
    """A label for a human reader, always returned with its evidence.

    Never used as a gate anywhere. A site-to-site instance and a road-warrior
    one differ only in how they happen to be configured, so a wrong guess must
    not change what any check does.
    """
    evidence: list[str] = []
    if str(row.get("disableroutes", "")) == "1":
        evidence.append("disableroutes=1")
    if row.get("gateway"):
        evidence.append(f"gateway={row['gateway']}")
    wide = [
        entry
        for peer in peers
        for entry in split_list(peer.get("tunneladdress"))
        if not is_host_route(entry)
    ]
    if wide:
        evidence.append(f"peer networks {', '.join(sorted(wide))}")
    if evidence:
        return "site_to_site", evidence
    if peers:
        return "road_warrior", [f"{len(peers)} peers, all host routes"]
    return "unknown", ["no resolvable peers"]


class ListWgInstancesTool(_WgToolBase):
    """List WireGuard instances, config joined to runtime state."""

    name = "list_wg_instances"
    description = (
        "List WireGuard instances with their tunnel addresses, peers and "
        "running state"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Only the instance with this name",
                "optional": True,
            },
        },
        "required": [],
    }

    async def _running_uuids(self) -> set[str]:
        """Server uuids the service manager reports as running.

        `/api/wireguard/service/status` cannot answer this: the plugin declares
        no configd status action, so it returns the literal string "unknown"
        while the interface is up and moving traffic. The core service grid
        embeds the server uuid in its row id and is the reliable signal.
        """
        payload = await self._search(CORE_SERVICE)
        running = set()
        for row in rows_or_refuse(payload, "services"):
            identifier = str(row.get("id", ""))
            if identifier.startswith("wireguard/") and str(row.get("running")) == "1":
                running.add(identifier.split("/", 1)[1])
        return running

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """List instances, or the one named."""
        params = params or {}
        if not self.client:
            return self._no_client()
        try:
            servers = rows_or_refuse(
                await self._search(WG_SERVER["search"]), "wireguard instances"
            )
            clients = rows_or_refuse(
                await self._search(WG_CLIENT["search"]), "wireguard peers"
            )
            running = await self._running_uuids()
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard instances")
            return {"status": "error", "error": str(exc)}

        by_uuid = {str(c.get("uuid", "")): c for c in clients}
        wanted = str(params.get("name") or "")

        instances = []
        for row in servers:
            if wanted and row.get("name") != wanted:
                continue
            peer_uuids = split_list(row.get("peers"))
            members = [by_uuid[u] for u in peer_uuids if u in by_uuid]
            shape, evidence = instance_shape(row, members)
            instances.append(
                public_instance(
                    row,
                    dangling_peers=[u for u in peer_uuids if u not in by_uuid],
                    running=str(row.get("uuid", "")) in running,
                    shape=shape,
                    shape_evidence=evidence,
                )
            )

        return {"status": "success", "count": len(instances), "instances": instances}
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_wireguard.py -q && uv run ruff check opnsense_mcp/tools/wireguard.py
```

Expected: PASS, clean.

- [ ] **Step 5: Falsify the dangling-peer test**

Change `dangling_peers` to `[]`. Expected:
`test_list_instances_reports_a_dangling_peer_rather_than_dropping_it` fails.
Revert with `git checkout opnsense_mcp/tools/wireguard.py`.

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/tools/wireguard.py tests/test_wireguard.py && git commit -m "Add list_wg_instances"
```

---

### Task 4: list_wg_peers

**Files:**
- Modify: `opnsense_mcp/tools/wireguard.py`
- Modify: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: Task 2's helpers, Task 3's `FakeClient` test fixture.
- Produces: `ListWgPeersTool` with `name = "list_wg_peers"`, and
  `runtime_by_name(rows) -> dict[str, dict]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wireguard.py`:

```python
@pytest.mark.asyncio
async def test_list_peers_returns_every_peer() -> None:
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})

    assert result["status"] == "success"
    assert len(result["peers"]) == 11


@pytest.mark.asyncio
async def test_an_interface_row_is_not_reported_as_a_peer() -> None:
    """service/show returns one array with two row schemas keyed by `type`.

    The interface row carries a plausible name and peer-status 'offline', so a
    normalizer that skips the type check reports the instance itself as an extra
    permanently-offline peer.
    """
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})

    assert "wg0HomeVpn" not in {p["name"] for p in result["peers"]}


@pytest.mark.asyncio
async def test_a_peer_that_never_connected_is_not_reported_as_connected() -> None:
    """Every never-connected peer carries non-zero transfer-tx against zero rx,
    so a `tx > 0` health check calls all of them healthy. Only the handshake
    separates 'never connected' from 'connected and now idle'."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})
    by_name = {p["name"]: p for p in result["peers"]}

    quiet = by_name["peerB"]
    assert quiet["runtime"]["transfer_tx"] > 0
    assert quiet["runtime"]["connected"] is False

    live = by_name["peerA"]
    assert live["runtime"]["connected"] is True


@pytest.mark.asyncio
async def test_a_peer_on_a_disabled_instance_reports_no_runtime_with_a_reason() -> None:
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    result = await ListWgPeersTool(instance_client()).execute({})
    s2s = next(p for p in result["peers"] if p["name"] == "wg2SiteToSite")

    assert s2s["runtime"] is None
    assert s2s["runtime_absent"]


@pytest.mark.asyncio
async def test_peers_can_be_filtered_by_instance_and_the_filter_is_verified() -> None:
    """A 200 is not evidence a filter applied: unknown parameters are accepted
    and ignored on every grid. The filter key is `servers`, and it must be an
    array; a bare string returns HTTP 500."""
    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    client = instance_client()
    await ListWgPeersTool(client).execute({"instance": "wg0HomeVpn"})

    bodies = [body for _m, endpoint, body in client.calls if "searchClient" in endpoint]
    assert any(isinstance((b or {}).get("servers"), list) for b in bodies)


@pytest.mark.asyncio
async def test_list_peers_never_returns_key_material() -> None:
    import json as _json

    from opnsense_mcp.tools.wireguard import ListWgPeersTool

    text = _json.dumps(await ListWgPeersTool(instance_client()).execute({}))

    assert "privkey" not in text
    assert "psk" not in text
    assert "public-key" not in text
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q -k peers
```

Expected: `ImportError: cannot import name 'ListWgPeersTool'`.

- [ ] **Step 3: Implement**

Append to `opnsense_mcp/tools/wireguard.py`:

```python
def runtime_by_name(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Kernel peer state keyed by peer name.

    `service/show` returns one array holding two row schemas discriminated by
    `type`, and the missing keys are absent rather than empty. The interface row
    carries peer-status 'offline' and a name that looks like a peer's, so it has
    to be filtered out before anything else reads the array.

    Kernel rows carry no uuid, so name is the only join back to a config row.
    """
    runtime = {}
    for row in rows:
        if row.get("type") != "peer":
            continue
        handshake = row.get("latest-handshake") or 0
        runtime[str(row.get("name", ""))] = {
            "device": row.get("if", ""),
            "endpoint": row.get("endpoint", ""),
            "kernel_allowed_ips": split_list(row.get("allowed-ips")),
            "handshake_epoch": handshake,
            "handshake_age": row.get("latest-handshake-age"),
            "transfer_rx": row.get("transfer-rx", 0),
            "transfer_tx": row.get("transfer-tx", 0),
            # The only field that separates a peer which has never connected
            # from one that connected and went idle. Transfer counters do not:
            # every never-connected peer here has a non-zero tx.
            "connected": bool(handshake),
            # Reported, not interpreted. Only two of the three values were ever
            # observed, so the enum is not encoded anywhere.
            "peer_status_raw": row.get("peer-status", ""),
        }
    return runtime


class ListWgPeersTool(_WgToolBase):
    """List WireGuard peers, config joined to runtime state."""

    name = "list_wg_peers"
    description = (
        "List WireGuard peers with their server-side allowed IPs, instance "
        "membership and last handshake"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "instance": {
                "type": "string",
                "description": "Only peers of this instance, by name or uuid",
                "optional": True,
            },
            "name": {
                "type": "string",
                "description": "Only the peer with this name",
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """List peers, optionally narrowed to one instance."""
        params = params or {}
        if not self.client:
            return self._no_client()
        wanted_instance = str(params.get("instance") or "")
        wanted_name = str(params.get("name") or "")

        try:
            servers = rows_or_refuse(
                await self._search(WG_SERVER["search"]), "wireguard instances"
            )
            body: dict[str, Any] = {}
            if wanted_instance:
                # `servers` is the filter key and must be an array. `server_uuid`
                # is accepted and ignored, and a bare string returns HTTP 500.
                match = [
                    str(s.get("uuid", ""))
                    for s in servers
                    if wanted_instance in (s.get("name", ""), s.get("uuid", ""))
                ]
                body["servers"] = match
            clients = rows_or_refuse(
                await self._search(WG_CLIENT["search"], body), "wireguard peers"
            )
            show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard peers")
            return {"status": "error", "error": str(exc)}

        enabled = {
            str(s.get("uuid", "")): str(s.get("enabled", "0")) == "1" for s in servers
        }
        runtime = runtime_by_name(show)

        peers = []
        for row in clients:
            if wanted_name and row.get("name") != wanted_name:
                continue
            name = str(row.get("name", ""))
            state = runtime.get(name)
            absent = ""
            if state is None:
                members = split_list(row.get("servers"))
                if members and not any(enabled.get(u, False) for u in members):
                    absent = "every instance this peer belongs to is disabled"
                else:
                    absent = "no kernel peer with this name"
            peers.append(
                public_peer(row, runtime=state, runtime_absent=absent)
            )

        return {
            "status": "success",
            "count": len(peers),
            "peers": peers,
            "note": (
                "Allowed IPs here are the addresses belonging to each peer, which "
                "fixes routing to that peer. What a peer sends through the tunnel "
                "lives in its own client config, which this API cannot read."
            ),
        }
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_wireguard.py -q && uv run ruff check opnsense_mcp/tools/wireguard.py
```

Expected: PASS, clean.

- [ ] **Step 5: Falsify the type-discrimination test**

In `runtime_by_name`, delete the `if row.get("type") != "peer": continue` guard.
Expected: `test_an_interface_row_is_not_reported_as_a_peer` fails. Revert.

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/tools/wireguard.py tests/test_wireguard.py && git commit -m "Add list_wg_peers"
```

---

### Task 5: reconcile_wg, peer address containment

**Files:**
- Modify: `opnsense_mcp/tools/wireguard.py`
- Modify: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: Tasks 2 to 4.
- Produces: `classify_entry(entry, networks) -> tuple[str, str]` and
  `ReconcileWgTool` with `name = "reconcile_wg"`, whose result carries
  `status`, `checked`, `counts`, `results`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wireguard.py`:

```python
def test_classify_entry_calls_a_host_route_inside_its_network_current() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])

    assert classify_entry("192.168.10.7/32", nets)[0] == "current"
    assert classify_entry("fd0b:cafe:f::2/128", nets)[0] == "current"


def test_classify_entry_calls_a_host_route_outside_its_network_drifted() -> None:
    """The case the tool exists for: a peer left on a prefix the instance no
    longer carries."""
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.10.1/24", "fd0b:cafe:f::1/64"])

    outcome, detail = classify_entry("2001:db8:5eed:b7ef::80/128", nets)

    assert outcome == "drifted"
    assert "2001:db8:5eed:b7ef::80/128" in detail


def test_classify_entry_calls_a_wider_network_a_routed_prefix() -> None:
    """The site-to-site remote LAN sits outside the tunnel network and is
    correct. Containment alone would call it drift, so prefix width is what
    separates an address on the tunnel from a network routed through it."""
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["172.20.181.2/24"])

    assert classify_entry("192.168.99.0/24", nets)[0] == "routed_prefix"
    assert classify_entry("172.20.181.1/32", nets)[0] == "current"


def test_classify_entry_reports_a_family_the_instance_does_not_carry() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    nets = networks_of(["192.168.11.1"])

    assert classify_entry("fd0b:cafe:f::2/128", nets)[0] == "no_interface"


def test_classify_entry_reports_an_unreadable_address() -> None:
    from opnsense_mcp.tools.wireguard import classify_entry, networks_of

    assert classify_entry("not-an-address", networks_of(["192.168.10.1/24"]))[0] == (
        "unreadable_address"
    )


@pytest.mark.asyncio
async def test_reconcile_reports_no_drift_on_the_captured_state() -> None:
    """Every peer on the box is currently inside its instance network. A tool
    that manufactures drift here is worse than one that finds none."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})

    assert result["status"] == "success"
    assert result["counts"]["drifted"] == 0


@pytest.mark.asyncio
async def test_the_site_to_site_remote_lan_is_not_reported_as_drift() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    entries = [
        r
        for r in result["results"]
        if r["check"] == "peer_containment" and r["entry"] == "192.168.99.0/24"
    ]

    assert entries, "the site-to-site remote LAN is missing from the report"
    assert entries[0]["outcome"] == "routed_prefix"


@pytest.mark.asyncio
async def test_reconcile_status_says_the_audit_ran_not_what_it_found() -> None:
    """A run that finds problems still ran. Severity belongs in the payload,
    or a caller cannot tell a finding from a failure to look."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})

    assert result["status"] == "success"
    assert "counts" in result


@pytest.mark.asyncio
async def test_reconcile_makes_no_write_call() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    client = reconcile_client()
    await ReconcileWgTool(client).execute({})

    for method, endpoint, _body in client.calls:
        assert method == "POST"
        assert not any(
            verb in endpoint
            for verb in ("/add", "/set", "/del", "/toggle", "/apply", "/reconfigure")
        )
```

Add the reconcile fixture client beside `instance_client`:

```python
def reconcile_client(**overrides):
    responses = {
        "searchServer": fixture("wg_searchserver_rows"),
        "searchClient": fixture("wg_searchclient_rows"),
        "service/show": fixture("wg_service_show_rows"),
        "interfaces_info": fixture("wg_interfaces_info_wg0"),
        "core/service/search": {"rows": [], "total": 0},
    }
    responses.update(overrides)
    return FakeClient(responses)
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q -k "classify or reconcile"
```

Expected: `ImportError: cannot import name 'classify_entry'`.

- [ ] **Step 3: Implement**

Append to `opnsense_mcp/tools/wireguard.py`:

```python
def classify_entry(entry: str, networks: list[Any]) -> tuple[str, str]:
    """Classify one server-side allowed-IP entry against its instance networks.

    Prefix width carries the meaning, not membership alone. A host route belongs
    to the peer and must sit inside the tunnel network; anything wider is a
    network routed through the tunnel and is expected to sit outside it. Without
    that distinction a site-to-site instance's remote LAN reads as drift, and
    the only alternative is an exception carved out for one instance.
    """
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError as exc:
        return "unreadable_address", f"{entry!r} is not a network: {exc}"

    family = [n for n in networks if n.version == network.version]
    if not family:
        return (
            "no_interface",
            f"the instance carries no IPv{network.version} tunnel address, so "
            f"{entry} cannot be judged",
        )
    if any(network.subnet_of(n) for n in family):
        return "current", ""
    carried = ", ".join(str(n) for n in family)
    if network.prefixlen == network.max_prefixlen:
        return "drifted", f"{entry} is a host route outside {carried}"
    return (
        "routed_prefix",
        f"{entry} is a network routed through the tunnel rather than an address "
        f"on it; its path depends on {carried} and the static routes",
    )


class ReconcileWgTool(_WgToolBase):
    """Report where the stored WireGuard config and the running kernel disagree.

    Report only. Nothing here writes, so `status` says whether the audit ran and
    every finding lives in the payload: a caller cannot otherwise tell an audit
    that found problems from one that failed to look.
    """

    name = "reconcile_wg"
    description = (
        "Report drift between WireGuard config and the running kernel: peer "
        "addresses outside their tunnel network, interface addresses no config "
        "accounts for, and routes that do not match the loaded allowed IPs"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def _read(self) -> tuple[list, list, list, list]:
        servers = rows_or_refuse(
            await self._search(WG_SERVER["search"]), "wireguard instances"
        )
        clients = rows_or_refuse(
            await self._search(WG_CLIENT["search"]), "wireguard peers"
        )
        show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        devices = rows_or_refuse(await self._search(INTERFACES), "interfaces")
        return servers, clients, show, devices

    def _peer_containment(
        self, servers: list[dict[str, Any]], clients: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check A: every peer address against its instance's tunnel networks."""
        by_uuid = {str(s.get("uuid", "")): s for s in servers}
        results = []
        for peer in clients:
            members = [by_uuid[u] for u in split_list(peer.get("servers")) if u in by_uuid]
            networks = networks_of(
                [a for s in members for a in split_list(s.get("tunneladdress"))]
            )
            for entry in split_list(peer.get("tunneladdress")):
                outcome, detail = classify_entry(entry, networks)
                results.append(
                    {
                        "check": "peer_containment",
                        "peer": peer.get("name", ""),
                        "peer_uuid": peer.get("uuid", ""),
                        "instances": [s.get("name", "") for s in members],
                        "entry": entry,
                        "outcome": outcome,
                        "detail": detail,
                    }
                )
            if not members:
                results.append(
                    {
                        "check": "peer_containment",
                        "peer": peer.get("name", ""),
                        "peer_uuid": peer.get("uuid", ""),
                        "instances": [],
                        "entry": "",
                        "outcome": "no_interface",
                        "detail": "this peer belongs to no instance that exists",
                    }
                )
        return results

    def _summarise(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for result in results:
            counts[result["outcome"]] = counts.get(result["outcome"], 0) + 1
        counts.setdefault("current", 0)
        counts.setdefault("drifted", 0)
        return counts

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run every check and report. Writes nothing."""
        if not self.client:
            return self._no_client()
        try:
            servers, clients, _show, _devices = await self._read()
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard state")
            return {"status": "error", "error": str(exc)}

        results = self._peer_containment(servers, clients)

        return {
            "status": "success",
            "checked": len(results),
            "counts": self._summarise(results),
            "results": results,
            "note": (
                "Server-side allowed IPs fix routing to a peer. What a peer sends "
                "through the tunnel lives in its own client config, which this "
                "API cannot read, so a clean report is not proof of end-to-end "
                "reachability."
            ),
        }
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_wireguard.py -q && uv run ruff check opnsense_mcp/tools/wireguard.py
```

Expected: PASS, clean.

- [ ] **Step 5: Falsify the width distinction**

In `classify_entry`, return `"drifted"` for every entry that is not `subnet_of`
a family network, deleting the host-route branch. Expected:
`test_the_site_to_site_remote_lan_is_not_reported_as_drift` and
`test_classify_entry_calls_a_wider_network_a_routed_prefix` fail, and
`test_reconcile_reports_no_drift_on_the_captured_state` fails too. Revert.

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/tools/wireguard.py tests/test_wireguard.py && git commit -m "Add reconcile_wg peer containment check"
```

---

### Task 6: reconcile_wg, address liveness and route cross-check

**Files:**
- Modify: `opnsense_mcp/tools/wireguard.py`
- Modify: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: Task 5's `ReconcileWgTool`.
- Produces: `ReconcileWgTool._address_liveness(...)` and
  `ReconcileWgTool._route_crosscheck(...)`, both returning the same result-row
  shape as `_peer_containment`.

Both checks read one endpoint. `interfaces_info` carries, per device, the kernel
addresses (`ipv4`, `ipv6`, each a list of `{"ipaddr": ...}`), the kernel routes
(`routes`, a list of destination strings with the prefix length omitted on host
routes), the interface assignment (`config`) and the OPNsense identifier.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wireguard.py`:

```python
@pytest.mark.asyncio
async def test_an_address_no_config_accounts_for_is_reported() -> None:
    """The captured device holds an address that neither the instance's tunnel
    address nor the interface assignment claims."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [
        r
        for r in result["results"]
        if r["check"] == "address_liveness" and r["outcome"] == "unaccounted_address"
    ]

    assert [r["entry"] for r in rows] == ["2001:db8:5eed:b50f::1/64"]


@pytest.mark.asyncio
async def test_the_check_is_not_keyed_on_what_a_prefix_looks_like() -> None:
    """The delegated prefix is live and nine interfaces track it. A rule keyed
    on the prefix would flag all of them and miss the real defect, so a device
    whose config claims its address is current whatever the prefix is."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    fixture_rows = fixture("wg_interfaces_info_wg0")
    device = fixture_rows["rows"][0]
    device["ipv6"] = [{"ipaddr": "2001:db8:5eed:b50f::1/64"}]
    device["config"] = dict(device["config"], ipaddrv6="2001:db8:5eed:b50f::1/64")

    result = await ReconcileWgTool(
        reconcile_client(interfaces_info=fixture_rows)
    ).execute({})

    assert not [
        r for r in result["results"] if r["outcome"] == "unaccounted_address"
    ]


@pytest.mark.asyncio
async def test_a_route_with_no_allowed_ip_behind_it_is_reported() -> None:
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r["outcome"] == "stale_route"]

    assert "2001:db8:5eed:b7ef::80" in {r["entry"] for r in rows}


@pytest.mark.asyncio
async def test_an_allowed_ip_with_no_route_is_reported() -> None:
    """The mirror-image defect. Checking one direction finds the stale route and
    misses the missing one, and the captured state holds one of each."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r["outcome"] == "missing_route"]

    assert "fd0b:cafe:f::2/128" in {r["entry"] for r in rows}


@pytest.mark.asyncio
async def test_kernel_and_config_allowed_ips_compare_as_sets() -> None:
    """The kernel emits v6 first and the config preserves entry order, so a
    string comparator passes all nine single-stack peers and fails only on the
    dual-stack one."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [
        r
        for r in result["results"]
        if r["check"] == "kernel_matches_config" and r["peer"] == "dualStackPeer"
    ]

    assert rows and rows[0]["outcome"] == "current"


@pytest.mark.asyncio
async def test_a_disabled_instance_absent_from_the_kernel_is_not_a_fault() -> None:
    """Disabled instances are absent from every runtime view with no
    placeholder, so absence has two causes and only `enabled` separates them."""
    from opnsense_mcp.tools.wireguard import ReconcileWgTool

    result = await ReconcileWgTool(reconcile_client()).execute({})
    rows = [r for r in result["results"] if r.get("instance") == "wg2SiteToSite"]

    assert all(r["outcome"] != "drifted" for r in rows)
    assert any(r["outcome"] == "instance_disabled" for r in rows)
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q -k "liveness or route or sets or disabled"
```

Expected: FAIL, each on an empty result list.

- [ ] **Step 3: Implement**

Replace `ReconcileWgTool.execute` and add the two checks:

```python
    @staticmethod
    def _config_networks(device: dict[str, Any], tunnel: list[str]) -> list[Any]:
        """Every network a device's configuration accounts for.

        Two sources, because the tunnel device is the only interface whose
        address comes from a WireGuard tunnel address rather than from an
        interface assignment or an ipalias virtual IP.
        """
        config = device.get("config") or {}
        assigned = [
            str(config.get(key, ""))
            for key in ("ipaddr", "ipaddrv6")
            if str(config.get(key, "")) not in ("", "none", "dhcp", "dhcp6", "track6")
        ]
        return networks_of([*tunnel, *assigned])

    def _address_liveness(
        self, servers: list[dict[str, Any]], devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check B: kernel addresses against config, in both directions.

        The predicate is "no config accounts for this address", never "this
        prefix looks retired". The delegated prefix is live and carried by many
        interfaces, so a rule keyed on the prefix flags the healthy ones and
        misses the orphan.
        """
        by_name = {str(d.get("device", "")): d for d in devices}
        results = []
        # Iterate the config, not the devices. A disabled instance has no device
        # at all, so a loop over devices emits nothing for it and the caller
        # cannot tell "disabled" from "never checked".
        for server in servers:
            name = str(server.get("interface", ""))
            instance = str(server.get("name", ""))
            if str(server.get("enabled", "0")) != "1":
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "instance_disabled",
                        "detail": (
                            "the instance is disabled, so it holds no kernel state "
                            "and absence is not a fault"
                        ),
                    }
                )
                continue
            device = by_name.get(name)
            if device is None:
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "device_absent",
                        "detail": (
                            f"{instance} is enabled and no device named {name} "
                            f"exists, so the kernel never brought it up"
                        ),
                    }
                )
                continue

            tunnel = split_list(server.get("tunneladdress"))
            accounted = self._config_networks(device, tunnel)
            held = [
                str(item.get("ipaddr", ""))
                for family in ("ipv4", "ipv6")
                for item in (device.get(family) or [])
                if item.get("ipaddr")
            ]

            for entry in held:
                try:
                    address = ipaddress.ip_interface(entry)
                except ValueError:
                    results.append(
                        {
                            "check": "address_liveness",
                            "instance": instance,
                            "device": name,
                            "entry": entry,
                            "outcome": "unreadable_address",
                            "detail": f"{entry!r} is not an address",
                        }
                    )
                    continue
                if address.network.is_link_local:
                    continue
                outcome = (
                    "current"
                    if any(address.ip in n for n in accounted)
                    else "unaccounted_address"
                )
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": entry,
                        "outcome": outcome,
                        "detail": ""
                        if outcome == "current"
                        else (
                            f"{name} holds {entry}, which neither the instance "
                            f"tunnel address nor the interface assignment accounts "
                            f"for"
                        ),
                    }
                )

            held_addresses = {
                ipaddress.ip_interface(e).ip for e in held if _parses(e)
            }
            for entry in tunnel:
                if not _parses(entry):
                    continue
                if ipaddress.ip_interface(entry).ip not in held_addresses:
                    results.append(
                        {
                            "check": "address_liveness",
                            "instance": instance,
                            "device": name,
                            "entry": entry,
                            "outcome": "missing_address",
                            "detail": (
                                f"the instance configures {entry} and {name} does "
                                f"not hold it"
                            ),
                        }
                    )
        return results

    def _route_crosscheck(
        self,
        servers: list[dict[str, Any]],
        show: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        clients: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Check C: routes against the allowed IPs the kernel actually holds.

        Both directions, because the captured state holds one defect of each
        kind: a route whose allowed IP is gone, and an allowed IP whose route
        was never created.

        Route destinations omit the prefix length on host routes, so the implied
        maximum is supplied before comparison.
        """
        by_name = {str(d.get("device", "")): d for d in devices}
        config_by_name = {str(c.get("name", "")): c for c in clients}
        results = []

        # Same reason as check B: driven by the config, so a disabled instance
        # is reported as disabled rather than skipped silently.
        for server in servers:
            name = str(server.get("interface", ""))
            instance = str(server.get("name", ""))
            if str(server.get("enabled", "0")) != "1":
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "instance_disabled",
                        "detail": "the instance is disabled, so it holds no routes",
                    }
                )
                continue
            device = by_name.get(name)
            if device is None:
                continue
            tunnel = networks_of(split_list(server.get("tunneladdress")))

            loaded: set[Any] = set()
            for row in show:
                if row.get("type") != "peer" or row.get("if") != name:
                    continue
                for entry in split_list(row.get("allowed-ips")):
                    if _parses(entry):
                        loaded.add(ipaddress.ip_network(entry, strict=False))

            routed = set()
            for destination in device.get("routes") or []:
                network = _as_network(str(destination))
                if network is None:
                    continue
                routed.add(network)
                if network in loaded or network in tunnel:
                    continue
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": str(destination),
                        "outcome": "stale_route",
                        "detail": (
                            f"{name} routes {destination}, and no allowed IP or "
                            f"tunnel network behind it"
                        ),
                    }
                )

            for network in sorted(loaded, key=str):
                if network in routed:
                    continue
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": str(network),
                        "outcome": "missing_route",
                        "detail": (
                            f"the kernel holds {network} as an allowed IP on {name} "
                            f"and no route reaches it"
                        ),
                    }
                )

        for row in show:
            if row.get("type") != "peer":
                continue
            peer = str(row.get("name", ""))
            config = config_by_name.get(peer)
            if config is None:
                results.append(
                    {
                        "check": "kernel_matches_config",
                        "peer": peer,
                        "entry": "",
                        "outcome": "dangling_peer",
                        "detail": f"the kernel holds peer {peer!r} and no config row does",
                    }
                )
                continue
            # Sets, not strings. The kernel emits v6 first while the config keeps
            # entry order, so a string comparison fails only on a dual-stack peer.
            kernel = {_as_network(e) for e in split_list(row.get("allowed-ips"))}
            stored = {_as_network(e) for e in split_list(config.get("tunneladdress"))}
            results.append(
                {
                    "check": "kernel_matches_config",
                    "peer": peer,
                    "entry": "",
                    "outcome": "current" if kernel == stored else "drifted",
                    "detail": ""
                    if kernel == stored
                    else f"kernel {sorted(map(str, kernel))} config {sorted(map(str, stored))}",
                }
            )
        return results

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run every check and report. Writes nothing."""
        if not self.client:
            return self._no_client()
        try:
            servers, clients, show, devices = await self._read()
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard state")
            return {"status": "error", "error": str(exc)}

        results = [
            *self._peer_containment(servers, clients),
            *self._address_liveness(servers, devices),
            *self._route_crosscheck(servers, show, devices, clients),
        ]

        return {
            "status": "success",
            "checked": len(results),
            "counts": self._summarise(results),
            "results": results,
            "note": (
                "Server-side allowed IPs fix routing to a peer. What a peer sends "
                "through the tunnel lives in its own client config, which this "
                "API cannot read, so a clean report is not proof of end-to-end "
                "reachability."
            ),
        }
```

Add the two module-level helpers above the class:

```python
def _parses(entry: str) -> bool:
    """True when the entry reads as an address with an optional prefix length."""
    try:
        ipaddress.ip_interface(entry)
    except ValueError:
        return False
    return True


def _as_network(destination: str) -> Any:
    """A route destination or allowed IP as a network.

    Route destinations omit the prefix length on host routes, so a bare address
    means the family maximum rather than a parse failure.
    """
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return None
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_wireguard.py -q && uv run ruff check opnsense_mcp/tools/wireguard.py
```

Expected: PASS, clean.

- [ ] **Step 5: Falsify both directions and the set comparison**

1. In `_route_crosscheck`, delete the `missing_route` loop. Expected:
   `test_an_allowed_ip_with_no_route_is_reported` fails while the stale-route
   test still passes, which is the point.
2. Delete the `stale_route` branch instead. Expected: the mirror test fails.
3. In `kernel_matches_config`, compare
   `split_list(row.get("allowed-ips")) == split_list(config.get("tunneladdress"))`.
   Expected: `test_kernel_and_config_allowed_ips_compare_as_sets` fails on the
   dual-stack peer and no other peer's row changes.

Revert after each with `git checkout opnsense_mcp/tools/wireguard.py`.

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/tools/wireguard.py tests/test_wireguard.py && git commit -m "Add reconcile_wg address and route checks"
```

---

### Task 7: Register and group the tools

**Files:**
- Modify: `opnsense_mcp/utils/registry.py`
- Modify: `opnsense_mcp/utils/tool_groups.py`
- Modify: `tests/test_wireguard.py`

**Interfaces:**
- Consumes: the three tool classes.
- Produces: the `wireguard` MCP group with actions `list_instances`,
  `list_peers`, `reconcile`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wireguard.py`:

```python
def test_the_wireguard_group_exposes_every_tool() -> None:
    from opnsense_mcp.utils.tool_groups import GROUPS

    description, actions = GROUPS["wireguard"]

    assert description
    assert actions == {
        "list_instances": "list_wg_instances",
        "list_peers": "list_wg_peers",
        "reconcile": "reconcile_wg",
    }


def test_no_wireguard_member_declares_a_field_named_action() -> None:
    """The group pops `action` to pick the member, so a member declaring its own
    would never receive one."""
    from opnsense_mcp.tools.wireguard import (
        ListWgInstancesTool,
        ListWgPeersTool,
        ReconcileWgTool,
    )

    for tool in (ListWgInstancesTool, ListWgPeersTool, ReconcileWgTool):
        assert "action" not in tool.input_schema["properties"]


def test_every_wireguard_tool_is_registered() -> None:
    from opnsense_mcp.utils.registry import TOOL_CLASSES

    names = {getattr(cls, "name", "") for cls in TOOL_CLASSES}

    assert {"list_wg_instances", "list_wg_peers", "reconcile_wg"} <= names
```

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/test_wireguard.py -q -k "group or registered or action"
```

Expected: `KeyError: 'wireguard'` and a failing subset assertion.

- [ ] **Step 3: Register the tools**

In `opnsense_mcp/utils/registry.py`, add the import beside the other tool
imports, keeping alphabetical order by module:

```python
from opnsense_mcp.tools.wireguard import (
    ListWgInstancesTool,
    ListWgPeersTool,
    ReconcileWgTool,
)
```

and add the three classes to `TOOL_CLASSES`.

- [ ] **Step 4: Add the group**

In `opnsense_mcp/utils/tool_groups.py`, add to `GROUPS`, keeping the existing
ordering convention:

```python
    "wireguard": (
        "WireGuard overlay: instances, peers, and drift between the stored "
        "config and the running kernel state",
        {
            "list_instances": "list_wg_instances",
            "list_peers": "list_wg_peers",
            "reconcile": "reconcile_wg",
        },
    ),
```

- [ ] **Step 5: Run the whole suite**

```bash
uv run pytest tests/ -q && uv run ruff check . && uv run ruff format --check .
```

Expected: PASS, clean. The repository-wide checks that matter here are
`test_guidance_names_are_real.py` (a name the registry does not know),
`test_schema_completeness.py` (a `params` key the schema never declares),
`test_surface_consistency.py`, and the grouped-tool collision check. If
`test_schema_completeness.py` fails, a tool reads a parameter its
`input_schema` does not declare: add the property rather than dropping the read.

- [ ] **Step 6: Commit**

```bash
git add opnsense_mcp/utils/registry.py opnsense_mcp/utils/tool_groups.py tests/test_wireguard.py && git commit -m "Expose the wireguard tool group"
```

- [ ] **Step 7: Verify against the live firewall**

The suite proves the parsing. It cannot prove the endpoints still answer, and
this project has shipped tools whose fixtures were right and whose endpoint was
not. Through the deployed MCP server, not workspace Python:

```
wireguard action=list_instances
wireguard action=list_peers instance=wg0HomeVpn
wireguard action=reconcile
```

Expected: three instances; **ten** peers for the named instance against eleven
unfiltered; and a reconcile naming the orphaned address, the stale route and the
missing route recorded in issue #46.

The peer count is the only real proof the instance filter works. Unknown request
parameters are accepted and ignored on every grid, so a fixture-backed test can
show the right key was sent and never that the firewall acted on it. Eleven back
from a filtered call means the filter is a no-op.

If reconcile reports nothing, the checks are reading the wrong device key: those
three defects were present when this plan was written.

Then run the shape check, which compares live response keys against the
committed fixtures:

```bash
uv run python benchmark_performance.py --check-shapes
```
