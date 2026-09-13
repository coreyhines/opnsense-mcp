# GIF Interface End-to-End Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `interface_device` so agents can create GIF tunnels, assign them, enable/address them, and verify — with Tunnel Broker as a composed example, not special API fields.

**Architecture:** New `opnsense_mcp/tools/gif_stack.py` holds GIF CRUD + shared `assign` helpers, patterned on VLAN in `routing_stack.py` and loopback delete guards in `ipv6_stack.py`. Wire keys come from live `Gif.xml`. Addressing stays on existing `set_interface_address` (SSH). Group registration only changes presentation.

**Tech Stack:** Python 3.12, `uv`, pytest, ruff, existing `run_apply` / confirm tokens / `GroupedTool`.

**Spec:** `docs/research/gif-interface-end-to-end-design.md`

## Global Constraints

- GIF writes stage by default; `apply` default is **false**; results always include `applied` via `run_apply`.
- Deletes require confirm tokens; refuse delete while an assignment holds the device.
- Never report success from HTTP 200 / `reconfigure` ok alone — re-read.
- No HE-specific parameters; documentation ranges / lab addresses only in fixtures.
- Cursor-safe schemas: no `"type": [...]` unions; no `constructor` / `__proto__` / `prototype` property keys.
- `gif_settings` may 403 until the API key has GIF privileges — fail with an explicit privilege error, never invent an empty success list.
- Addressing uses existing SSH `set_interface_address`; do not reintroduce silent API address writes.

---

## File structure

| File | Responsibility |
|------|----------------|
| `opnsense_mcp/tools/gif_stack.py` | GIF endpoints, param↔wire mapper, list/create/update/delete, assign tool |
| `tests/test_gif_stack.py` | Unit tests against fixtures + mapper + delete/assign guards |
| `tests/fixtures/opnsense-26.7.3/gif_*.json` | Captured (sanitised) API responses |
| `opnsense_mcp/utils/registry.py` | Register new tool classes in `TOOL_CLASSES` |
| `opnsense_mcp/utils/tool_groups.py` | Add GIF + assign actions to `interface_device` |
| `tests/fixtures/tool_surface.json` | Regenerated golden surface |
| `docs/EXAMPLES/` or `docs/research/gif-tunnel-broker-example.md` | Composed Tunnel Broker sequence |

---

### Task 1: Privilege note, fixture capture, and mapper skeleton

**Files:**
- Create: `opnsense_mcp/tools/gif_stack.py` (constants + pure helpers only)
- Create: `tests/fixtures/opnsense-26.7.3/gif_get_item_blank.json` (after ACL)
- Create: `tests/fixtures/opnsense-26.7.3/gif_search_item_empty.json` (or with lab rows)
- Create: `tests/test_gif_stack.py`
- Create: `docs/research/gif-api-privilege.md` (one-page ops prerequisite)

**Interfaces:**
- Produces: `GIF` endpoint dict; `gif_params_to_wire(params: dict) -> dict`; `project_gif_row(row: dict) -> dict`; `privilege_error_message()` string helper

- [ ] **Step 1: Write the ops privilege doc**

Create `docs/research/gif-api-privilege.md` stating:
- Symptom: `GET/POST /api/interfaces/gif_settings/*` → 403
- Fix: grant the OPNsense user/API key the Interfaces GIF (Devices) privilege (exact UI path: System → Access → Users / API keys → privileges covering `interfaces:gif_settings` / Devices GIF)
- Until fixed, MCP GIF tools must return `status: error` with that message

- [ ] **Step 2: Capture fixtures (requires ACL)**

After privileges are granted, from a machine with `OPNSENSE_*` in `~/.env`:

```bash
set -a && source ~/.env && set +a
BASE="https://${OPNSENSE_FIREWALL_HOST}/api"
AUTH=(-u "${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}" -k -sS)
curl "${AUTH[@]}" "${BASE}/interfaces/gif_settings/get_item" \
  -o /tmp/gif_get_item_blank.json
curl "${AUTH[@]}" -X POST -H 'Content-Type: application/json' \
  -d '{"current":1,"rowCount":50}' \
  "${BASE}/interfaces/gif_settings/search_item" \
  -o /tmp/gif_search_item.json
# Sanitise any site IPs before commit; copy into tests/fixtures/opnsense-26.7.3/
```

If ACL is not yet granted, commit a **hand-built** blank fixture shaped exactly like `Gif.xml` fields (documented in the design) and a search fixture with `"rows": []`, `"total": 0`. Mark the hand-built file with a top-level `"_note": "synthetic until ACL allows capture"`.

Minimum blank `gif` node keys to include in the fixture (wire names):

`if`, `ipaddr`, `gifif`, `remote-addr`, `tunnel-local-addr`, `tunnel-remote-addr`, `tunnel-remote-net`, `descr`, `link1`, `link2`, `noclamp`

- [ ] **Step 3: Write failing mapper tests**

```python
# tests/test_gif_stack.py
from opnsense_mcp.tools.gif_stack import gif_params_to_wire, project_gif_row


def test_gif_params_to_wire_maps_parent_interface() -> None:
    wire = gif_params_to_wire(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
            "description": "lab",
            "ecn": True,
        }
    )
    assert wire["if"] == "wan"
    assert wire["remote-addr"] == "203.0.113.10"
    assert wire["tunnel-local-addr"] == "2001:db8:1::2"
    assert wire["tunnel-remote-addr"] == "2001:db8:1::1"
    assert wire["tunnel-remote-net"] == "64"
    assert wire["descr"] == "lab"
    assert wire["link1"] == "1"
    assert "ipaddr" not in wire or wire.get("ipaddr") in ("", None)


def test_gif_params_to_wire_defaults_tunnel_remote_net_to_32() -> None:
    wire = gif_params_to_wire(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "192.0.2.1",
            "tunnel_remote": "192.0.2.2",
        }
    )
    assert wire["tunnel-remote-net"] == "32"


def test_project_gif_row_uses_wire_keys() -> None:
    public = project_gif_row(
        {
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "gifif": "gif0",
            "if": "wan",
            "remote-addr": "203.0.113.10",
            "tunnel-local-addr": "2001:db8:1::2",
            "tunnel-remote-addr": "2001:db8:1::1",
            "tunnel-remote-net": "64",
            "descr": "lab",
        }
    )
    assert public["device"] == "gif0"
    assert public["parent"] == "wan"
    assert public["remote"] == "203.0.113.10"
    assert public["tunnel_local"] == "2001:db8:1::2"
    assert public["uuid"]
```

- [ ] **Step 4: Run tests — expect import/fail**

```bash
uv run pytest tests/test_gif_stack.py::test_gif_params_to_wire_maps_parent_interface -v
```

Expected: FAIL (module or symbols missing)

- [ ] **Step 5: Implement mapper + constants**

In `opnsense_mcp/tools/gif_stack.py`:

```python
"""GIF tunnel devices and interface assignment helpers."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)

GIF = {
    "search": "/api/interfaces/gif_settings/search_item",
    "get": "/api/interfaces/gif_settings/get_item",
    "add": "/api/interfaces/gif_settings/add_item",
    "set": "/api/interfaces/gif_settings/set_item",
    "delete": "/api/interfaces/gif_settings/del_item",
    "reconfigure": "/api/interfaces/gif_settings/reconfigure",
}

ASSIGNMENT = {
    "search": "/api/interfaces/assignment/search_item",
    "get": "/api/interfaces/assignment/get_item/",
    "add": "/api/interfaces/assignment/add_item",
    "set": "/api/interfaces/assignment/set_item",
    "delete": "/api/interfaces/assignment/del_item",
    "reconfigure": "/api/interfaces/assignment/reconfigure",
}

PRIVILEGE_HINT = (
    "API privilege missing for gif_settings (HTTP 403). Grant the key "
    "Interfaces → Devices → GIF access, then retry."
)


def gif_params_to_wire(params: dict[str, Any]) -> dict[str, Any]:
    """Map MCP create/update fields to Gif.xml wire keys."""
    parent = str(params.get("parent") or "").strip()
    wire: dict[str, Any] = {
        "remote-addr": str(params.get("remote") or "").strip(),
        "tunnel-local-addr": str(params.get("tunnel_local") or "").strip(),
        "tunnel-remote-addr": str(params.get("tunnel_remote") or "").strip(),
        "tunnel-remote-net": str(params.get("tunnel_remote_net", 32)),
        "descr": str(params.get("description") or ""),
        "link1": "1" if params.get("ecn") else "0",
        "link2": "1" if params.get("link2") else "0",
        "noclamp": "1" if params.get("noclamp") else "0",
    }
    if parent:
        # Interface keys are names; addresses parse as IP.
        try:
            ipaddress.ip_address(parent.split("%", 1)[0])
            wire["ipaddr"] = parent
        except ValueError:
            wire["if"] = parent
    device = str(params.get("device") or "").strip()
    if device:
        wire["gifif"] = device
    return wire


def project_gif_row(row: dict[str, Any]) -> dict[str, Any]:
    """Public list/create projection."""
    parent = row.get("if") or row.get("ipaddr") or ""
    return {
        "uuid": row.get("uuid", ""),
        "device": row.get("gifif", ""),
        "parent": parent,
        "remote": row.get("remote-addr", ""),
        "tunnel_local": row.get("tunnel-local-addr", ""),
        "tunnel_remote": row.get("tunnel-remote-addr", ""),
        "tunnel_remote_net": row.get("tunnel-remote-net", ""),
        "description": row.get("descr", ""),
    }
```

- [ ] **Step 6: Re-run mapper tests**

```bash
uv run pytest tests/test_gif_stack.py -k gif_params_to_wire -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add opnsense_mcp/tools/gif_stack.py tests/test_gif_stack.py \
  tests/fixtures/opnsense-26.7.3/gif_*.json docs/research/gif-api-privilege.md
git commit -m "$(cat <<'EOF'
Add GIF wire mapper and privilege prerequisite note

EOF
)"
```

(Use `\cat` if `cat` is aliased to `bat` in the shell.)

---

### Task 2: ListGifTool + 403 handling

**Files:**
- Modify: `opnsense_mcp/tools/gif_stack.py`
- Modify: `tests/test_gif_stack.py`
- Test: fixture-driven list

**Interfaces:**
- Consumes: `project_gif_row`, `GIF`, `PRIVILEGE_HINT`
- Produces: `ListGifTool` with `name = "list_gif"`

- [ ] **Step 1: Failing tests**

```python
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.tools.gif_stack import ListGifTool, PRIVILEGE_HINT

FIX = Path(__file__).parent / "fixtures" / "opnsense-26.7.3"


@pytest.mark.asyncio
async def test_list_gif_projects_rows() -> None:
    payload = json.loads((FIX / "gif_search_item.json").read_text())
    # If only empty synthetic exists, skip body assert and only check shape.
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=payload)
    tool = ListGifTool(client)
    result = await tool.execute({})
    assert result["status"] == "success"
    assert "gifs" in result
    assert result["count"] == len(result["gifs"])
    for row in result["gifs"]:
        assert row.get("device") or result["count"] == 0


@pytest.mark.asyncio
async def test_list_gif_maps_403_to_privilege_error() -> None:
    client = AsyncMock()

    async def boom(*_a, **_k):
        raise RuntimeError("403 Forbidden")  # or whatever the client raises

    # Prefer: client returns {"status": 403, "message": "Forbidden"}
    client._make_request = AsyncMock(
        return_value={"status": 403, "message": "Forbidden"}
    )
    tool = ListGifTool(client)
    result = await tool.execute({})
    assert result["status"] == "error"
    assert "403" in result["error"] or "privilege" in result["error"].lower()
    assert "gif_settings" in result["error"]
```

Adjust the 403 detection to match how `OPNsenseClient._make_request` surfaces HTTP 403 in this repo (read `api.py` / `api_optimized.py` once and assert on that real shape — do not invent a second error channel).

- [ ] **Step 2: Run — expect fail**

```bash
uv run pytest tests/test_gif_stack.py::test_list_gif_projects_rows -v
```

- [ ] **Step 3: Implement `ListGifTool`**

Follow `_RoutingToolBase` patterns from `routing_stack.py` (`_rows`, `_no_client`). Detect 403 body or exception; return privilege error. Otherwise project rows.

- [ ] **Step 4: Tests pass**

```bash
uv run pytest tests/test_gif_stack.py -k list_gif -v
```

- [ ] **Step 5: Commit**

```bash
git commit -m "$(cat <<'EOF'
Add list_gif with explicit 403 privilege errors

EOF
)"
```

---

### Task 3: MkGifTool (create, idempotent, apply)

**Files:**
- Modify: `opnsense_mcp/tools/gif_stack.py`
- Modify: `tests/test_gif_stack.py`

**Interfaces:**
- Consumes: `gif_params_to_wire`, `run_apply`, `GIF`
- Produces: `MkGifTool` (`name = "mk_gif"`) — group action `create_gif` maps to this name

- [ ] **Step 1: Validation + idempotency tests**

```python
@pytest.mark.asyncio
async def test_mk_gif_requires_core_fields() -> None:
    tool = MkGifTool(AsyncMock())
    result = await tool.execute({"parent": "wan"})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_mk_gif_reuses_identical_tunnel() -> None:
    existing = {
        "rows": [
            {
                "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "gifif": "gif0",
                "if": "wan",
                "remote-addr": "203.0.113.10",
                "tunnel-local-addr": "2001:db8:1::2",
                "tunnel-remote-addr": "2001:db8:1::1",
                "tunnel-remote-net": "64",
                "descr": "lab",
            }
        ]
    }
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=existing)
    tool = MkGifTool(client)
    result = await tool.execute(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
        }
    )
    assert result["status"] == "success"
    assert result["created"] is False
    assert result["device"] == "gif0"
    # add_item must not have been called
    assert not any(
        "add_item" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )


@pytest.mark.asyncio
async def test_mk_gif_stages_without_apply_by_default() -> None:
    client = AsyncMock()

    async def fake(method, endpoint, **kwargs):
        if "search_item" in endpoint:
            return {"rows": []}
        if "add_item" in endpoint:
            return {"uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "result": "saved"}
        raise AssertionError(endpoint)

    client._make_request = AsyncMock(side_effect=fake)
    tool = MkGifTool(client)
    result = await tool.execute(
        {
            "parent": "wan",
            "remote": "203.0.113.10",
            "tunnel_local": "2001:db8:1::2",
            "tunnel_remote": "2001:db8:1::1",
            "tunnel_remote_net": 64,
        }
    )
    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert not any(
        "reconfigure" in str(c.args[1])
        for c in client._make_request.await_args_list
        if c.args
    )
```

Declare `apply` in `input_schema` with `"default": False` (required by `test_every_apply_field_declares_its_default`).

- [ ] **Step 2: Implement create**

Payload shape (from GifSettingsController `internalModelName = 'gif'`):

```python
await self.client._make_request(
    "POST", GIF["add"], call_class="write", json={"gif": wire}
)
```

After write, optional `run_apply(self.client, GIF["reconfigure"])` when `apply` is true. Parse tunnel addresses with `ipaddress` before POST; refuse `tunnel_remote_net` outside 1–128.

- [ ] **Step 3: Tests pass + commit**

```bash
uv run pytest tests/test_gif_stack.py -k mk_gif -v
```

---

### Task 4: SetGifTool + RmGifTool (confirm + assignment guard)

**Files:**
- Modify: `opnsense_mcp/tools/gif_stack.py`
- Modify: `tests/test_gif_stack.py`

**Interfaces:**
- Produces: `SetGifTool` (`set_gif`), `RmGifTool` (`rm_gif`)

- [ ] **Step 1: Tests for confirm + holder refusal**

Mirror `RmVlanTool` / `RmLoopbackTool`:

- Missing confirm → `confirmation_required` + token for resource `"gif"`
- Assignment search finds `if == gif0` → error listing holders, no delete POST
- Confirm valid + no holders → delete + optional apply

Also: `SetGifTool` refuses changing `gifif` (firmware overlay locks it); omit device rename from wire on update.

- [ ] **Step 2: Implement using `issue_delete_confirm_token` / `validate_delete_confirm_token`**

Assignment holder check:

```python
rows = await self._assignment_rows()
holders = [
    r.get("identifier") or r.get("uuid") for r in rows if (r.get("if") or "") == device
]
```

- [ ] **Step 3: Ensure delete is listed for confirm discipline**

If `tests/test_every_delete_either_confirms_or_says_why_not` matches on `del_item` endpoint, `RmGifTool` must take `confirm`. No allowlist exception.

- [ ] **Step 4: Commit**

```bash
git commit -m "$(cat <<'EOF'
Add set_gif and rm_gif with assignment delete guards

EOF
)"
```

---

### Task 5: AssignInterfaceTool

**Files:**
- Modify: `opnsense_mcp/tools/gif_stack.py`
- Modify: `tests/test_gif_stack.py`
- Create: `tests/fixtures/opnsense-26.7.3/assignment_get_item_blank.json` (capture or trim from live blank — strip to keys only if huge)

**Interfaces:**
- Produces: `AssignInterfaceTool` (`name = "assign_interface"`) — group action `assign`

- [ ] **Step 1: Probe write shape (privileged session or UI network tab)**

Confirm `POST .../assignment/add_item` JSON. Controller has `addItemAction`. Expect something like:

```json
{"interface": {"descr": "HE-GIF", "if": "gif0"}}
```

Capture one successful add+delete in lab notes; keep fixture of blank `get_item` for “device must be in options” test.

- [ ] **Step 2: Tests**

```python
@pytest.mark.asyncio
async def test_assign_refuses_unknown_device() -> None:
    blank = json.loads((FIX / "assignment_get_item_blank.json").read_text())
    client = AsyncMock()
    client._make_request = AsyncMock(return_value=blank)
    tool = AssignInterfaceTool(client)
    result = await tool.execute({"device": "gif99"})
    assert result["status"] == "error"
    assert "gif99" in result["error"]


@pytest.mark.asyncio
async def test_assign_reuses_existing_binding() -> None:
    client = AsyncMock()
    client._make_request = AsyncMock(
        return_value={
            "rows": [
                {
                    "uuid": "opt20",
                    "identifier": "opt20",
                    "if": "gif0",
                    "descr": "lab",
                    "lock": "0",
                }
            ]
        }
    )
    tool = AssignInterfaceTool(client)
    result = await tool.execute({"device": "gif0"})
    assert result["status"] == "success"
    assert result.get("created") is False
    assert result["identifier"] == "opt20"
```

- [ ] **Step 3: Implement**

1. GET blank; ensure `device` is a key under `interface.if` (or equivalent after flatten).
2. Search assignments; if `if == device`, reuse.
3. Else POST add_item; re-read search; return identifier.
4. `apply` → `ASSIGNMENT["reconfigure"]` via `run_apply`.

- [ ] **Step 4: Commit**

```bash
git commit -m "$(cat <<'EOF'
Add assign_interface for binding devices like gifN

EOF
)"
```

---

### Task 6: Registry + interface_device group + surface golden

**Files:**
- Modify: `opnsense_mcp/utils/registry.py`
- Modify: `opnsense_mcp/utils/tool_groups.py`
- Modify: `tests/fixtures/tool_surface.json` (via regen)
- Modify: `tests/test_guidance_names_are_real.py` pass by construction

**Interfaces:**
- Group actions: `list_gif`, `create_gif`, `update_gif`, `delete_gif`, `assign` (+ existing)

- [ ] **Step 1: Register classes**

Import and append to `TOOL_CLASSES`: `ListGifTool`, `MkGifTool`, `SetGifTool`, `RmGifTool`, `AssignInterfaceTool`.

- [ ] **Step 2: Update GROUPS**

```python
"interface_device": (
    "Create the devices interfaces are built on: 802.1Q VLANs, loopbacks, "
    "and GIF tunnels; assign devices to interface ids",
    {
        "list_vlans": "list_vlans",
        "create_vlan": "mk_vlan",
        "delete_vlan": "rm_vlan",
        "list_loopback": "list_loopback",
        "create_loopback": "mk_loopback",
        "delete_loopback": "rm_loopback",
        "list_gif": "list_gif",
        "create_gif": "mk_gif",
        "update_gif": "set_gif",
        "delete_gif": "rm_gif",
        "assign": "assign_interface",
        "set_address": "set_interface_address",
    },
),
```

- [ ] **Step 3: Regen surface + run contract suite**

```bash
uv run python -m tests.regen_tool_surface
uv run pytest tests/test_tool_surface_contract.py tests/test_guidance_names_are_real.py \
  tests/test_every_apply_field_declares_its_default.py \
  tests/test_every_delete_either_confirms_or_says_why_not.py \
  tests/test_gif_stack.py -q
```

- [ ] **Step 4: Commit**

```bash
git commit -m "$(cat <<'EOF'
Expose GIF and assign on the interface_device group

EOF
)"
```

---

### Task 7: Tunnel Broker example doc + enable path note

**Files:**
- Create: `docs/research/gif-tunnel-broker-example.md`
- Optionally adjust `MkGifTool` / example to mention `set_address` for enable

- [ ] **Step 1: Write example**

Document composition only (no HE-branded tool fields):

1. Ensure API key has GIF privilege; ICMP to broker peer allowed if needed (`fw_rule` / alias) — out of band.
2. `interface_device(action=create_gif, parent=wan, remote=..., tunnel_local=..., tunnel_remote=..., tunnel_remote_net=64, apply=true)`
3. `interface_device(action=assign, device=gif0, description=..., apply=true)`
4. `interface_device(action=set_address, interface=optN, address=..., subnet_bits=...)` if enable/static required beyond GIF device fields
5. `routing` gateway create/set upstream as needed
6. Verify with `diagnostics` / ping
7. Teardown: unassign (assignment delete — if not in v1, document UI/API), then `delete_gif` with confirm

Note: `tunnel_remote_net` firmware default is **32**; IPv6 broker setups must pass **64**.

- [ ] **Step 2: Commit**

```bash
git commit -m "$(cat <<'EOF'
Document GIF Tunnel Broker composition example

EOF
)"
```

---

### Task 8: Live smoke (manual gate)

**Files:** none required (lab notes optional)

- [ ] **Step 1: Confirm ACL** — `list_gif` returns success (not 403)
- [ ] **Step 2: Create disposable lab GIF** with documentation addresses, `apply=true`
- [ ] **Step 3: Assign, verify list + assignment search**
- [ ] **Step 4: Teardown** — remove assignment if added, `delete_gif` with confirm
- [ ] **Step 5: Leave no orphan gifN or locked assignment on the firewall**

Do not commit live site identifiers.

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| GIF list/create/update/delete | 2–4 |
| Mapper / Gif.xml fields | 1 |
| assign | 5 |
| set_address reuse | 7 (doc) + existing tool |
| apply default false + run_apply | 3–5 |
| confirm delete + holder guard | 4 |
| 403 privilege handling | 1–2 |
| interface_device registration | 6 |
| Tunnel Broker example | 7 |
| Live verify / teardown | 8 |
| Cursor schema safety | 6 contract tests |

## Placeholder / consistency review

- Tool names: `list_gif`, `mk_gif`, `set_gif`, `rm_gif`, `assign_interface` ↔ group actions `list_gif`, `create_gif`, `update_gif`, `delete_gif`, `assign`.
- Wire keys match live `Gif.xml`: `remote-addr`, `tunnel-local-addr`, `tunnel-remote-addr`, `tunnel-remote-net`, `gifif`, `if`/`ipaddr`.
- Assignment endpoints from live controller: `add_item`, `set_item`, `del_item`, `reconfigure`.
