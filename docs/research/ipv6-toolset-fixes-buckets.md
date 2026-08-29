# Bucket plan — ipv6-toolset-fixes

Source: NPTv6/ULA toolset readiness review, 2026-08-29 (defects D1–D5 + phase-2 capability gaps).
Integration branch: `feat/ipv6-toolset-fixes`
Approval status: **pending**
Capacity snapshot (before): kept outside the repo, in the notes tree under
`docs/research/pb-sessions/ipv6-toolset-fixes/` — these record real infra hostnames and
`test_no_site_identifiers.py` walks everything under `docs/`.

## Scope

In: D1–D5, the phase-2 capability gaps (GUA literal inventory, bulk ULA DNS apply),
and the research-note corrections in `~/code/untracked/opnsense-mcp-notes`.

Out: performing any part of the migration; writes to the firewall beyond what a
falsification test needs; Forgejo issue filing; EVPN; quadlet/Netavark changes.

## Standing rule for every bucket

Each bucket ships a test that **fails when its defect is reintroduced**. A bucket whose
test passes both with and without the fix is not done. This is the repo's own rule
(`CLAUDE.md`, "Failure modes this project has already paid for") and it is what caught
the CLAUDE.md overclaim in the previous wave.

## Buckets

| ID | Title | Defect | Profile | Owns |
|---|---|---|---|---|
| B0 | Captured API fixtures (contract) | D1 input | contract | `tests/fixtures/opnsense-26.7.3/{radvd_get_entry,unbound_gethostoverride,npt_get_rule_blank,vip_get_item_blank}.json`, that dir's `README.md` |
| B1 | RA correctness in ula_migration | D1a + D5 | write_crud | `opnsense_mcp/tools/ula_migration.py`, `tests/test_ula_migration.py` |
| B2 | Shape check covers node responses | D1b | pure_logic | `benchmark_performance.py`, `tests/test_shape_check.py` (new) |
| B3 | ipv6_stack contract fixes | D3 + D4 | write_crud | `opnsense_mcp/tools/ipv6_stack.py`, `tests/test_ipv6_stack.py`, `tests/test_schema_completeness.py` (new) |
| B4 | Server reports its own runtime paths | D2a | write_crud | `opnsense_mcp/tools/system.py`, `opnsense_mcp/utils/deploy_probe.py` (new), `tests/test_deploy_runtime_paths.py` |
| B5 | GUA literal inventory | gap | read_tools | `opnsense_mcp/tools/ula_inventory.py` (new), `tests/test_ula_inventory.py` (new) |
| B6 | Bulk ULA DNS apply | gap | write_crud | `opnsense_mcp/tools/ula_dns_apply.py` (new), `tests/test_ula_dns_apply.py` (new) |
| B7 | Wiring | — | mcp_wiring | `opnsense_mcp/utils/registry.py`, `opnsense_mcp/utils/tool_groups.py`, `tests/fixtures/tool_surface.json` |
| B8 | Host quadlet redeploy | D2b | coordinator | container host unit file (no repo files) |
| B9 | Research-note corrections | — | pure_logic | `~/code/untracked/opnsense-mcp-notes/research/2026-08-24-ula-nptv6-feasibility.md` |
| R1 | Review: falsification adequacy | — | pure_logic (review) | read-only |
| R2 | Review: live-API fidelity | — | pure_logic (review) | read-only |
| R3 | Review: blast radius of new writes | — | pure_logic (review) | read-only |

## Bucket detail

### B0 — captured API fixtures (contract, no code)
Land the five live captures as fixtures. This is the contract every other bucket reads.
The whole reason D1 exists is that `RA_ENTRY` was hand-written; nothing downstream may
invent a key. **Do NOT** write code, touch tools, or edit tests.

### B1 — RA correctness (D1a + D5)
- Fix `SetRouterAdvertTool`'s node extraction against the captured `get_entry` shape.
  `list_adverts` returns uuids that `set_advert` currently cannot resolve.
- Replace `RA_ENTRY` / `RA_ENTRY_ENABLED` with the B0 capture.
- `_apply_ra_domain` must verify something a reconfigure could actually change — the
  serving daemon's advertised config, not the daemon classification (which reconfigure
  never alters, so `verified: true` is currently near-unconditional).
- Falsification: restoring the `"entry"` key assumption fails a test; stubbing the
  apply comparison fails `test_apply_ula_reports_verification_failure` **and** a new
  test that a no-op reconfigure no longer reports `verified: true`.
**Do NOT** touch `ipv6_stack.py`, `benchmark_performance.py`, `registry.py`, `tool_groups.py`.

### B2 — shape check covers node responses (D1b)
- `_row_keys` returns an empty set for a `get_*` node response, so a node fixture would
  compare empty-to-empty and never drift. Add node-shaped extraction; let `SHAPE_SOURCES`
  declare the response kind.
- Add the four get-shaped endpoints to `SHAPE_SOURCES`, reading B0's fixture paths.
- Falsification: a renamed key must report DRIFT; a node fixture must not silently pass.
**Do NOT** write fixture files (B0 owns them) or touch any tool.

### B3 — ipv6_stack contract fixes (D3 + D4)
- `MkVipTool` gets the rigor `MkNptRuleTool` already has beside it: parse `subnet` with
  `ipaddress`, enforce family, bound `subnet_bits` by family, refuse a host/prefix mismatch.
- `MkLoopbackTool` declares `ipaddrv6`, `track6-interface`, `track6-prefix-id` in
  `input_schema` so its track6 refusal is reachable over MCP at all.
- New cross-cutting test: every param a member tool reads from `params` is declared in
  its `input_schema`.
- Falsification: removing the parse lets a garbage subnet through; dropping the schema
  keys fails the completeness test.
**Do NOT** touch `ula_migration.py`, `registry.py`, `tool_groups.py`.

### B4 — server reports its own runtime paths (D2a)
- `deploy_probe.py`: pure logic, path → resolved/writable/missing with reason codes.
- `system.py`: `mcp_server` gains `runtime_paths` (backup dir, ssh key dir).
- Rewrite the backup assertions in `test_deploy_runtime_paths.py` to say plainly they
  check the repo *example*, and add the live check as a command, not a test.
- Falsification: with `OPNSENSE_BACKUP_DIR` unset the report must say `download` cannot work.
**Do NOT** edit the quadlet example or touch the host.

### B5 — GUA literal inventory (gap)
Read-only sweep for addresses inside a given prefix across aliases, filter rules, DHCP
reservations and Unbound overrides, reporting where each literal lives. Fixture-driven
from captured shapes; assert normalized values are non-empty.
**Do NOT** wire it into the registry — B7 owns that.

### B6 — bulk ULA DNS apply (gap)
Consume a `plan_ula` mapping and execute add-then-delete per record. `dry_run` default
true. Per-record result. Never delete before the add reads back. Refuse when a record's
current value has drifted from the plan.
**Do NOT** wire it into the registry — B7 owns that.

### B7 — wiring (coordinator, inline)
Register B5 and B6, place them in `tool_groups`, refresh the surface fixture.

### B8 — host quadlet redeploy (coordinator, inline)
Redeploy the installed unit so `OPNSENSE_BACKUP_DIR` resolves. Outward-facing: confirm
with the user before touching the host. Verify with B4's live check, not with a claim.

### B9 — research-note corrections (coordinator, subagent)
Correct the prefix-id F collision (the WireGuard interface already holds prefix-id 15,
0xF, off the delegated /60)
and the stale §2 interface table. Not a git repo; no commit, file edits only.

### R1–R3 — adversarial review wave (read-only, parallel)
- R1: does each bucket's test actually fail when its defect is reintroduced?
- R2: does any fixture, field name or normalizer still assume a shape the firewall
  does not send?
- R3: blast radius of the new write paths (bulk DNS apply, VIP validation) — silent
  failures, partial application, success reported for a no-op.

## Merge order

`B0 → (B1 ∥ B2 ∥ B3 ∥ B4 ∥ B9) → (B5 ∥ B6) → B7 → B8 → (R1 ∥ R2 ∥ R3)`

## Status

| Bucket | Owner | Backend | Model | Exec | Branch | Commit | Tests | Status |
|---|---|---|---|---|---|---|---|---|
| B0 | coordinator | inline | opus | inline | — | — | — | pending |
| B1 | claude-opus | claude-cli | opus | — | — | — | — | pending |
| B2 | ollama-local | ollama-local-cli | qwen3.6:35b-a3b-mxfp8 | — | — | — | — | pending |
| B3 | cursor-auto | cursor-cli | auto | — | — | — | — | pending |
| B4 | ollama-cloud | ollama-cloud-cli | glm-5.3:cloud | — | — | — | — | pending |
| B5 | codex-default | codex-cli | gpt-5.6-sol | — | — | — | — | pending |
| B6 | claude-opus | claude-cli | opus | — | — | — | — | pending |
| B7 | coordinator | inline | opus | inline | — | — | — | pending |
| B8 | coordinator | inline | opus | inline | — | — | — | pending |
| B9 | coordinator | inline | opus | subagent | — | — | — | pending |
| R1 | coordinator | inline | opus | subagent | — | — | — | pending |
| R2 | coordinator | inline | opus | subagent | — | — | — | pending |
| R3 | coordinator | inline | opus | subagent | — | — | — | pending |
