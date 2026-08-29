# ULA RA gaps — bucket plan

**Feature slug:** `ula-ra-gaps`
**Integration branch:** `feat/ula-ra-gaps-spec`
**Source issues (Forgejo):** #26 (RA daemon defect), #27 (dnsmasq range fields), #28 (PD holder)
**Approval status:** approved (user, 2026-08-28)
**Capacity snapshot (before):** `~/code/untracked/opnsense-mcp-notes/pb-sessions/ula-ra-gaps/before.json` (kept outside the repo: the probe records real infra hostnames, which `test_no_site_identifiers.py` scans for on the filesystem regardless of gitignore)
**Session level:** GREEN — anthropic 7% session / 39% week, cursor 23%, ollama-cloud 0% session / 49% week, codex 1% session / 24% week

## Context

The RA tools shipped in Wave 5b (`76419f9`) target radvd. This firewall serves RA through
dnsmasq: ten IPv6 ranges carry `constructor:<iface>` across nine LAN interfaces, while nine of
ten radvd entries are disabled and the tenth sits on an admin-down interface. So
`set_router_advert` writes config nothing reads, and `apply_ula`'s `ra` domain reports
`applied: true` for a reconfigure that changes nothing observable.

Found while bucketizing, not in the issues: `dnsmasq._flat_range_payload` (line 967) rebuilds
the range node from a fixed field list that preserves `ra_mode` and `ra_priority` but omits
`constructor`, `prefix_len`, `ra_interval`, `ra_mtu`, `ra_router_lifetime`, `lease_time` and
`subnet_mask`. `toggle_range` posts that payload, so toggling a v6 range blanks the field that
makes it advertise. This is the partial-POST failure this repo has already paid for once
(`67957c1`). It belongs to B1 and raises that bucket from plumbing to a data-loss fix.

## Buckets

| ID | Title | Profile | Anthropic | Owner | Backend | Model | Exec | Depends | Files (own) |
|----|-------|---------|-----------|-------|---------|-------|------|---------|-------------|
| S1 | Spike: dnsmasq range object shape | spike | none | coordinator | inline | opus | inline | — | none (read-only) |
| S2 | Spike: track-interface + prefix-id | spike | none | coordinator | inline | opus | inline | — | none (read-only) |
| B1 | dnsmasq range fields: read, write, and the toggle blanking bug | write_crud | opus | claude-opus | claude-cli | opus | farm | S1 | `opnsense_mcp/utils/dhcp_providers/dnsmasq.py`, `opnsense_mcp/tools/dhcp_ranges.py`, `tests/test_dhcp_ranges_and_groups.py` |
| B2 | Captured v6 range fixture + shape test | mock_fixtures | none | codex-default | codex-cli | gpt-5.6-sol | farm | S1 | `tests/fixtures/**`, `tests/test_fixture_shapes.py` |
| B3 | RA daemon detector (pure logic) | pure_logic | none | cursor-auto | cursor-cli | auto | farm | — | `opnsense_mcp/utils/ra_daemon.py` (new), `tests/test_ra_daemon.py` (new) |
| B4 | Route RA writes to serving daemon; verify applied state (deprecate action dropped, S1) | write_crud | opus | cursor-named-opus | cursor-cli | opus | farm | B1, B3 | `opnsense_mcp/tools/ula_migration.py`, `tests/test_ula_migration.py` |
| B5 | PD holder: document supported shape and refuse (S2: API cannot express it) | write_crud | none | ollama-cloud | ollama-cloud-cli | glm-5.3:cloud | farm | S2 | `opnsense_mcp/tools/ipv6_stack.py`, `tests/test_ipv6_stack.py` |
| B8 | Docs: CLAUDE.md failure mode + notes addendum | pure_logic | none | opencode-ollama-local | opencode-cli | qwen3.8:27b-mxfp8 | farm | B4 | `CLAUDE.md`, `docs/research/ula-ra-gaps-findings.md` |
| B6 | Wiring: tool groups, registry, help text | mcp_wiring | none | coordinator | inline | opus | inline | B1, B4, B5 | `opnsense_mcp/utils/tool_groups.py`, `opnsense_mcp/utils/registry.py` |
| B7 | Live MCP verify against the firewall | live_mcp | none | coordinator | inline | opus | inline | B6 | none (read-only) |

## Waves

```text
Wave 0:  S1 ∥ S2                    (coordinator, read-only, live firewall)
Wave 1:  B1 ∥ B2 ∥ B3               (three pools, disjoint files)
Wave 2:  B4                         (needs B1 write path + B3 detector)
Wave 3:  B5 ∥ B8                    (B5 gated on S2's answer)
Wave 4:  B6 → B7                    (coordinator inline, wiring then live verify)
```

## Merge order

`S1, S2 → (B1 ∥ B2 ∥ B3) → B4 → (B5 ∥ B8) → B6 → B7`

## Probe overrides

| Bucket | Probe said | Assigned | Why |
|---|---|---|---|
| B4 | ollama-cloud | cursor-named-opus | B4 is the bucket issue #26 turns on: it replaces a false-success path with a verify-the-state path. It is tagged opus-tier and should land on an opus-tier executor. |
| B5 | cursor-named-opus | ollama-cloud | Swapped with B4. B5 is mechanical once S2 answers, and may reduce to "document and refuse". |

Both sides of the swap keep the same six capacity groups, so the spread is unchanged.

## Do NOT

- B1 must not touch `ula_migration.py` (B4 owns it) or `tests/test_fixture_shapes.py` (B2 owns it).
- B2 must not edit tool or provider source; fixtures and the shape test only.
- B3 must not wire the detector into any tool; B4 consumes it.
- B4 must not change the dnsmasq provider; it calls B1's API.
- B5 must not proceed past S2's verdict. If S2 says track-interface is unsupported, B5's
  deliverable is an explicit refusal plus the recorded reason, not a partial implementation.
- No bucket edits `tool_groups.py` or `registry.py`; B6 owns wiring, last.

## Out of scope

- Executing any part of the ULA migration on the live firewall. This is tool work only.
- `plan_dns_ula` per-`/64` granularity. Per-VLAN staging makes that the right shape, not a gap.
- radvd removal. It stays configured and inert; B4 only stops writing to it blindly.

## Status

| Bucket | Status | Branch | Commit | Sub-agent |
|---|---|---|---|---|
| S1 | **done** | — | — | coordinator inline |
| S2 | **done** | — | — | coordinator inline |
| B1 | **merged** | `feat/ula-ra-gaps-bucket-B1-claude` | `e206d91` | claude-cli |
| B2 | **merged** | `feat/ula-ra-gaps-bucket-B2-codex` | `969ce93` | codex-cli |
| B3 | **merged** | `feat/ula-ra-gaps-bucket-B3-cursor` | `ef16641` | cursor-cli |
| B4 | **merged** | `feat/ula-ra-gaps-bucket-B4-cursor` | `fffacd8` | cursor-cli |
| B5 | **merged** (rerouted ollama-cloud → codex) | `feat/ula-ra-gaps-bucket-B5-codex` | `9a1cfeb` | codex-cli |
| B8 | running (rerouted opencode → ollama-local) | `feat/ula-ra-gaps-bucket-B8-ollama` | — | ollama-local |
| B6 | pending | — | — | — |
| B7 | pending | — | — | — |
