# Bucket plan — apply-repo-wide

Source: R3's review finding, extended repo-wide. 20 `call_class="apply"` sites in 9
files bypass `opnsense_mcp/utils/apply.run_apply`.
Integration branch: `feat/ipv6-toolset-fixes` (continues the current wave)
Approval status: **pending**
Capacity snapshot: notes tree, `docs/research/pb-sessions/apply-repo-wide/`

## The defect, twice

`utils/apply.py` was written after adversarial review found two things, and its own
docstring names both:

1. **Nothing read what reconfigure answered.** `ApiMutableServiceControllerBase` returns
   `{"status": ...}`; the client raises only on `{"result": "failed"}`. A configd refusal
   arrives as HTTP 200 and the tool reports the change applied.
2. **The reconfigure sat inside the write's `try`.** An apply failure was caught by the
   write's handler and reported as the write having failed — which for a delete inverts
   the truth: the record is gone and the caller is told it is not.

`run_apply` fixes (1). Fixing (2) is per-call-site: catch `ApplyError` separately, keep
`status` success, report `applied: false` with the reason.

Three paths were converted this wave (`ula_migration` ×2, `ula_dns_apply` ×1). Twenty
were not.

## Scope

| Shape | Sites | Files |
|---|---|---|
| A — apply inside the write's `try`, needs both fixes | 11 | `routing_stack` (7), `ipv6_stack` (2), `nat_outbound` (1), `fw_groups` (1) |
| B — helper or client method that returns the response | 9 | `alias_write` (1), `dhcp_ranges` (1), `shaper_mutation` (1), `utils/api` (3), plus callers |

## Buckets

| ID | Title | Owns | Sites |
|---|---|---|---|
| C1 | routing_stack applies | `opnsense_mcp/tools/routing_stack.py`, `tests/test_routing_stack.py` | 7 |
| C2 | ipv6_stack, nat_outbound, fw_groups applies | those three tools + their tests | 4 |
| C3 | helper-method applies | `alias_write.py`, `dhcp_ranges.py`, `utils/shaper_mutation.py` + tests | 3 |
| C4 | client-layer applies | `opnsense_mcp/utils/api.py` + tests | 3 |
| C5 | the enforcing test | `tests/test_apply_discipline.py` (new) | — |

## C5 is the point

Without it this is a one-off cleanup that regresses the next time someone adds a tool.
C5 fails when any tool issues `call_class="apply"` without going through `run_apply`,
by walking the AST the way `tests/_schema_ast.py` already does for params. Any site that
genuinely must stay raw goes in an allowlist **with a reason**, the pattern
`DELETES_WITHOUT_CONFIRM` and `_ALLOWLIST` already use here.

C5 lands last because it is red until C1–C4 are in.

## Do NOT (all buckets)

- Do not change any tool's `apply` default. This makes failures visible; it does not
  change when a change goes live.
- Do not touch `utils/apply.py`. It is correct and shared.
- Do not edit another bucket's files.

## Falsification (all buckets)

Per converted site: make the reconfigure return `{"status": "failed"}` at HTTP 200 and
assert the tool reports `applied: false` with `status` still success. A test that only
checks the happy path does not close this.

## Merge order

`(C1 ∥ C2 ∥ C3 ∥ C4) → C5`

## Status

| Bucket | Owner | Backend | Model | Exec | Status |
|---|---|---|---|---|---|
| C1 | claude-opus | claude-cli | opus | — | pending |
| C2 | codex-default | codex-cli | gpt-5.6-sol | — | pending |
| C3 | ollama-cloud | ollama-cloud-cli | glm-5.3:cloud | — | pending |
| C4 | cursor-auto | cursor-cli | auto | — | pending |
| C5 | coordinator | inline | opus | inline | pending |
