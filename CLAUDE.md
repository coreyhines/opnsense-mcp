# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that exposes OPNsense firewall management capabilities to AI assistants. It provides tools for querying ARP/NDP tables, DHCP leases, firewall logs, LLDP neighbors, interface lists, firewall rules, and system status.

## Environment Variables

All connection credentials come from environment variables, typically loaded from `~/.env` (see `opnsense_mcp/utils/env.py`):

```
OPNSENSE_FIREWALL_HOST   # Hostname/IP of the OPNsense firewall
OPNSENSE_API_KEY         # OPNsense API key
OPNSENSE_API_SECRET      # OPNsense API secret
```

## Commands

```bash
# Run all tests
uv run pytest tests/

# Run a single test file
uv run pytest tests/test_arp.py

# Run a single test
uv run pytest tests/test_arp.py::test_function_name

# Lint and format
uv run ruff check .
uv run ruff format .

# Benchmark all tools against a live firewall
python benchmark_performance.py
python benchmark_performance.py --output results.json --verbose
```

## Architecture

```
opnsense_mcp/
├── server.py           # MCP server entry point; exports get_opnsense_client()
├── tools/              # One file per MCP tool exposed to the AI
│   ├── arp.py          # ARPTool
│   ├── dhcp.py         # DHCPTool
│   ├── fw_rules.py     # FwRulesTool
│   ├── get_logs.py     # GetLogsTool
│   ├── interface_list.py # InterfaceListTool
│   ├── lldp.py         # LLDPTool
│   └── system.py       # SystemTool
└── utils/
    └── api_optimized.py  # OptimizedOPNsenseClient — direct HTTP with pre-computed auth headers
```

**Request flow**: MCP client → `server.py` → Tool class → `OptimizedOPNsenseClient` → OPNsense REST API (`https://<host>/api/...`)

**Client design**: `OptimizedOPNsenseClient` uses `requests` (not pyopnsense) with Basic auth headers pre-computed at init time, `verify=False` for self-signed certs, and aggressive timeouts (2–3 seconds). Sync HTTP calls are run in a thread executor so tool `execute()` methods can be async.

**Tool pattern**: Each tool takes a client instance and implements `async execute(args: dict) -> dict`.

## Git Commits and Pushes

`cat` is aliased to `bat` (a syntax-highlighting pager) in this shell. This means `$(cat <<'EOF'...EOF)` heredocs used for commit messages get wrapped in ANSI color escape sequences, which are stored literally in the commit message.

Always use `\cat` (backslash bypasses the alias) when constructing commit messages:

```bash
git commit -m "$(\cat <<'EOF'
your message here

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

Never use bare `cat` in a commit message heredoc.

## OPNsense MCP Output

When displaying results from OPNsense MCP tools, summarize the data in a human-readable format (tables, bullet points, or prose). Do not show raw JSON unless the user explicitly asks for it.

## MCP-first live operations

For homelab changes (DHCP, DNS, firewall), **use MCP tools** against the deployed server — not `uv run python` with `get_opnsense_client()` in this repo. See `.cursor/rules/mcp-first.mdc`. Fallback only when MCP is errored or no tool exists; say why.

**Testing MCP:** agent sessions using MCP tools (primary), `python benchmark_performance.py` (live smoke), `uv run pytest tests/` (unit). Workspace Python bypasses the MCP protocol path.

## Code Standards

- Python 3.12+, typing annotations and docstrings on all functions/classes
- Use `uv` for dependency management
- Ruff for linting and formatting (f-strings preferred except where they cause TRY401 issues)
- pytest (not unittest) for all tests; place tests in `./tests/` with `__init__.py`
- Do not break existing functionality during cleanup or formatting passes

## Writing: commits, PRs, and replies

Short. The user has asked twice; assume the ask stands.

**Commits.** Subject under 60 chars. Body at most 3-4 lines, and only when the
change is not self-evident: say what was wrong, not what the code now does.
No section headings, no tables, no bullet lists, no restating the diff. If the
reasoning needs more room, it belongs in a code comment next to the thing.

**PR bodies.** Lead with what broke. Skip the tour.

**Replies.** Answer, then stop. Cut in this order:
- preamble ("Here's what I found", "Let me explain") and sign-offs
- restating what was just asked
- tables with two rows
- narrating tool calls the user can see
- summarising work already summarised

**Banned constructions**, because they appear constantly and add nothing:
- "X isn't just Y, it's Z" and other negative parallelism
- "the thing is", "worth noting", "it's worth flagging"
- opening a paragraph with "Importantly" or "Critically"
- bolding a phrase for emphasis mid-sentence
- em dashes as dramatic pauses; use a comma or a full stop
- closing with a rhetorical flourish about what the work "really" means

Findings do not need selling. State the defect, the evidence, the fix.

## Failure modes this project has already paid for

Each of these shipped a defect. They are listed because intending to avoid them
did not work; the checks did.

**A safety claim needs a falsification test, not a happy-path test.**
`set_interface_address` documented "parsed by ipaddress, so injection fails to
parse". Nobody tested the claim, and it was false for IPv6 scope ids
(`fe80::1%$(reboot)` parses). Its read-back was a substring match, so
`198.51.100.1` was satisfied by `198.51.100.10`. When a docstring says a thing
is safe, write the test that tries to break it in that exact way.

**Assert on structured fields, not on message wording.** Four assertions here
tested phrasing and passed or failed for the wrong reason (`"enable"` is not a
substring of `"enabling"`). Assert `result["status"]`, `result["applied"]`, the
absence of a key — not that an error message contains a chosen phrase.

**Cleanup must be gated on the step it undoes.** A `finally` that deleted a
device regardless of whether the unassign succeeded left an orphaned,
lock-protected interface on the live firewall. Teardown checks the previous
step's result before proceeding.

**Never chain a gate with `;`.** `ruff check . ; git commit && git push` pushes
a lint failure, because the pipeline reports the last command. Use `&&`
throughout. This pushed broken commits three times in one session.

**Replace a sweep with a test.** Two grep-based reference sweeps missed
`README.md` at the repository root. `tests/test_review_wave4.py` now walks every
markdown file and fails on a tool name the registry does not know. When
removing or renaming something, the deliverable is the test, not the grep.

**Read the error body before concluding an API cannot do something.**
`del_item` returning 500 was declared undoable; the body said "Interface
locked, unset lock first before removal". The fix was three commands.

**Probe scripts run against the live firewall and deserve the same care as
tools.** Every orphan left on the firewall this session came from a throwaway
script, not from a tool. A probe named `test_*` at the repository root is worse:
pytest collects it, so a routine test run opens live connections. Keep probes
out of the collection path.

**A fixture that uses key names the API does not emit tests nothing.**
`fw_rules.py` read `source`/`destination` where `searchRule` sends
`source_net`/`destination_net`, so every rule on the firewall listed as
any->any. `dhcp_scope.py` read `start`/`rangestart` where dnsmasq range rows
send `start_addr`/`end_addr`, so the documented `subnet` selector could never
match. Both suites were green throughout, because each normalizer was fed a
hand-written fixture in the shape it already expected, and nothing asserted a
normalized value was ever non-empty. Capture the response, keep the keys it
really has, and assert on values.

**A group selector eats a member field of the same name.** `GroupedTool` pops
`action` to choose the member, so every member declaring its own `action` was
unreachable: created rules were always `pass`, list could not filter, and a
packet capture could be started but never stopped. Adding a member is where
this recurs, so it is a test rather than a habit.

**Say whether the operation ran, not what it found.** A shaper audit that found
problems returned `status: "error"`, which a caller cannot tell from an audit
that failed to run. Severity goes in the payload.

**A bind mount whose source nothing created mounts empty, and does not fail.**
The quadlet mounted a host `ssh` directory at `/root/.ssh` and nothing created
it. Podman creates a missing bind source rather than refusing, so the deploy
succeeded and handed the container an empty mount; every SSH-backed tool then
failed one call at a time. `config_backup download` was the same shape: the
variable was unset and the only mounted path was read-only. Neither is visible
at deploy time. A mount needs a directory someone created and a test that says
so.

**Verify the state you report, do not infer it from the call that returned ok.**
`delete_pipe` returned `applied: true` because `service/reconfigure` returned
ok. Reconfigure removes the config row without flushing the dummynet pipe, so
the kernel kept it and one orphan accumulated per delete. An apply reporting
success is evidence the request was accepted, not that the system reached the
state.

**A tool that writes to a service nobody is running reports success forever.**
`ula_migration.py` targeted radvd unconditionally. This firewall serves RA
through dnsmasq: ten v6 ranges carry a constructor field across nine
interfaces, while nine of ten radvd entries are disabled and the tenth is on an
admin-down interface. `apply_ula` called `radvd/service/reconfigure`, got `ok`,
and reported `applied: true` having changed nothing observable. The design spec
listed radvd or dnsmasq as alternatives and made "which one does this box use"
a gate. The gate was never closed and the tools were built for radvd anyway.
The fix: writes now consult which daemon actually serves, and the apply
re-reads and reports `applied: false` when the state does not match.

**A scripted falsification loop can lie to you via stale bytecode.**
Reverting one site at a time often produces files of *identical byte length*,
because the inserted block is the same across sites sharing an endpoint
constant. CPython invalidates `.pyc` on `(mtime, size)`, and mtimes are
second-granularity, so a fast revert-and-check loop can reuse stale bytecode
and report a reverted site as still passing. Two of three loop runs disagreed
before this was found. Any scripted revert loop here needs
`PYTHONDONTWRITEBYTECODE=1` and a `__pycache__` sweep between iterations, or it
under-reports — which means the method this list depends on quietly stops
working.

**A check that reads documentation is not a check on the deployment.**
`test_deploy_runtime_paths` asserted against `deploy/*.container.example` and
passed for months while installed units left `OPNSENSE_BACKUP_DIR` unset and
`/root/.ssh` unmounted. `install.sh` never reads that file: it verifies it
exists, then writes the unit from its own printf lines, which omitted all
three. The tests now parse the unit the installer generates. Separately, the
installer only ever ran `systemctl start`, which is a no-op on an active unit,
so a re-run rewrote the quadlet and left the old container running.

**Now enforced, not remembered.**
`.claude/hooks/bash_guard.py` runs as a `PreToolUse` hook on every Bash call. It
refuses the `;`-chained publish and the bare-cat heredoc, and warns on workspace
Python calling `get_opnsense_client()`. `tests/test_bash_guard.py` holds the
falsification cases, including the one where the guard blocked its own commit
for quoting a pattern it forbids.

Nine more run as tests:

| Check | Fails when |
|---|---|
| `test_guidance_names_are_real.py` | a source string names an action or offers a `tool()` call the registry does not know |
| `test_no_member_field_collides_with_the_group_selector` | a member declares `action` without a `FIELD_ALIASES` entry |
| `test_every_apply_field_declares_its_default` | a tool takes `apply` without saying what omitting it does |
| `test_fixture_shapes.py` | a normalizer produces empty values from a captured response |
| `test_every_delete_either_confirms_or_says_why_not` | a delete takes no confirm token and no reason is recorded for it |
| `test_deploy_runtime_paths.py` | a quadlet mounts a path no install step creates, or backups are unset or read-only |
| `test_ssh_known_hosts.py` | the host-key check accepts a listed name presenting the wrong key |
| `test_shaper_kernel_sync.py` | an applied delete reports success while the kernel still holds the pipe |
| `test_apply_ula_reports_verification_failure` | an applied RA change reports success while the serving daemon does not match |
| `test_apply_discipline.py` | a call passes `call_class="apply"` without going through `run_apply`, so a configd refusal at HTTP 200 reads as applied |
| `test_every_delete_either_confirms_or_says_why_not` | a tool whose class posts to a `del*` endpoint takes no confirm token and is not listed with a reason — matched on the endpoint, not the action name |
| `test_schema_completeness.py` | `execute` reads a `params` key the tool's own `input_schema` never declares |
| `test_shape_check.py` | a node-shaped API response is compared with the row extractor, so empty matches empty and nothing is checked |

`benchmark_performance.py --check-shapes` diffs live response keys against the
captured fixtures. It needs the firewall, so it is a command rather than a test.

Every check here was verified by reintroducing the defect and watching it fail.
The rest of this list is still read rather than run.
