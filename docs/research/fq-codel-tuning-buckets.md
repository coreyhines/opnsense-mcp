# FQ-CoDel bandwidth tuning — bucket plan

**Feature:** Live shaper tuning (raise download/upload without latency regression)  
**Approval status:** approved (schedule); measurement revised to flent sidecar 2026-06-20  
**Integration branch:** n/a (live ops, no code branch)  
**Baseline captured:** 2026-06-20

## Current state

| Item | Value |
|------|-------|
| Download pipe | 1776 Mbit/s, fq_codel |
| Upload pipe | 325 Mbit/s, fq_codel |
| WAN rules | IPv4 + IPv6, in/out |
| Audit (no ISP ref) | 100/100 |
| Shaper stats baseline | `7c7de55b-6847-4d75-8e4b-a533f79c366a` |

## Speedtracker baseline (today, Comcast #8088)

| Time | Download | Upload | Ping |
|------|----------|--------|------|
| 5:00pm | 1.33 Gbps | 295 Mbps | 30 ms |
| 4:42pm | 1.13 Gbps | 299 Mbps | 27 ms |
| 4:00pm | 1.66 Gbps | 296 Mbps | 28 ms |
| 3:00pm | 1.48 Gbps | 107 Mbps* | 26 ms |
| 2:00pm | 1.61 Gbps | 287 Mbps | 31 ms |

\*Upload outlier at 3pm — treat as anomaly unless repeated.

**Observations:** Throughput sits **below** shaper caps (headroom exists on paper). Ping stable 26–31 ms on idle speedtests. Raising shaper further only makes sense if ISP plan max exceeds current caps.

## Constraints (user — locked 2026-06-20)

| Parameter | Value |
|-----------|-------|
| ISP plan max (approx) | ~2000↓ / 350–400↑ Mbit |
| Floor (never go below) | 1776↓ / 325↑ Mbit |
| Latency gate | **Loaded** ping (flent `rrul`) **> baseline + 5 ms**; speedtest ping secondary only |
| Tune order | **Download first**, then upload |
| Step up | **+5%** per iteration on active direction |
| Step down (backoff) | On fail: revert to last good; next try **midpoint** between last good and failed (+ bisect until stable) |
| Verify | **`flent rrul` sidecar on net-10** (primary); speedtracker throughput log only |
| Measurement | Option **B**: disposable Ubuntu sidecar on **net-10**, gw **10.0.10.1** → WAN → internet netperf peer |
| Netperf peer | **`netperf-eu.bufferbloat.net`** (works from net-10; `netperf.bufferbloat.net` handshake broken; west DNS dead) |
| Script | `deploy/flent-sidecar-net10.sh` on strongpod → `/opt/containerdata/flent-sidecar-net10.sh` |
| Results dir | strongpod `/opt/containerdata/flent-results/` |
| MCP path | `set_shaper_pipe` → `apply_shaper` → `shaper_statistics` → flent rerun |
| Rollback | `restore_shaper_snapshot` or revert to last-good bandwidth |

## Out of scope

- Changing scheduler away from fq_codel
- IPv6 rule changes (rules exist; v6 traffic minimal)
- Code changes in opnsense-mcp repo
- waveform.net automation (optional manual follow-up)

## Model routing (edited 2026-06-20)

| Role | Owner | Model | Exec |
|------|-------|-------|------|
| Live MCP apply / rollback | Cursor | auto | inline |
| Bisect analysis, pass/fail verdict, final write-up | **Claude** | **opus** | **`claude -p`** (reads session doc + speedtest data pasted by coordinator) |
| Session report file on disk | Cursor | auto | inline |

Claude CLI cannot call OPNsense MCP directly in this workflow — coordinator passes baseline table + each speedtest row into `claude -p` prompts; Cursor executes MCP from Claude's verdict.

**Probe overrides:** O-pre, O-loop, O-final → **Claude opus** (user choice over Ollama-local `pure_logic` default).

## Buckets

| ID | Title | Depends | Owner | Model | Exec |
|----|-------|---------|-------|-------|------|
| T0 | Baseline capture (MCP + speedtracker) | — | Cursor | auto | inline — **done** |
| T1 | Lock tuning parameters | T0 | User + Cursor | auto | inline — **done** |
| O-pre | Claude Opus: baseline analysis + bisect ladder to ~2000↓ | T1 | Claude | opus | `claude -p` |
| T2 | Download step: set pipe, apply, snapshot | O-pre | Cursor | auto | inline |
| T3 | **flent rrul** sidecar rerun (same peer/length) | T2 | Cursor | auto | inline |
| O-loop | Claude Opus: verdict using **loaded ping** (+5 ms vs flent baseline) | T3 | Claude | opus | `claude -p` |
| T4 | Execute Claude verdict via MCP | O-loop | Cursor | auto | inline |
| T5 | Upload wave (repeat T2–O-loop–T4, floor 325↑) | T4 download done | Cursor | auto | inline |
| O-final | Claude Opus: sign-off + sweet-spot summary | T5 | Claude | opus | `claude -p` |
| T6 | Session report file | O-final | Cursor | auto | inline |

### Download iteration math (wave 1 starting point)

| Step | Download Mbit | Notes |
|------|---------------|-------|
| 0 (floor) | 1776 | current |
| 1 | 1865 | +5% |
| 2 | 1958 | +5% |
| 3 | 2056 | +5% — likely above ~2000 ISP; expect ping fail → bisect 1958–2056 |

Upload wave starts only after download sweet spot found; same +5% / backoff rules, ceiling ~350–400.

## Rollback

Before each T2, rely on shaper snapshot from MCP (`restore_shaper_snapshot`) or revert pipe bandwidth to previous values.

## Session reports

Save to `docs/research/fq-codel-tuning-session-YYYY-MM-DD.md` after each execute wave.
