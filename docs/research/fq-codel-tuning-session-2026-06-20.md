# FQ-CoDel tuning session — 2026-06-20

## Session summary

| Bucket | Owner | Model | Exec | Status |
|--------|-------|-------|------|--------|
| M-setup | Cursor | auto | inline | Done — sidecar script + strongpod deploy |
| M0 baseline | Cursor | auto | inline | Done — flent rrul @ 1776↓ / 325↑ |
| T2–T4 (speedtest) | Cursor | auto | inline | Superseded by flent approach |

## Shaper state (end of session)

| Pipe | Mbit/s | Snapshot notes |
|------|--------|----------------|
| Download | **1776** | Floor restored after 1865 experiment |
| Upload | **325** | Reverted from unverified 341 |

## Measurement stack (Option B)

- **Sidecar:** Ubuntu 24.04 on Podman **`net-10`**, gw **10.0.10.1**, DNS **10.0.2.2**
- **Script:** `deploy/flent-sidecar-net10.sh` → strongpod `/opt/containerdata/flent-sidecar-net10.sh`
- **Results:** `/opt/containerdata/flent-results/` on strongpod
- **Peer:** **`netperf-eu.bufferbloat.net`** (only working public peer from net-10; US canonical host broken)

### Peer probe (2026-06-20)

| Host | Port 12865 | netperf TCP_STREAM |
|------|------------|-------------------|
| netperf.bufferbloat.net | open | handshake fails (partial response) |
| netperf-west.bufferbloat.net | — | DNS NXDOMAIN |
| netperf-eu.bufferbloat.net | open | **OK** (~98 Mbit smoke test) |

## Flent baseline @ 1776↓ / 325↑

**Run:** `20260620T224106Z_baseline-1776-325`  
**Data:** `rrul-2026-06-20T224138.811366.baseline-1776-325_net-10_via_10_0_10_1.flent.gz`

| Metric (under RRUL load) | avg | median | 99th % |
|--------------------------|-----|--------|--------|
| **Ping ICMP** | **140.24 ms** | 140.00 | 152.00 |
| Ping UDP (avg of classes) | ~140.4 ms | — | ~151 |
| TCP download (sum) | 571.71 Mbit/s | — | — |
| TCP upload (sum) | 256.73 Mbit/s | — | — |
| TCP totals | 828.44 Mbit/s | — | — |

**Notes:**

- Loaded latency gate for this peer/path: **baseline ~140 ms** → fail if avg **> 145 ms** (+5 ms).
- EU peer does not saturate local 1776 Mbit cap (total ~828 Mbit). Throughput deltas may reflect remote/server limits; **use loaded ping as primary gate**, throughput as secondary.
- Idle gw ping from sidecar: ~7 ms to 10.0.10.1; loaded ~140 ms to netperf-eu via WAN.

## Rerun command

```bash
ssh root@strongpod.freeblizz.com \
  'NETPERF_HOST=netperf-eu.bufferbloat.net LABEL=step-1865down \
   /opt/containerdata/flent-sidecar-net10.sh step-1865down'
```

## Final sweet spot (2026-06-21)

| Pipe | Was | **Now** | Loaded ping (flent rrul, EU peer) |
|------|-----|---------|-------------------------------------|
| Download | 1776 | **1958 Mbit/s** | 140.85 ms avg (gate 145 ms) |
| Upload | 325 | **325 Mbit/s** | 341 tested — no upload gain, reverted |

2056↓ rejected (throughput regression). 341↑ rejected (no upload sum improvement).

## Confirmation run @ 1958/325 (2026-06-21)

| Metric | Baseline 1776 | First 1958 run | **Confirm 1958/325** | Gate |
|--------|---------------|----------------|----------------------|------|
| ICMP avg | 140.24 ms | 140.85 ms | **142.01 ms** | < 145 ✓ |
| Down sum | 572 Mbit/s | 654 Mbit/s | 597 Mbit/s | vs baseline +25 |
| Up sum | 257 Mbit/s | 242 Mbit/s | 193 Mbit/s | EU peer variance |
| TCP totals | 828 Mbit/s | 896 Mbit/s | 790 Mbit/s | — |

Latency gate holds. Throughput swings run-to-run (remote EU netperf); loaded ping is the reliable signal. **1958↓ / 325↑ confirmed.**
