# Traffic shaper BF-fix buckets (post P2h smoke)

**Date:** 2026-06-20  
**Branch:** `feat/traffic-shaper-spec`  
**Trigger:** P2h live MCP smoke + scheduler remediation session

## Bucket registry

| Wave | ID | Fix | GitLab | Status |
|------|-----|-----|--------|--------|
| 1 | **BF1a** | Shaper write POST: `{pipe\|queue\|rule}` wrapper + string enums | [#4](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/4) | Done |
| 1 | **BF1b** | `SCHEDULER_DRIFT` false positive when FQ-CoDel flowset layout OK (OPNsense #8572) | [#5](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/5) | Done |
| 2 | **BF2a** | Deploy runbook: recreate containers after image tag change | — | Done |
| 2 | **BF2b** | MCP-first rule: file GitLab issues before bypass | [#6](https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/work_items/6) | Done |
| 3 | **BF3** | Unit tests + live MCP re-smoke | — | In progress |

## Still open (not in this pass)

| ID | Item |
|----|------|
| MCP-03 | `set_shaper_settings` stub / limited fields |
| FW-02 | Missing IPv6 shaper rules (operator / preset) |
| TEST-01/02 | Pagination register tests; queue/rule write integration |

## Key files (BF1)

| Area | Paths |
|------|-------|
| API POST serialization | `opnsense_mcp/utils/shaper_serialize.py` (`*_api_post`) |
| Write tools | `opnsense_mcp/tools/shaper_pipes.py`, `shaper_queues.py`, `shaper_rules.py` |
| Restore | `opnsense_mcp/utils/shaper_mutation.py` |
| Drift logic | `opnsense_mcp/utils/shaper_interpret.py`, `shaper_audit_rules.py` |
| Mock | `opnsense_mcp/utils/mock_api.py` (`_unwrap_shaper_post`) |
| Fixtures | `tests/fixtures/shaper/statistics.json`, `examples/mock_data/traffic_shaper.json` |

## Verification

```bash
uv run pytest tests/
python benchmark_performance.py   # optional live smoke
```

Live MCP (after redeploy + Cursor reconnect):

1. `dhcp`, `fw_rules` (null args)
2. Shaper read tools
3. `set_shaper_pipe` (harmless re-set of `scheduler=fq_codel`)
4. `shaper_statistics`, `audit_shaper_config` — no `SCHEDULER_DRIFT` on healthy FQ-CoDel layout
