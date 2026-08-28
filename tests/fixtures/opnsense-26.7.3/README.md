# OPNsense 26.7.3 API fixtures

Recorded from a live firewall so normalizers are coded against real payload
shapes rather than guessed field names. Field names, nesting, enum option sets
and value formats are preserved exactly. Only site-identifying values are
replaced, using the same mapping as `../opnsense-26.7.2/README.md`.

These two exist because hand-written fixtures used key names the API does not
emit, so two normalizers were tested against the shape they already expected
and returned empty values against the firewall while the suite stayed green:

- `fw_rules.py` read `source` / `destination`; rows carry `source_net` /
  `destination_net`, so every rule listed as any->any.
- `dhcp_scope.py` read `subnet` / `start` / `rangestart`; dnsmasq range rows
  carry `start_addr` / `end_addr` and no subnet key at all, so the documented
  `subnet` selector could never match.

## Files

| File | Source | Used by |
|---|---|---|
| `filter_searchrule_rows.json` | `POST firewall/filter/searchRule` | `tests/test_fixture_shapes.py`, `tests/test_live_findings.py` |
| `dnsmasq_search_range_rows.json` | `GET dnsmasq/settings/search_range` | `tests/test_fixture_shapes.py`, `tests/test_live_findings.py` |

## Adding a fixture

Capture the whole response, not the row you care about: the keys that are
absent are the finding. Sanitise per the table in the 26.7.2 README, then add
a contract test that asserts the normalizer produces **non-empty** values from
it. A test that only checks a key exists is what let both defects ship.
