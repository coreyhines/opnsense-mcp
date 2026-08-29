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

## Node-shaped captures (`get_*`), 2026-08-29

Captured live off OPNsense 26.7.3_8. Addresses moved into `2001:db8::/32`
and the domain to `example.com`; every key name is exactly what the
firewall sent.

| File | Endpoint | Root key |
|---|---|---|
| `radvd_get_entry.json` | `radvd/settings/get_entry/<uuid>` | `entries` |
| `unbound_gethostoverride.json` | `unbound/settings/getHostOverride/<uuid>` | `host` |
| `npt_get_rule_blank.json` | `firewall/npt/get_rule` | `rule` |
| `vip_get_item_blank.json` | `interfaces/vip_settings/get_item` | `vip` |

These exist because a hand-written fixture said the radvd root key was
`entry`. It is `entries`, so `set_advert` could not resolve any uuid
`list_adverts` returned, and the suite stayed green throughout: the
fixture and the code shared one wrong assumption, which is not a test.

The NPT model confirms `source_net` / `destination_net` / `trackif`,
which the code already had right.

The VIP model is worth a note, because reading it wrongly is how this
paragraph first got written. Its fields are `address`, `network` and
`descr`; there is no `subnet` or `subnet_bits`, and `mk_vip` posts
exactly those two names. That looks like the defect this directory
exists to catch, and it is not: tested on the live firewall by creating
an ipalias VIP through `mk_vip`, reading it back, and deleting it, the
address round-trips correctly. `search_item` renders `subnet` and
`subnet_bits` as display columns and the write path accepts them.

A model's field list is evidence about storage, not about what a
controller accepts. Two adversarial reviewers read this file and
independently reported the mismatch as an unfixed bug, which is what an
untested inference in a fixtures README buys.
