# OPNsense 26.7.8 API fixtures

Captured live off OPNsense 26.7.8_2 on 2026-11-12, sanitised per the table in
`../opnsense-26.7.2/README.md`.

| File | Endpoint | Root key | Used by |
|---|---|---|---|
| `filter_getrule.json` | `GET firewall/filter/getRule/<uuid>` | `rule` | `tests/test_mvc_merge_lists.py` |

`filter_getrule.json` is trimmed, not whole. Every key and value type is
kept, but each enum keeps only its selected options plus one unselected
option, and unselected option keys that named site aliases, gateways or
schedules are renamed `<field>_option`. `audit` is change metadata with
faked values. The firewall has one category defined, so `categories` is an
option map here; a firewall with none sends `[]` (Forgejo #164).
