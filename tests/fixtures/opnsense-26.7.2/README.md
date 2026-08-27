# OPNsense 26.7.2 API fixtures

Recorded from a live firewall so tools are coded against real payload shapes rather than guessed
field names. Field names, nesting, enum option sets and value formats are preserved exactly. Only
site-identifying values are replaced.

## Sanitisation

Anything that identifies the site is rewritten to a fictional equivalent, using an Infocom naming
theme so sanitised values are recognisable as such at a glance. Apply the same mapping to any new
fixture before committing.

| Kind | Real | Fixture |
|---|---|---|
| Public IPv4 | site WAN address | `203.0.113.0/24` (RFC 5737) |
| Private IPv4 | site RFC 1918 space | `172.20.0.0/16` |
| VPN transit IPv4 | site tunnel space | `172.20.99.0/24` |
| IPv6 GUA | delegated prefix | `2001:db8::/32` (RFC 3849) |
| IPv6 ULA | site ULA | `fd0b:b022:1e5::/48` |
| Domain | site domain | `frobozz.example` (RFC 2606 TLD) |
| Hosts | site hostnames | `brogmoid`, `flathead`, `grue` |
| Geographic alias | site region alias | `FrobozzRegion` |
| Monitoring alias | site tool alias | `GRUE` |
| Switch mgmt alias | site switch alias | `flatheadmgmt` |
| VPN gateway label | site gateway label | `wgtunnel - 172.20.99.1` |

Left as-is, because they are OPNsense or FreeBSD vocabulary rather than site identifiers:
interface device names (`ax0`, `igb3`, `optN`, `wg0`, `bridge0`), generated alias names
(`__optN_network`), zone names (`innerNets`, `cams`, `workshopNets`), and VLAN tag numbers.

## Files

| File | Source | Used by |
|---|---|---|
| `filter_getrule_log_quick_invert.json` | `GET firewall/filter/getRule/$uuid` on a rule with `log`, `quick` and an inverted source | `tests/test_set_firewall_rule_preserves_fields.py` |

The rule fixture is the one case where the values matter to the test: it proves a partial edit
preserves fields the caller did not restate, so the test asserts on the sanitised values.
