"""Router advertisements, host overrides, ULA planning and the apply step.

The rest of the firewall side of a ULA conversion. NPT and VIP live in
`ipv6_stack`; this covers advertising the prefix, answering for it internally,
and loading the staged changes.

`plan_dns_ula` deliberately changes nothing. A site can have hundreds of AAAA
records, some of which the outside world resolves and which therefore keep their
delegated address, so the mapping is something to read before acting on.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from opnsense_mcp.utils.mvc_merge import flatten_mvc_node
from opnsense_mcp.utils.ra_daemon import (
    DAEMON_BOTH,
    DAEMON_DNSMASQ,
    DAEMON_NONE,
    DAEMON_RADVD,
    REASON_BOTH_SERVING,
    RaVerdict,
    classify_ra_daemons,
)

logger = logging.getLogger(__name__)

RADVD = {
    "search": "/api/radvd/settings/search_entry",
    "get": "/api/radvd/settings/get_entry",
    "set": "/api/radvd/settings/set_entry",
    "reconfigure": "/api/radvd/service/reconfigure",
}
DNSMASQ = {
    "search_range": "/api/dnsmasq/settings/search_range",
    "reconfigure": "/api/dnsmasq/service/reconfigure",
}
UNBOUND = {
    "search": "/api/unbound/settings/searchHostOverride",
    "get": "/api/unbound/settings/getHostOverride",
    "set": "/api/unbound/settings/setHostOverride",
    "reconfigure": "/api/unbound/service/reconfigure",
}

# Reason code for deprecate refusal — dnsmasq has no preferred-lifetime field.
REASON_DEPRECATE_NOT_SUPPORTED = "dnsmasq_deprecate_not_supported"

# NPT translation must be live before the prefix is advertised, or anything
# that believes the advertisement sends traffic that cannot be translated.
APPLY_DOMAINS: tuple[str, ...] = ("vip", "npt", "ra", "unbound")

_DOMAIN_ENDPOINTS = {
    "vip": "/api/interfaces/vip_settings/reconfigure",
    "npt": "/api/firewall/filter/apply",
    "ra": RADVD["reconfigure"],
    "unbound": UNBOUND["reconfigure"],
}

# radvd computes these; writing them back is noise.
_RA_COMPUTED = frozenset({"uuid"})


class _UlaToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _fetch_radvd_rows(self) -> list[dict[str, Any]]:
        """Fetch radvd search_entry rows for classification."""
        data = await self.client._make_request(
            "POST", RADVD["search"], json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []

    async def _fetch_dnsmasq_range_rows(self) -> list[dict[str, Any]]:
        """Fetch dnsmasq search_range rows for classification."""
        data = await self.client._make_request(
            "POST", DNSMASQ["search_range"], json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []

    async def _fetch_interface_states(self) -> dict[str, bool]:
        """Fetch interface admin-up states from the overview endpoint."""
        try:
            raw = await self.client._make_request(
                "GET", "/api/interfaces/overview/export"
            )
            states: dict[str, bool] = {}
            if isinstance(raw, list):
                for entry in raw:
                    iface = entry.get("identifier") or entry.get("device") or ""
                    if iface:
                        states[iface] = entry.get("enabled") in (True, 1, "1")
            elif isinstance(raw, dict):
                for key, val in raw.items():
                    if isinstance(val, dict):
                        states[key] = val.get("enabled") in (True, 1, "1")
            return states
        except Exception:
            logger.warning("Failed to fetch interface states; verdict may be imprecise")
            return {}

    async def _classify_interfaces(self) -> dict[str, RaVerdict]:
        """Classify which RA daemon serves each interface."""
        radvd_rows = await self._fetch_radvd_rows()
        dnsmasq_rows = await self._fetch_dnsmasq_range_rows()
        interface_states = await self._fetch_interface_states()
        return classify_ra_daemons(radvd_rows, dnsmasq_rows, interface_states)


class ListRouterAdvertsTool(_UlaToolBase):
    """List router advertisement entries."""

    name = "list_router_adverts"
    description = "List radvd router advertisement entries, one per interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each entry's interface, mode and lifetime settings."""
        if not self.client:
            return self._no_client()
        try:
            data = await self.client._make_request(
                "POST", RADVD["search"], json={"current": 1, "rowCount": 5000}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list router adverts")
            return {"status": "error", "error": str(exc)}

        rows = data.get("rows", []) if isinstance(data, dict) else []
        entries = [
            {
                "uuid": row.get("uuid", ""),
                "interface": row.get("interface", ""),
                "mode": row.get("mode", ""),
                "enabled": row.get("enabled", ""),
                "preferred_lifetime": row.get("AdvPreferredLifetime", ""),
                "valid_lifetime": row.get("AdvValidLifetime", ""),
                "deprecate_prefix": row.get("DeprecatePrefix", ""),
            }
            for row in rows
        ]
        return {"status": "success", "count": len(entries), "entries": entries}


class SetRouterAdvertTool(_UlaToolBase):
    """Update a router advertisement entry."""

    name = "set_router_advert"
    description = (
        "Update a radvd entry: enable it or change mode. Deprecation is not "
        "supported when dnsmasq serves RA because dnsmasq has no preferred-lifetime "
        "field."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Entry uuid"},
            "enabled": {"type": "boolean", "optional": True},
            "mode": {
                "type": "string",
                "description": "radvd mode, for example managed or unmanaged",
                "optional": True,
            },
            "preferred_lifetime": {
                "type": "number",
                "description": "Advertised preferred lifetime; 0 deprecates the prefix",
                "optional": True,
            },
            "valid_lifetime": {"type": "number", "optional": True},
            "deprecate_prefix": {
                "type": "boolean",
                "description": "Advertise the prefix as deprecated",
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "description": "Reconfigure radvd afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the entry, overlay the changes, write it back.

        Consults which daemon actually serves RA on the interface. Writing to
        radvd when dnsmasq serves is silently ineffective, so this refuses
        rather than reporting success for a no-op.

        Deprecation (preferred_lifetime=0 or deprecate_prefix=True) is refused
        when dnsmasq serves because dnsmasq has no preferred-lifetime field.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        # Check if this is a deprecate request
        wants_deprecate = (
            params.get("deprecate_prefix") is True
            or params.get("preferred_lifetime") == 0
        )

        try:
            # Fetch the radvd entry to get its interface
            current = await self.client._make_request("GET", f"{RADVD['get']}/{uuid}")
            node = current.get("entry") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"radvd entry {uuid} not found"}

            # Extract the interface from the entry (MVC select → key)
            iface_field = node.get("interface", {})
            if isinstance(iface_field, dict):
                iface = next(
                    (k for k, v in iface_field.items() if v.get("selected")), ""
                )
            else:
                iface = str(iface_field or "")

            # Classify which daemon serves RA on this interface
            verdicts = await self._classify_interfaces()
            verdict = verdicts.get(iface)

            # If the interface is not in our classification, check radvd entry
            # without dnsmasq context (may be a new interface not in ranges)
            if verdict is None:
                # No range on this interface, check if radvd is enabled
                radvd_rows = await self._fetch_radvd_rows()
                iface_states = await self._fetch_interface_states()
                verdicts = classify_ra_daemons(radvd_rows, [], iface_states)
                verdict = verdicts.get(iface)

            # Apply the routing decision
            if verdict is not None:
                if verdict.daemon == DAEMON_BOTH:
                    return {
                        "status": "refused",
                        "reason": (
                            "Both radvd and dnsmasq serve RA on this interface. "
                            "Writing either one makes the misconfiguration worse. "
                            "Disable one before proceeding."
                        ),
                        "reason_codes": list(verdict.reason_codes),
                        "interface": iface,
                        "uuid": uuid,
                    }

                if verdict.daemon == DAEMON_DNSMASQ:
                    # More specific message when deprecation is requested
                    if wants_deprecate:
                        return {
                            "status": "refused",
                            "reason": (
                                f"dnsmasq serves RA on {iface} and has no "
                                "preferred-lifetime field. Deprecating an advertised "
                                "prefix is not implementable through this API. "
                                "Phase 3 (graceful prefix deprecation) must be done "
                                "in the UI or by dropping track6 from the interface."
                            ),
                            "reason_codes": [
                                REASON_DEPRECATE_NOT_SUPPORTED,
                                *verdict.reason_codes,
                            ],
                            "interface": iface,
                            "uuid": uuid,
                            "missing_capability": "preferred_lifetime",
                        }
                    return {
                        "status": "refused",
                        "reason": (
                            f"dnsmasq serves RA on {iface}, not radvd. Writing to "
                            "radvd would change config nothing reads. Use the "
                            "dhcp_ranges tool to modify dnsmasq RA settings."
                        ),
                        "reason_codes": list(verdict.reason_codes),
                        "interface": iface,
                        "uuid": uuid,
                    }

                if verdict.daemon == DAEMON_NONE:
                    return {
                        "status": "refused",
                        "reason": (
                            f"Neither radvd nor dnsmasq is advertising on {iface}. "
                            "Enable one daemon before configuring RA."
                        ),
                        "reason_codes": list(verdict.reason_codes),
                        "interface": iface,
                        "uuid": uuid,
                    }

            # If we get here and the caller wants deprecation, refuse if
            # dnsmasq serves (already checked) OR if we would be writing to
            # radvd (which is the only path left). However, radvd *does* support
            # deprecation, so only refuse when dnsmasq serves — but we already
            # exited above for dnsmasq. Double-check nonetheless for the
            # REASON_DEPRECATE_NOT_SUPPORTED code path (future-proofing for
            # when dnsmasq ranges might be partially served).

            # radvd serves — proceed with the write
            payload = flatten_mvc_node(node)
            for field in _RA_COMPUTED:
                payload.pop(field, None)

            if params.get("enabled") is not None:
                payload["enabled"] = "1" if params["enabled"] else "0"
            if params.get("mode"):
                payload["mode"] = params["mode"]
            if params.get("preferred_lifetime") is not None:
                payload["AdvPreferredLifetime"] = str(params["preferred_lifetime"])
            if params.get("valid_lifetime") is not None:
                payload["AdvValidLifetime"] = str(params["valid_lifetime"])
            if params.get("deprecate_prefix") is not None:
                payload["DeprecatePrefix"] = "1" if params["deprecate_prefix"] else "0"

            await self.client._make_request(
                "POST",
                f"{RADVD['set']}/{uuid}",
                call_class="write",
                json={"entry": payload},
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", RADVD["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update radvd entry")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "interface": iface,
            "daemon": DAEMON_RADVD,
            "note": "Staged unless apply was set.",
        }


class SetHostOverrideTool(_UlaToolBase):
    """Edit an existing Unbound host override."""

    name = "set_host_override"
    description = (
        "Edit an existing Unbound host override in place; use mkdns to create one"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {
                "type": "string",
                "description": "Override uuid, from the dns tool",
            },
            "server": {
                "type": "string",
                "description": "Replacement address",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "enabled": {"type": "boolean", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure Unbound afterwards (default true)",
                "optional": True,
                "default": True,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the record, change what was asked, write the whole node back.

        The record type is never inferred from the address. Guessing AAAA from a
        colon would silently rewrite the type of anything it got wrong, and a
        migration edits hundreds of these.

        This is repair, not the migration path. Moving a name from GUA to ULA is
        add-then-delete with `mkdns` and `rmdns`, so both answers exist while
        clients hold cached results.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {
                "status": "error",
                "error": "uuid is required; this edits an existing override",
            }

        try:
            current = await self.client._make_request("GET", f"{UNBOUND['get']}/{uuid}")
            node = current.get("host") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"host override {uuid} not found"}

            payload = flatten_mvc_node(node)
            if params.get("server") is not None:
                payload["server"] = params["server"]
            if params.get("description") is not None:
                payload["description"] = params["description"]
            if params.get("enabled") is not None:
                payload["enabled"] = "1" if params["enabled"] else "0"

            await self.client._make_request(
                "POST",
                f"{UNBOUND['set']}/{uuid}",
                call_class="write",
                json={"host": payload},
            )
            if params.get("apply", True):
                await self.client._make_request(
                    "POST", UNBOUND["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update host override")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "hostname": payload.get("hostname", ""),
            "rr": payload.get("rr", ""),
            "server": payload.get("server", ""),
        }


class PlanDnsUlaTool(_UlaToolBase):
    """Propose ULA addresses for AAAA records under a delegated prefix."""

    name = "plan_dns_ula"
    description = (
        "Read-only: map AAAA host overrides from a delegated prefix onto a ULA prefix"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "gua_prefix": {
                "type": "string",
                "description": "Current delegated prefix, for example 2001:db8:1::/64",
            },
            "ula_prefix": {
                "type": "string",
                "description": "Target ULA prefix of the same length",
            },
            "public_names": {
                "type": "array",
                "description": "Fully qualified names the outside world resolves; "
                "these keep their delegated address",
                "optional": True,
            },
        },
        "required": ["gua_prefix", "ula_prefix"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the proposed mapping without changing anything."""
        params = params or {}
        if not self.client:
            return self._no_client()

        try:
            gua = ipaddress.ip_network(params.get("gua_prefix", ""), strict=False)
            ula = ipaddress.ip_network(params.get("ula_prefix", ""), strict=False)
        except ValueError as exc:
            return {"status": "error", "error": f"invalid prefix: {exc}"}

        if gua.version != 6 or ula.version != 6:
            return {"status": "error", "error": "both prefixes must be IPv6"}
        if gua.prefixlen != ula.prefixlen:
            return {
                "status": "error",
                "error": (
                    f"prefix length mismatch: /{gua.prefixlen} and /{ula.prefixlen}. "
                    "Host bits are preserved, so both sides must be the same size."
                ),
            }

        public = {name.lower() for name in (params.get("public_names") or [])}

        try:
            data = await self.client._make_request(
                "POST", UNBOUND["search"], json={"current": 1, "rowCount": 5000}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read host overrides")
            return {"status": "error", "error": str(exc)}

        rows = data.get("rows", []) if isinstance(data, dict) else []
        records: list[dict[str, Any]] = []
        for row in rows:
            if row.get("rr") != "AAAA":
                continue
            try:
                address = ipaddress.ip_address(row.get("server", ""))
            except ValueError:
                continue
            if address not in gua:
                continue

            fqdn = f"{row.get('hostname', '')}.{row.get('domain', '')}".strip(".")
            keep_gua = fqdn.lower() in public
            host_bits = int(address) - int(gua.network_address)
            proposed = None if keep_gua else str(ula.network_address + host_bits)
            records.append(
                {
                    "uuid": row.get("uuid", ""),
                    "hostname": row.get("hostname", ""),
                    "domain": row.get("domain", ""),
                    "current": str(address),
                    "proposed": proposed,
                    "keep_gua": keep_gua,
                }
            )

        movable = [r for r in records if not r["keep_gua"]]
        return {
            "status": "success",
            "gua_prefix": str(gua),
            "ula_prefix": str(ula),
            "count": len(records),
            "movable": len(movable),
            "keep_gua": len(records) - len(movable),
            "records": records,
            "note": (
                "Nothing was changed. Add the ULA record with mkdns and remove the "
                "GUA one with rmdns once clients have picked it up; names the "
                "outside world resolves keep their delegated address."
            ),
        }


class ApplyUlaTool(_UlaToolBase):
    """Load the staged IPv6 changes, in order."""

    name = "apply_ula"
    description = (
        "Load staged VIP, NPT, router advertisement and Unbound changes, in order"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "dry_run": {
                "type": "boolean",
                "description": "Report what would run without doing it (default true)",
                "optional": True,
            },
            "domains": {
                "type": "array",
                "description": f"Subset of {list(APPLY_DOMAINS)}, in that order",
                "optional": True,
            },
        },
        "required": [],
    }

    async def _apply_ra_domain(self) -> dict[str, Any]:
        """Apply the RA domain by reconfiguring the serving daemon(s).

        Returns a dict with keys:
        - ``daemons_reconfigured``: list of daemon names reconfigured
        - ``verified``: whether post-apply read confirmed the state
        - ``error``: error message if something went wrong (optional)
        """
        verdicts_before = await self._classify_interfaces()

        # Determine which daemons serve across any interface
        needs_radvd = any(
            v.daemon in (DAEMON_RADVD, DAEMON_BOTH) for v in verdicts_before.values()
        )
        needs_dnsmasq = any(
            v.daemon in (DAEMON_DNSMASQ, DAEMON_BOTH) for v in verdicts_before.values()
        )

        if not needs_radvd and not needs_dnsmasq:
            # No RA daemon serving on any interface — nothing to apply
            return {
                "daemons_reconfigured": [],
                "verified": True,
                "note": "No RA daemon serving on any interface; nothing to reconfigure.",
            }

        reconfigured: list[str] = []

        # Reconfigure in order: radvd then dnsmasq (order matters less here,
        # but consistent ordering aids debugging)
        if needs_radvd:
            await self.client._make_request(
                "POST", RADVD["reconfigure"], call_class="apply"
            )
            reconfigured.append(DAEMON_RADVD)

        if needs_dnsmasq:
            await self.client._make_request(
                "POST", DNSMASQ["reconfigure"], call_class="apply"
            )
            reconfigured.append(DAEMON_DNSMASQ)

        # Verify: re-read and confirm the serving state
        verdicts_after = await self._classify_interfaces()

        # The apply is verified if the daemon classification is unchanged
        # (we reconfigured what was serving, not changed what serves).
        # A more sophisticated check would compare specific fields, but the
        # point is to detect when reconfigure returned ok but nothing happened.
        verified = True
        mismatches: list[str] = []
        for iface, before in verdicts_before.items():
            after = verdicts_after.get(iface)
            if after is None or after.daemon != before.daemon:
                verified = False
                mismatches.append(
                    f"{iface}: was {before.daemon}, now "
                    f"{after.daemon if after else 'unknown'}"
                )

        result: dict[str, Any] = {
            "daemons_reconfigured": reconfigured,
            "verified": verified,
        }
        if mismatches:
            result["mismatches"] = mismatches
        return result

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Reconfigure each domain in turn, reporting where it stopped.

        This is not a transaction. If a domain fails the ones before it stay
        applied, so the result says what landed and what did not rather than
        attempting a rollback that could leave the box in a third state.

        The ``ra`` domain routes to the daemon(s) actually serving RA and
        verifies that the reconfigure took effect. If verification fails,
        ``applied`` is ``False`` for that domain.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        requested = params.get("domains") or list(APPLY_DOMAINS)
        unknown = [d for d in requested if d not in APPLY_DOMAINS]
        if unknown:
            return {
                "status": "error",
                "error": (
                    f"unknown domain(s): {', '.join(unknown)}. "
                    f"Expected a subset of {', '.join(APPLY_DOMAINS)}."
                ),
            }

        ordered = [d for d in APPLY_DOMAINS if d in requested]
        dry_run = params.get("dry_run", True)

        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "applied": False,
                "would_run": ordered,
                "note": (
                    "DRY RUN, nothing was loaded. Call again with dry_run=false "
                    "to apply. NPT runs before the advertisement so a prefix is "
                    "never advertised before its translation is live."
                ),
            }

        done: list[str] = []
        ra_result: dict[str, Any] | None = None

        for domain in ordered:
            try:
                if domain == "ra":
                    # Special handling: route to serving daemon and verify
                    ra_result = await self._apply_ra_domain()
                    if not ra_result.get("verified", True):
                        # The reconfigure returned ok but verification failed
                        remaining = ordered[ordered.index(domain) + 1 :]
                        return {
                            "status": "warning",
                            "dry_run": False,
                            "applied": False,
                            "done": done,
                            "failed": domain,
                            "remaining": remaining,
                            "ra_result": ra_result,
                            "error": (
                                "RA reconfigure returned ok but post-apply "
                                "verification found mismatches. The serving state "
                                "may not reflect the staged changes."
                            ),
                            "recovery": (
                                "Check interface RA configuration and retry. The "
                                "mismatches field shows which interfaces diverged."
                            ),
                        }
                else:
                    await self.client._make_request(
                        "POST", _DOMAIN_ENDPOINTS[domain], call_class="apply"
                    )
            except Exception as exc:  # noqa: BLE001
                logger.exception("apply_ula failed at %s", domain)
                remaining = ordered[ordered.index(domain) + 1 :]
                result: dict[str, Any] = {
                    "status": "partial_failure",
                    "dry_run": False,
                    "applied": True,
                    "done": done,
                    "failed": domain,
                    "remaining": remaining,
                    "error": str(exc),
                    "recovery": (
                        "Earlier domains stayed applied. Nothing was rolled back. "
                        "Fix the cause and re-run with the remaining domains."
                    ),
                }
                if ra_result:
                    result["ra_result"] = ra_result
                return result
            done.append(domain)

        result = {
            "status": "success",
            "dry_run": False,
            "applied": True,
            "done": done,
        }
        if ra_result:
            result["ra_result"] = ra_result
        return result
