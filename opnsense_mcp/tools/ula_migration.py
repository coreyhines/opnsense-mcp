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

logger = logging.getLogger(__name__)

RADVD = {
    "search": "/api/radvd/settings/search_entry",
    "get": "/api/radvd/settings/get_entry",
    "set": "/api/radvd/settings/set_entry",
    "reconfigure": "/api/radvd/service/reconfigure",
}
UNBOUND = {
    "search": "/api/unbound/settings/searchHostOverride",
    "get": "/api/unbound/settings/getHostOverride",
    "set": "/api/unbound/settings/setHostOverride",
    "reconfigure": "/api/unbound/service/reconfigure",
}

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
        "Update a radvd entry: enable it, change mode, or deprecate the old prefix"
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

        Setting the preferred lifetime to 0 is how clients are told to stop
        sourcing new connections from a prefix while existing ones drain.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        try:
            current = await self.client._make_request("GET", f"{RADVD['get']}/{uuid}")
            node = current.get("entry") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"radvd entry {uuid} not found"}

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
            "interface": payload.get("interface", ""),
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

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Reconfigure each domain in turn, reporting where it stopped.

        This is not a transaction. If a domain fails the ones before it stay
        applied, so the result says what landed and what did not rather than
        attempting a rollback that could leave the box in a third state.
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
        for domain in ordered:
            try:
                await self.client._make_request(
                    "POST", _DOMAIN_ENDPOINTS[domain], call_class="apply"
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("apply_ula failed at %s", domain)
                remaining = ordered[ordered.index(domain) + 1 :]
                return {
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
            done.append(domain)

        return {
            "status": "success",
            "dry_run": False,
            "applied": True,
            "done": done,
        }
