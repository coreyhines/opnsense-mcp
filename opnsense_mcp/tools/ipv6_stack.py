"""NPTv6 rules, virtual IPs and loopback devices.

The objects a ULA conversion needs on the firewall: a stable fd00::/8 address on
each LAN interface (VIP), a 1:1 prefix translation to the delegated GUA on WAN
(NPT), and optionally a loopback to hold the delegated prefix once the LAN stops
carrying it.

Field names are taken from the firmware's own model rather than documentation.
`Filter.xml` defines `<npt>` with `source_net` (internal), `destination_net`
(external) and `trackif`; `Interfaces/Vip.xml` defines `mode`, `subnet` and
`subnet_bits`.

Writes stage by default. Nothing here reloads the packet filter on its own,
because a half-built v6 translation applied mid-change is worse than one that is
not live yet.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

NPT = {
    "search": "/api/firewall/npt/search_rule",
    "get": "/api/firewall/npt/get_rule",
    "add": "/api/firewall/npt/add_rule",
    "set": "/api/firewall/npt/set_rule",
    "delete": "/api/firewall/npt/del_rule",
    "toggle": "/api/firewall/npt/toggle_rule",
}
VIP = {
    "search": "/api/interfaces/vip_settings/search_item",
    "get": "/api/interfaces/vip_settings/get_item",
    "add": "/api/interfaces/vip_settings/add_item",
    "delete": "/api/interfaces/vip_settings/del_item",
}
LOOPBACK = {
    "search": "/api/interfaces/loopback_settings/search_item",
    "add": "/api/interfaces/loopback_settings/add_item",
    "delete": "/api/interfaces/loopback_settings/del_item",
}

VIP_MODES = ("ipalias", "carp", "proxyarp", "other")

# Anything shorter than a /64 cannot express a per-VLAN mapping: SLAAC is one
# /64 per L2 domain, and VLAN ids commonly place prefixes outside any single
# shorter block.
MIN_PREFIX_LEN = 64

# A rule whose external side is only `trackif` loads without error and shows up
# in search_rule, but pf holds no mapping for it, so the ULA source reaches WAN
# untranslated. Callers key off this rather than the message wording.
REASON_TRACKIF_DOES_NOT_TRANSLATE = "trackif_does_not_translate"


class _V6ToolBase:
    """Shared client handling and lookups."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _rows(self, endpoint: str) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", endpoint, json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []


class _TruncatedListingError(Exception):
    """A search returned fewer rows than it claims exist."""


def _refuse_if_truncated(rows: Any, what: str) -> None:
    """Raise when a search page does not cover the whole result set.

    A guard that reads a truncated listing as the whole truth is worse than one
    that refuses: it would silently miss the row that matters — a device past
    the cap read as "not found", or an assignment holder never seen, orphaning
    the interface the guard exists to protect.
    """
    if not isinstance(rows, dict):
        return
    total = rows.get("total")
    returned = len(rows.get("rows", []))
    if isinstance(total, int) and total > returned:
        raise _TruncatedListingError(
            f"the {what} listing is truncated ({returned} of {total}); refusing "
            f"rather than acting on a partial view"
        )


def _parse_v6_network(value: str, label: str) -> tuple[Any, str | None]:
    """Return the parsed network, or an error message explaining the refusal."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        return None, f"{label} {value!r} is not a valid network: {exc}"
    if network.version != 6:
        return None, f"{label} must be an IPv6 prefix; {value!r} is IPv4"
    return network, None


def _parse_vip_address(subnet: str, subnet_bits: Any) -> tuple[Any, int, str | None]:
    """Parse a VIP host address and bound its prefix length by address family.

    ``subnet`` is a bare address (no prefix length). Returns
    ``(address, bits, None)`` on success, or ``(None, 0, error)`` on refusal.
    """
    try:
        address = ipaddress.ip_address(subnet)
    except ValueError:
        return None, 0, f"subnet {subnet!r} is not a valid address"

    max_bits = 32 if address.version == 4 else 128
    family = "IPv4" if address.version == 4 else "IPv6"
    try:
        bits = int(subnet_bits)
    except (TypeError, ValueError):
        return (
            None,
            0,
            f"subnet_bits {subnet_bits!r} is not an integer prefix length",
        )
    if bits < 0 or bits > max_bits:
        return (
            None,
            0,
            (
                f"subnet_bits {bits} is out of range for {family} address "
                f"{subnet!r} (valid 0–{max_bits})"
            ),
        )
    return address, bits, None


class ListNptRulesTool(_V6ToolBase):
    """List NPTv6 rules."""

    name = "list_npt_rules"
    description = "List NPTv6 prefix translation rules"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each rule's interface, prefixes and track interface."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(NPT["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list NPT rules")
            return {"status": "error", "error": str(exc)}

        rules = []
        for row in rows:
            destination_net = row.get("destination_net", "")
            rule = {
                "uuid": row.get("uuid", ""),
                "interface": row.get("interface", ""),
                "source_net": row.get("source_net", ""),
                "destination_net": destination_net,
                "trackif": row.get("trackif", ""),
                "enabled": row.get("enabled", ""),
                "description": row.get("description", ""),
                # An enabled rule is not necessarily a translating one.
                "translating": bool(destination_net),
            }
            if not destination_net:
                rule["reason"] = REASON_TRACKIF_DOES_NOT_TRANSLATE
            rules.append(rule)

        not_translating = [r["uuid"] for r in rules if not r["translating"]]
        out: dict[str, Any] = {
            "status": "success",
            "count": len(rules),
            "rules": rules,
        }
        if not_translating:
            out["warning"] = (
                f"{len(not_translating)} rule(s) carry no destination_net. They "
                f"load and read back fine but pf holds no mapping for them, so "
                f"traffic egresses WAN with its internal source. Give each one "
                f"the delegated /64 as destination_net."
            )
        return out


class MkNptRuleTool(_V6ToolBase):
    """Create an NPTv6 rule."""

    name = "mk_npt_rule"
    description = (
        "Create an NPTv6 rule translating an internal IPv6 prefix to an external one"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {
                "type": "string",
                "description": "Interface the translation applies on, usually wan",
            },
            "source_net": {
                "type": "string",
                "description": "Internal prefix, for example fd00:...:2::/64",
            },
            "destination_net": {
                "type": "string",
                "description": "External prefix, the delegated /64 to translate onto",
            },
            "trackif": {
                "type": "string",
                "description": (
                    "Recognized and refused: interface whose delegated prefix would "
                    "supply the external side. OPNsense stores it but generates no "
                    "translation from it. Pass destination_net instead"
                ),
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reload the filter afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["interface", "source_net"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the rule after checking it can express a working mapping."""
        params = params or {}
        if not self.client:
            return self._no_client()

        interface = (params.get("interface") or "").strip()
        source_net = (params.get("source_net") or "").strip()
        destination_net = (params.get("destination_net") or "").strip()
        trackif = (params.get("trackif") or "").strip()

        if not interface or not source_net:
            return {"status": "error", "error": "interface and source_net are required"}

        source, error = _parse_v6_network(source_net, "source_net")
        if error:
            return {"status": "error", "error": error}

        if not destination_net:
            return {
                "status": "error",
                "error": (
                    "destination_net is required. trackif on its own does not "
                    "translate: OPNsense accepts the field and search_rule reads "
                    "it back, but the generated ruleset carries no mapping, so "
                    "packets leave WAN with their ULA source and are dropped "
                    "upstream. Confirmed on 26.7.3 by capturing on WAN. Pass the "
                    f"delegated /64 for {trackif or 'the tracked interface'} as "
                    "destination_net."
                ),
                "reason": REASON_TRACKIF_DOES_NOT_TRANSLATE,
            }

        if source.prefixlen < MIN_PREFIX_LEN:
            return {
                "status": "error",
                "error": (
                    f"source_net is a /{source.prefixlen}; NPT rules here are one "
                    f"per /64. SLAAC serves one /64 per L2 domain, and a shorter "
                    f"prefix silently covers ranges that belong to other VLANs."
                ),
            }

        if destination_net:
            destination, error = _parse_v6_network(destination_net, "destination_net")
            if error:
                return {"status": "error", "error": error}
            if destination.prefixlen != source.prefixlen:
                return {
                    "status": "error",
                    "error": (
                        f"NPT is a 1:1 prefix swap, so both sides must be the same "
                        f"length; got /{source.prefixlen} and /{destination.prefixlen}."
                    ),
                }

        try:
            existing_rows = await self._rows(NPT["search"])

            for row in existing_rows:
                if (
                    row.get("interface") == interface
                    and row.get("source_net") == source_net
                ):
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A rule for this interface and source prefix exists.",
                    }

            if destination_net:
                clash = next(
                    (
                        row
                        for row in existing_rows
                        if row.get("destination_net") == destination_net
                        and row.get("source_net") != source_net
                    ),
                    None,
                )
                if clash:
                    return {
                        "status": "error",
                        "error": (
                            f"{clash.get('source_net')} already maps onto "
                            f"{destination_net}. Mapping several internal prefixes "
                            f"onto one external prefix works outbound only and "
                            f"breaks inbound; give each its own external /64."
                        ),
                    }

            payload = {
                "interface": interface,
                "source_net": source_net,
                "destination_net": destination_net,
                "trackif": trackif,
                "description": params.get("description", ""),
                "enabled": "1",
            }
            result = await self.client._make_request(
                "POST", NPT["add"], call_class="write", json={"rule": payload}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create NPT rule")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await run_apply(self.client, "/api/firewall/filter/apply")
                applied = True
            except ApplyError as exc:
                logger.warning("NPT rule created but filter reload failed: %s", exc)
                apply_error = str(exc)

        out = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                "Rule created and loaded into the packet filter."
                if applied
                else "Staged. Run the apply step to load it."
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class ToggleNptRuleTool(_V6ToolBase):
    """Enable or disable an NPTv6 rule."""

    name = "toggle_npt_rule"
    description = "Enable or disable an NPTv6 rule"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Rule uuid"},
            "enabled": {"type": "boolean", "description": "Target state"},
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Set the rule to an explicit state rather than flipping it."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if params.get("enabled") is None:
            return {"status": "error", "error": "enabled is required"}

        state = "1" if params["enabled"] else "0"
        try:
            await self.client._make_request(
                "POST", f"{NPT['toggle']}/{uuid}/{state}", call_class="write"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle NPT rule")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "enabled": bool(params["enabled"])}


class RmNptRuleTool(_V6ToolBase):
    """Delete an NPTv6 rule."""

    name = "rm_npt_rule"
    description = "Delete an NPTv6 rule; requires a confirm token from a prior call"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Rule uuid"},
            "confirm": {"type": "string", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once a matching confirm token is supplied."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "npt_rule", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("npt_rule", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{NPT['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete NPT rule")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}


class ListVipTool(_V6ToolBase):
    """List virtual IPs."""

    name = "list_vip"
    description = "List interface virtual IPs"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each VIP, without the CARP password the rows carry."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(VIP["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list VIPs")
            return {"status": "error", "error": str(exc)}

        vips = [
            {
                "uuid": row.get("uuid", ""),
                "interface": row.get("interface", ""),
                "mode": row.get("mode", ""),
                "subnet": row.get("subnet", ""),
                "subnet_bits": row.get("subnet_bits", ""),
                "description": row.get("descr", ""),
            }
            for row in rows
        ]
        return {"status": "success", "count": len(vips), "vips": vips}


class MkVipTool(_V6ToolBase):
    """Create a virtual IP."""

    name = "mk_vip"
    description = "Create an interface virtual IP, an IP alias by default"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "description": "Interface to add it to"},
            "subnet": {
                "type": "string",
                "description": "Address, without the prefix length",
            },
            "subnet_bits": {"type": "number", "description": "Prefix length, e.g. 64"},
            "mode": {
                "type": "string",
                "description": f"One of: {', '.join(VIP_MODES)} (default ipalias)",
                "optional": True,
            },
            "vhid": {
                "type": "number",
                "description": "CARP virtual host id; required only for mode=carp",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure interfaces afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["interface", "subnet", "subnet_bits"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the VIP, defaulting to an IP alias."""
        params = params or {}
        if not self.client:
            return self._no_client()

        interface = (params.get("interface") or "").strip()
        subnet = (params.get("subnet") or "").strip()
        bits = params.get("subnet_bits")
        mode = (params.get("mode") or "ipalias").strip()

        if not interface or not subnet or bits is None:
            return {
                "status": "error",
                "error": "interface, subnet and subnet_bits are required",
            }

        _address, bits_int, parse_error = _parse_vip_address(subnet, bits)
        if parse_error:
            return {"status": "error", "error": parse_error}

        if mode not in VIP_MODES:
            return {
                "status": "error",
                "error": f"unknown mode {mode!r}; expected one of: {', '.join(VIP_MODES)}",
            }
        if mode == "carp" and not params.get("vhid"):
            return {
                "status": "error",
                "error": (
                    "mode=carp requires a vhid. Two nodes sharing a segment with "
                    "the same vhid fight over the address."
                ),
            }

        try:
            for row in await self._rows(VIP["search"]):
                if row.get("interface") == interface and row.get("subnet") == subnet:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A VIP with this address exists on that interface.",
                    }

            payload = {
                "interface": interface,
                "mode": mode,
                "subnet": subnet,
                "subnet_bits": str(bits_int),
                "descr": params.get("description", ""),
                "vhid": str(params["vhid"]) if params.get("vhid") else "",
            }
            result = await self.client._make_request(
                "POST", VIP["add"], call_class="write", json={"vip": payload}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create VIP")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await run_apply(self.client, "/api/interfaces/vip_settings/reconfigure")
                applied = True
            except ApplyError as exc:
                logger.warning("VIP created but interfaces not reconfigured: %s", exc)
                apply_error = str(exc)

        out = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                "VIP created and interfaces reconfigured."
                if applied
                else "Staged. Reconfigure interfaces to bring it up."
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class RmVipTool(_V6ToolBase):
    """Delete a virtual IP."""

    name = "rm_vip"
    description = "Delete an interface virtual IP; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "VIP uuid"},
            "confirm": {"type": "string", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once a matching confirm token is supplied."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "vip", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("vip", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{VIP['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete VIP")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}


class ListLoopbackTool(_V6ToolBase):
    """List loopback devices."""

    name = "list_loopback"
    description = "List loopback interface devices"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the configured loopback devices."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(LOOPBACK["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list loopbacks")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "count": len(rows), "loopbacks": rows}


class MkLoopbackTool(_V6ToolBase):
    """Create a loopback device, or explain how to make a PD holder manually.

    OPNsense 26.7 exposes only the loopback device list through
    ``loopback_settings/get``. The other ``/api/interfaces/`` models were also
    probed: ``settings/get`` has global IPv6/offload toggles,
    ``overview/interfacesInfo`` is read-only status, and the VIP/VLAN models do
    not carry interface addressing. Consequently, Track Interface IPv6 mode
    and its prefix-id are UI or config-edit only.

    An unsupported Track Interface request returns ``status: success`` because
    the tool ran and correctly answered the request. ``unsupported: true`` and
    ``created: false`` distinguish that finding from a completed write; actual
    failures still return ``status: error``.
    """

    name = "mk_loopback"
    description = (
        "Create a loopback interface device. Track Interface IPv6 addressing is "
        "refused with manual UI/config-edit steps: every /api/interfaces/ model "
        "was probed, but loopback is device-only, settings is global toggles, "
        "overview is read-only, and VIP/VLAN models have no interface addressing. "
        "Requests using the config.xml shape ipaddrv6=track6, track6-interface, "
        "and track6-prefix-id are recognized but never partially staged"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "description": {"type": "string", "description": "Device description"},
            "planned_address": {
                "type": "string",
                "description": (
                    "An address you intend this loopback to carry. Not written "
                    "here — OPNsense has no per-interface addressing API — but "
                    "echoed back as the exact step to perform. Use "
                    "set_interface_address to actually write one"
                ),
                "optional": True,
            },
            "planned_subnet_bits": {
                "type": "number",
                "description": "Prefix length for planned_address, normally 32 or 128",
                "optional": True,
            },
            "ipaddrv6": {
                "type": "string",
                "description": (
                    "Recognized and refused: IPv6 addressing mode such as "
                    "track6. Not written — the API cannot set it"
                ),
                "optional": True,
            },
            "track6-interface": {
                "type": "string",
                "description": (
                    "Recognized and refused: interface whose delegated prefix "
                    "to track. Not written — the API cannot set it"
                ),
                "optional": True,
            },
            "track6-prefix-id": {
                "type": "number",
                "description": (
                    "Recognized and refused: IPv6 prefix-id for Track Interface. "
                    "Not written — the API cannot set it"
                ),
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "description": "Reconfigure interfaces afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["description"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the device, and optionally instantiate it.

        Assigning it is possible over the API given the
        page-interfaces-assignnetworkports privilege. Addressing it is not, in
        the 26.7 series: the NetworkInterface model defines only descr,
        identifier, icon, optgroup, if and lock, and the controller exposes
        whatever the model defines, so an address is accepted and dropped. Those
        fields are present in master, so this is a version gap rather than a
        permanent absence.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        description = (params.get("description") or "").strip()
        if not description:
            return {"status": "error", "error": "description is required"}

        ipv6_mode = (params.get("ipaddrv6") or "").strip()
        track_interface = (params.get("track6-interface") or "").strip()
        prefix_id = params.get("track6-prefix-id")
        if ipv6_mode == "track6" or track_interface or prefix_id is not None:
            return {
                "status": "success",
                "unsupported": True,
                "created": False,
                "reason": {
                    "code": "per_interface_ipv6_addressing_api_unavailable",
                    "capability": "Track Interface IPv6 addressing mode",
                    "availability": "UI or config.xml edit only",
                    "detail": (
                        "OPNsense exposes no API for per-interface IPv6 "
                        "addressing mode, including track6-interface and "
                        "track6-prefix-id."
                    ),
                },
                "requested": {
                    "ipaddrv6": ipv6_mode,
                    "track6-interface": track_interface,
                    "track6-prefix-id": prefix_id,
                },
                "manual_steps": [
                    "Create and assign the dedicated interface.",
                    "Set IPv6 Configuration Type to Track Interface.",
                    f"Set the tracked interface to {track_interface or 'WAN'}.",
                    f"Set the IPv6 prefix-id to {prefix_id}.",
                    "Turn router advertisements off on the interface.",
                    "Do not add firewall policy for the interface.",
                ],
            }

        address = (params.get("planned_address") or "").strip()
        subnet_bits = params.get("planned_subnet_bits")
        if address and subnet_bits is None:
            return {
                "status": "error",
                "error": (
                    "planned_subnet_bits is required with planned_address. A "
                    "loopback given the wrong prefix advertises a subnet it does "
                    "not own; for a loopback this is normally 32 or 128."
                ),
            }

        try:
            result = await self.client._make_request(
                "POST",
                LOOPBACK["add"],
                call_class="write",
                json={"loopback": {"description": description}},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create loopback")
            return {"status": "error", "error": str(exc)}

        # Applied as a separate phase, and checked. The note previously claimed
        # the device was "instantiated" from the caller's argument alone,
        # without looking at what reconfigure answered.
        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await run_apply(
                    self.client, "/api/interfaces/loopback_settings/reconfigure"
                )
                applied = True
            except ApplyError as exc:
                logger.warning("Loopback created but not instantiated: %s", exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                f"Device created but not instantiated: {apply_error}. It will "
                f"not appear as assignable until the loopback configuration is "
                f"reconfigured."
                if apply_error
                else "Device created and instantiated. Assigning it is possible with "
                "the page-interfaces-assignnetworkports privilege; addressing it "
                "is not, since the assignment model has no address field and "
                "accepts one silently. Use a virtual IP on an assigned interface "
                "instead."
                if applied
                else "Device created but not instantiated: it does not exist on "
                "the system and will not appear as assignable until the loopback "
                "configuration is reconfigured. Re-run with apply=true, or expect "
                'an assignment to fail with "Option [] not in list".'
            ),
        }
        if address:
            # Never posted. set_item accepts ipaddr and answers "saved" while
            # changing nothing, so writing it would report success and do
            # nothing. Handing the values back is the honest alternative.
            out["manual_step"] = {
                "why": (
                    "Per-interface addressing has no API in the 26.7 series. "
                    "NetworkInterface.xml there defines six fields (descr, "
                    "identifier, icon, optgroup, if, lock) and the assignment "
                    "controller exposes whatever the model defines, so an "
                    "address posted to it is accepted and discarded. The fields "
                    "exist in master, so a later release should make this "
                    "possible; re-check the model before assuming it still is not."
                ),
                "where": "Interfaces -> Assignments, then the new interface",
                "address": address,
                "subnet_bits": subnet_bits,
                "instruction": (
                    f"Assign this device, enable the interface, set the IPv4 or "
                    f"IPv6 configuration type to Static, and set the address to "
                    f"{address}/{subnet_bits}."
                ),
                "alternative": (
                    f"Or skip assignment entirely: add a virtual IP of mode "
                    f"ipalias with {address}/{subnet_bits} on an already-assigned "
                    f"interface such as lo0, which mk_vip does over the API."
                ),
            }
        return out


class RmLoopbackTool(_V6ToolBase):
    """Delete a loopback device."""

    name = "rm_loopback"
    description = "Delete a loopback interface device; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Loopback device uuid"},
            "device": {
                "type": "string",
                "description": (
                    "Device name, e.g. lo1. Given, the tool refuses to delete a "
                    "device an interface is still assigned to"
                ),
                "optional": True,
            },
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def _device_name(self, uuid: str) -> str:
        """Map a loopback uuid to its device name, e.g. lo1.

        Raises when the listing is truncated: past the row cap the device might
        not be in the page, and a false "not found" would refuse a legitimate
        delete — while on the assignment side a missed holder would orphan one.
        """
        rows = await self.client._make_request(
            "POST", LOOPBACK["search"], json={"current": 1, "rowCount": 5000}
        )
        _refuse_if_truncated(rows, "loopback devices")
        for row in rows.get("rows", []) if isinstance(rows, dict) else []:
            if row.get("uuid") == uuid:
                raw = row.get("deviceId")
                if raw is None:
                    raw = row.get("device")
                number = str(raw if raw is not None else "").strip()
                return f"lo{number}" if number.isdigit() else number
        return ""

    async def _assignments_using(self, device: str) -> list[str]:
        """Which assigned interfaces point at this device."""
        rows = await self.client._make_request(
            "POST",
            "/api/interfaces/assignment/search_item",
            json={"current": 1, "rowCount": 5000},
        )
        _refuse_if_truncated(rows, "interface assignments")
        return [
            r.get("uuid", "")
            for r in (rows.get("rows", []) if isinstance(rows, dict) else [])
            if r.get("if") == device
        ]

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Exists because mk_loopback did not have one, which left deleting a
        device as a hand-written request against a uuid read some time earlier.
        A device that is still assigned to an interface cannot be removed, and
        the API says so rather than cascading.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "loopback", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("loopback", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            # Always resolve from the uuid. A caller-supplied `device` is only a
            # cross-check: preferring it let a wrong value skip the guard, which
            # checked assignments against a device nobody was using — the
            # orphaned, lock-protected assignment this exists to prevent.
            try:
                device = await self._device_name(uuid)
            except _TruncatedListingError as exc:
                return {"status": "error", "error": str(exc)}
            if not device:
                return {
                    "status": "error",
                    "error": (
                        f"no loopback device with uuid {uuid}; it may already be "
                        f"gone, or the uuid came from an older listing."
                    ),
                }
            claimed = (params.get("device") or "").strip()
            if claimed and claimed != device:
                return {
                    "status": "error",
                    "error": (
                        f"uuid {uuid} is device {device}, not {claimed!r}. Remove "
                        f"the device argument or correct it; the assignment check "
                        f"runs against the resolved device either way."
                    ),
                }

            try:
                holders = await self._assignments_using(device)
            except _TruncatedListingError as exc:
                return {"status": "error", "error": str(exc)}
            if holders:
                return {
                    "status": "error",
                    "error": (
                        f"{device} is still assigned to {', '.join(holders)}. "
                        f"Deleting it would leave that assignment pointing at "
                        f"nothing. Unassign first: the interface is locked, so "
                        f"clear its lock before removing it."
                    ),
                }

            result = await self.client._make_request(
                "POST", f"{LOOPBACK['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete loopback device")
            return {"status": "error", "error": str(exc)}

        if isinstance(result, dict) and result.get("result") == "not found":
            return {
                "status": "error",
                "error": (
                    f"no loopback device with uuid {uuid}. It may already be gone, "
                    f"or the uuid came from an older listing."
                ),
            }

        # Apply as a separate, checked phase — not inside the write's try, where
        # a reconfigure failure was reported as the delete having failed.
        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await run_apply(
                    self.client, "/api/interfaces/loopback_settings/reconfigure"
                )
                applied = True
            except ApplyError as exc:
                logger.warning("Loopback deleted but not applied: %s", exc)
                apply_error = str(exc)
        out = {"status": "success", "uuid": uuid, "deleted": True, "applied": applied}
        if apply_error:
            out["apply_error"] = apply_error
        return out
