"""DHCP ranges and DHCP options, including the router option.

Option 3 is the capability this adds. A subnet that sits behind a router rather
than on the firewall gets its default gateway from DHCP, and nothing here could
set one, so moving a subnet behind a router was a UI-only operation.

Two shapes that are easy to get wrong, both read off the live API rather than
guessed:

- `constructor` on a range is the IPv6 prefix-from-interface field. It reads
  like a relay setting and is not one.
- An option scopes by `interface` or by `tag`, and the v4 and v6 option numbers
  are separate enums: 3 is `router` in v4 and `option_ia_na` in v6, so putting
  a v4 number in `option6` yields a valid request that configures something
  else.

Writes here stage by default. When a caller does ask for the reload, it is a
phase of its own: OPNsense answers a reconfigure with a `{"status": ...}`
document even when configd refuses, at HTTP 200, so every write reports
`applied` and a refused reload is reported as such — never as the write
having failed.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.mvc_merge import (
    is_enum_field,
    merge_for_set,
    selected_keys,
)
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

DNSMASQ = {
    "search_range": "/api/dnsmasq/settings/search_range",
    "get_range": "/api/dnsmasq/settings/get_range",
    "add_range": "/api/dnsmasq/settings/add_range",
    "set_range": "/api/dnsmasq/settings/set_range",
    "del_range": "/api/dnsmasq/settings/del_range",
    "search_option": "/api/dnsmasq/settings/search_option",
    "get_option": "/api/dnsmasq/settings/get_option",
    "add_option": "/api/dnsmasq/settings/add_option",
    "set_option": "/api/dnsmasq/settings/set_option",
    "del_option": "/api/dnsmasq/settings/del_option",
    "reconfigure": "/api/dnsmasq/service/reconfigure",
}

ROUTER_OPTION = "3"

# The 18 fields get_range returns, plus uuid. Four of them (ra_mode,
# ra_priority, constructor, domain_type) are MVC selects on read and bare
# option keys on write, so both directions go through mvc_merge.
_RANGE_FIELDS = (
    "uuid",
    "interface",
    "start_addr",
    "end_addr",
    "subnet_mask",
    "constructor",
    "mode",
    "prefix_len",
    "lease_time",
    "domain",
    "domain_type",
    "set_tag",
    "nosync",
    "description",
    "ra_mode",
    "ra_priority",
    "ra_interval",
    "ra_mtu",
    "ra_router_lifetime",
)

# Fields a caller may write on a range, beyond the bounds and the interface.
_RANGE_WRITE_FIELDS = (
    "start_addr",
    "end_addr",
    "subnet_mask",
    "constructor",
    "mode",
    "prefix_len",
    "lease_time",
    "domain",
    "description",
    # The dnsmasq client tag. A range's set_tag labels every client that
    # leases from it, and a DHCP option carrying the matching `tag` is sent
    # only to those clients. Omitting it from the writable set meant a range
    # created here could never receive the options its VLAN's other ranges
    # get -- a ULA range served addresses and no DNS server.
    "set_tag",
    "ra_mode",
    "ra_priority",
    "ra_interval",
    "ra_mtu",
    "ra_router_lifetime",
)

# Read live off the model. dnsmasq combines RA modes, so ra_mode is validated
# token by token. The empty string is accepted for either select and means
# "leave it at the model default": normal priority, and no RA mode set.
RA_MODES = (
    "ra-only",
    "slaac",
    "ra-names",
    "ra-stateless",
    "ra-advrouter",
    "off-link",
)
RA_PRIORITIES = ("high", "low")

_RA_MODE_HELP = f"One or more of: {', '.join(RA_MODES)}. Empty leaves it unset."
_RA_PRIORITY_HELP = (
    f"Router preference: {', '.join(RA_PRIORITIES)}, or empty for normal."
)

_OPTION_FIELDS = (
    "uuid",
    "type",
    "option",
    "option6",
    "interface",
    "tag",
    "set_tag",
    "value",
    "force",
    "description",
)


def _v6_schema_fields() -> dict[str, Any]:
    """Return the IPv6/RA properties shared by the create and update schemas.

    A function rather than a module constant so the two schemas do not share
    one mutable dict.
    """
    return {
        "constructor": {
            "type": "string",
            "description": (
                "Interface key to take the IPv6 prefix from, e.g. opt13. This "
                "is the field that makes an IPv6 range advertise; it is not a "
                "relay setting."
            ),
            "optional": True,
        },
        "mode": {
            "type": "string",
            "description": "Range mode; empty for a plain DHCP range",
            "optional": True,
        },
        "prefix_len": {
            "type": "string",
            "description": "Advertised prefix length, e.g. 64",
            "optional": True,
        },
        "set_tag": {
            "type": "string",
            "description": (
                "dnsmasq client tag uuid. Every client leasing from this "
                "range is tagged with it, and a DHCP option carrying the "
                "same tag is sent only to those clients. Copy it from "
                "another range on the same interface; list_options shows "
                "which options each tag carries."
            ),
            "optional": True,
        },
        "ra_mode": {
            "type": "string",
            "description": _RA_MODE_HELP,
            "optional": True,
        },
        "ra_priority": {
            "type": "string",
            "description": _RA_PRIORITY_HELP,
            "optional": True,
        },
        "ra_interval": {
            "type": "string",
            "description": "Router advertisement interval, in seconds",
            "optional": True,
        },
        "ra_mtu": {
            "type": "string",
            "description": "MTU to advertise",
            "optional": True,
        },
        "ra_router_lifetime": {
            "type": "string",
            "description": (
                "Router lifetime, in seconds. The model has no preferred "
                "lifetime for the advertised prefix."
            ),
            "optional": True,
        },
    }


class _DnsmasqToolBase:
    """Shared client handling, row access, and the reconfigure helper.

    `_reconfigure` raises :class:`ApplyError` unless the reload reported
    success, so callers report a refused apply instead of a failed write.
    """

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

    async def _reconfigure(self) -> None:
        """Reload dnsmasq, or raise :class:`ApplyError`.

        A configd refusal answers at HTTP 200 with a `{"status": ...}`
        document, so the raw POST cannot tell a reloaded service from an
        unchanged one.
        """
        await run_apply(self.client, DNSMASQ["reconfigure"])


def _flat_value(value: Any) -> Any:
    """Collapse an MVC select to its selected key, leaving scalars alone.

    search_* rows hand back scalars, get_* nodes hand back
    ``{option: {value, selected}}``. A reader that only handled the first shape
    reported a select as an unreadable dict.
    """
    if is_enum_field(value):
        return selected_keys(value)
    return value


def _project(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Keep the real fields, and surface the display label under a plain name."""
    out = {field: _flat_value(row.get(field, "")) for field in fields}
    if "%interface" in row:
        out["interface_label"] = row["%interface"]
    return out


def _option_tokens(value: Any) -> list[str]:
    """Split a select value into its option keys, dropping empties."""
    if isinstance(value, (list, tuple)):
        raw = [str(item) for item in value]
    else:
        raw = str(value or "").split(",")
    return [token.strip() for token in raw if token.strip()]


def _normalize_select(
    field: str, value: Any, allowed: tuple[str, ...]
) -> tuple[str, str | None]:
    """Return the comma-joined option keys, or an error naming the bad ones.

    Posting an option key the model does not have is accepted by the API and
    silently stored as nothing, so an unknown ra_mode would read back as a
    range that advertises differently than the caller asked for. Refuse it here
    instead of finding out from the firewall's behaviour.
    """
    tokens = _option_tokens(value)
    unknown = [token for token in tokens if token not in allowed]
    if unknown:
        return "", (
            f"{field}: unknown value(s) {', '.join(unknown)}; "
            f"valid options are {', '.join(allowed)} (or empty for the default)"
        )
    return ",".join(tokens), None


def _validated_range_changes(
    params: dict[str, Any], fields: tuple[str, ...]
) -> tuple[dict[str, Any], str | None]:
    """Collect the range fields present in *params*, validating the selects."""
    changes: dict[str, Any] = {
        field: params[field] for field in fields if field in params
    }
    for field, allowed in (("ra_mode", RA_MODES), ("ra_priority", RA_PRIORITIES)):
        if field not in changes:
            continue
        normalized, error = _normalize_select(field, changes[field], allowed)
        if error:
            return {}, error
        changes[field] = normalized
    return changes, None


class ListDhcpRangesTool(_DnsmasqToolBase):
    """List dnsmasq DHCP ranges."""

    name = "list_dhcp_ranges"
    description = "List DHCP ranges served by dnsmasq"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the ranges without the display-only fields."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(DNSMASQ["search_range"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list DHCP ranges")
            return {"status": "error", "error": str(exc)}
        ranges = [_project(row, _RANGE_FIELDS) for row in rows]
        return {"status": "success", "count": len(ranges), "ranges": ranges}


class MkDhcpRangeTool(_DnsmasqToolBase):
    """Create a DHCP range."""

    name = "mk_dhcp_range"
    description = "Create a DHCP range on an interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "description": "Interface key, e.g. opt3"},
            "start_addr": {"type": "string", "description": "First address"},
            "end_addr": {"type": "string", "description": "Last address"},
            "subnet_mask": {"type": "string", "optional": True},
            "lease_time": {
                "type": "string",
                "description": "Seconds, or a suffixed value like 2h",
                "optional": True,
            },
            "domain": {"type": "string", "optional": True},
            "description": {"type": "string", "optional": True},
            **_v6_schema_fields(),
            "apply": {
                "type": "boolean",
                "description": "Reconfigure dnsmasq afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["interface", "start_addr", "end_addr"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the range, keyed on interface and start address."""
        params = params or {}
        if not self.client:
            return self._no_client()

        interface = (params.get("interface") or "").strip()
        start = (params.get("start_addr") or "").strip()
        end = (params.get("end_addr") or "").strip()
        if not interface:
            return {"status": "error", "error": "interface is required"}
        if not start or not end:
            missing = "start_addr" if not start else "end_addr"
            return {
                "status": "error",
                "error": f"{missing} is required; a range needs both bounds",
            }

        extra, error = _validated_range_changes(params, _RANGE_WRITE_FIELDS)
        if error:
            return {"status": "error", "error": error}

        try:
            for row in await self._rows(DNSMASQ["search_range"]):
                if row.get("interface") == interface and row.get("start_addr") == start:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A range with this interface and start address exists.",
                    }

            payload = {
                "interface": interface,
                "start_addr": start,
                "end_addr": end,
                "subnet_mask": params.get("subnet_mask", ""),
                "lease_time": params.get("lease_time", ""),
                "domain": params.get("domain", ""),
                "description": params.get("description", ""),
            }
            # Only the fields the caller asked for; the rest keep the model's
            # own defaults rather than being posted as empty. merge_for_set
            # over an empty node is used for its scalar stringifying.
            payload.update(
                {
                    key: value
                    for key, value in merge_for_set({}, extra).items()
                    if key not in payload
                }
            )
            result = await self.client._make_request(
                "POST",
                DNSMASQ["add_range"],
                call_class="write",
                json={"range": payload},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create DHCP range")
            return {"status": "error", "error": str(exc)}

        # The reload is a separate phase: one that refuses leaves the range
        # staged, which is not the same as the create having failed.
        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await self._reconfigure()
                applied = True
            except ApplyError as exc:
                logger.warning("DHCP range staged but not applied: %s", exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                "Staged; the reconfigure did not complete, so dnsmasq is not "
                "serving it yet."
                if apply_error
                else "Applied; dnsmasq reloaded with the range."
                if applied
                else "Staged. Reconfigure dnsmasq to serve it."
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class SetDhcpRangeTool(_DnsmasqToolBase):
    """Update a DHCP range."""

    name = "set_dhcp_range"
    description = "Update fields on an existing DHCP range"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Range uuid"},
            "start_addr": {"type": "string", "optional": True},
            "end_addr": {"type": "string", "optional": True},
            "subnet_mask": {"type": "string", "optional": True},
            "lease_time": {"type": "string", "optional": True},
            "domain": {"type": "string", "optional": True},
            "description": {"type": "string", "optional": True},
            **_v6_schema_fields(),
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the range, merge the given fields, write the whole node back.

        A partial POST to an MVC model blanks every field it omits. That is the
        defect that made set_fw_rule widen rules to any/any, and a range would
        lose its bounds, its constructor and its RA settings the same way.

        ra_mode and ra_priority are validated before the write: the model
        accepts an option key it does not have and stores nothing for it.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        changes, error = _validated_range_changes(params, _RANGE_WRITE_FIELDS)
        if error:
            return {"status": "error", "error": error}
        if not changes:
            return {
                "status": "error",
                "error": (
                    f"nothing to change; pass one of: {', '.join(_RANGE_WRITE_FIELDS)}"
                ),
            }

        try:
            current = await self.client._make_request(
                "GET", f"{DNSMASQ['get_range']}/{uuid}"
            )
            node = current.get("range", {}) if isinstance(current, dict) else {}
            if not node:
                return {"status": "error", "error": f"range {uuid} not found"}

            payload = merge_for_set(node, changes)
            await self.client._make_request(
                "POST",
                f"{DNSMASQ['set_range']}/{uuid}",
                call_class="write",
                json={"range": payload},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update DHCP range")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await self._reconfigure()
                applied = True
            except ApplyError as exc:
                logger.warning("DHCP range %s updated but not applied: %s", uuid, exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "changed": sorted(changes),
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class RmDhcpRangeTool(_DnsmasqToolBase):
    """Delete a DHCP range."""

    name = "rm_dhcp_range"
    description = "Delete a DHCP range; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Range uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Removing a range stops the subnet getting addresses at all, and the
        symptom appears whenever leases happen to expire rather than at once.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "dhcp_range", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("dhcp_range", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{DNSMASQ['del_range']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete DHCP range")
            return {"status": "error", "error": str(exc)}

        # A refused reload must not read as a failed delete: the range is
        # gone from the config, and a retry would only fetch a new confirm
        # token for a record that no longer exists.
        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await self._reconfigure()
                applied = True
            except ApplyError as exc:
                logger.warning("DHCP range %s deleted but not applied: %s", uuid, exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "deleted": True,
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class ListDhcpOptionsTool(_DnsmasqToolBase):
    """List dnsmasq DHCP options."""

    name = "list_dhcp_options"
    description = "List DHCP options, with their human-readable option names"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the options, keeping the option label alongside the number."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(DNSMASQ["search_option"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list DHCP options")
            return {"status": "error", "error": str(exc)}

        options = []
        for row in rows:
            entry = _project(row, _OPTION_FIELDS)
            # The number alone is unreadable; the API already knows the name.
            entry["label"] = row.get("%option") or row.get("%option6") or ""
            options.append(entry)
        return {"status": "success", "count": len(options), "options": options}


class SetDhcpRouterOptionTool(_DnsmasqToolBase):
    """Set the default gateway handed out by DHCP."""

    name = "set_dhcp_router_option"
    description = (
        "Set the default gateway (DHCP option 3) for an interface or tag, "
        "which is what a subnet behind a router needs"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "router": {
                "type": "string",
                "description": "Gateway address to advertise",
            },
            "interface": {
                "type": "string",
                "description": "Interface key to scope the option to, e.g. opt3",
                "optional": True,
            },
            "tag": {
                "type": "string",
                "description": "Tag uuid to scope to instead of an interface",
                "optional": True,
            },
            "force": {
                "type": "boolean",
                "description": "Send the option even when the client did not ask",
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
            },
        },
        "required": ["router"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create or update the option 3 row for this scope.

        Scoping is required. An unscoped option 3 applies to every subnet
        dnsmasq serves, which points unrelated networks at the wrong gateway
        and looks like a routing fault rather than a DHCP one.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        router = (params.get("router") or "").strip()
        if not router:
            return {"status": "error", "error": "router is required"}

        interface = (params.get("interface") or "").strip()
        tag = (params.get("tag") or "").strip()
        if not interface and not tag:
            return {
                "status": "error",
                "error": (
                    "one of interface or tag is required. An unscoped option 3 "
                    "becomes the default gateway for every subnet dnsmasq serves."
                ),
            }

        try:
            existing = None
            for row in await self._rows(DNSMASQ["search_option"]):
                # Match the option number too: an interface usually carries
                # several options, and matching on scope alone would overwrite
                # whichever happened to be first.
                if row.get("option") != ROUTER_OPTION:
                    continue
                if interface and row.get("interface") == interface:
                    existing = row
                    break
                if tag and row.get("tag") == tag:
                    existing = row
                    break

            payload = {
                "type": "set",
                "option": ROUTER_OPTION,
                # Left empty deliberately: 3 is option_ia_na in the v6 enum.
                "option6": "",
                "interface": interface,
                "tag": tag,
                "set_tag": "",
                "value": router,
                "force": "1" if params.get("force") else "0",
                "description": (existing or {}).get("description", ""),
            }

            if existing:
                uuid = existing.get("uuid", "")
                await self.client._make_request(
                    "POST",
                    f"{DNSMASQ['set_option']}/{uuid}",
                    call_class="write",
                    json={"option": payload},
                )
                created = False
            else:
                result = await self.client._make_request(
                    "POST",
                    DNSMASQ["add_option"],
                    call_class="write",
                    json={"option": payload},
                )
                uuid = result.get("uuid", "") if isinstance(result, dict) else ""
                created = True
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to set the DHCP router option")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await self._reconfigure()
                applied = True
            except ApplyError as exc:
                logger.warning("Router option staged but not applied: %s", exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "created": created,
            "router": router,
            "scope": interface or f"tag:{tag}",
            "applied": applied,
            "note": (
                "Staged; the reconfigure did not complete, so dnsmasq is not "
                "serving it yet."
                if apply_error
                else "Applied; dnsmasq reloaded with the option."
                if applied
                else "Staged. Reconfigure dnsmasq to serve it."
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class RmDhcpOptionTool(_DnsmasqToolBase):
    """Delete a DHCP option."""

    name = "rm_dhcp_option"
    description = "Delete a DHCP option; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Option uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Exists so set_dhcp_router_option is reversible. Removing option 3
        strips a subnet's default gateway, and clients keep working until
        their leases renew, so the damage surfaces long after the change. A
        reload that refuses leaves the option deleted but dnsmasq still
        handing it out; that is reported as `applied: false`.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "dhcp_option", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("dhcp_option", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{DNSMASQ['del_option']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete DHCP option")
            return {"status": "error", "error": str(exc)}

        # Same separation as the range delete: the option is gone from the
        # config whatever the reload answered.
        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await self._reconfigure()
                applied = True
            except ApplyError as exc:
                logger.warning("DHCP option %s deleted but not applied: %s", uuid, exc)
                apply_error = str(exc)

        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "deleted": True,
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out
