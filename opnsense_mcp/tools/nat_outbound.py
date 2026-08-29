"""Outbound source NAT, and reachability tested from the firewall.

Once a prefix is routed rather than directly connected, the firewall stops
generating a source NAT rule for it automatically, and it loses internet access
without one. These tools add the rule and read the generation mode.

`fw_ping` exists because nothing else could answer "is the next hop reachable
from the firewall". Pinging from wherever the MCP server runs tests a different
path entirely, which is no help when checking a transit the server has no route
to.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

SNAT = {
    "get": "/api/firewall/source_nat/get",
    "set": "/api/firewall/source_nat/set",
    "search": "/api/firewall/source_nat/search_rule",
    "add": "/api/firewall/source_nat/add_rule",
    "delete": "/api/firewall/source_nat/del_rule",
    "toggle": "/api/firewall/source_nat/toggle_rule",
    "apply": "/api/firewall/filter/apply",
}
PING = {
    "set": "/api/diagnostics/ping/set",
    "start": "/api/diagnostics/ping/start",
    "jobs": "/api/diagnostics/ping/searchJobs",
    "stop": "/api/diagnostics/ping/stop",
    "remove": "/api/diagnostics/ping/remove",
}

# automatic keeps generated rules only; hybrid keeps them and adds yours;
# advanced replaces them; disabled turns generation off.
SAFE_MODES = ("automatic", "hybrid")
ALL_MODES = ("automatic", "hybrid", "advanced", "disabled")

_DISPLAY_PREFIXES = ("alias_meta_", "category_colors", "%")
_RULE_FIELDS = (
    "uuid",
    "interface",
    "source_net",
    "source_not",
    "destination_net",
    "destination_not",
    "target",
    "target_port",
    "staticnatport",
    "enabled",
    "log",
    "description",
)

# The model calls the address families ip and ip6; callers say inet and inet6,
# which is what every other tool here and every firewall CLI uses.
PING_FAMILIES = {"inet": "ip", "inet6": "ip6", "ip": "ip", "ip6": "ip6"}

PING_POLL_INTERVAL_SECONDS = 0.5
PING_DEFAULT_COUNT = 3
PING_MAX_COUNT = 20
# Packets go out about one a second, so the wait is roughly `count` seconds.
# The grace covers startup and a target that never answers at all.
PING_GRACE_POLLS = 5


class _NatToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _rows(self) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", SNAT["search"], json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []


def _selected(field: Any) -> str:
    """The selected key of an OPNsense enum object."""
    if not isinstance(field, dict):
        return str(field or "")
    for key, meta in field.items():
        if isinstance(meta, dict) and str(meta.get("selected")) in {"1", "True"}:
            return key
    return ""


class NatOutboundModeTool(_NatToolBase):
    """Read or change how outbound NAT rules are generated."""

    name = "nat_outbound_mode"
    description = "Read or set outbound source NAT generation mode"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action_mode": {
                "type": "string",
                "description": "get or set (default get)",
                "optional": True,
            },
            "mode": {
                "type": "string",
                "description": f"When setting: one of {', '.join(SAFE_MODES)}",
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Report the mode, or move between automatic and hybrid.

        `advanced` and `disabled` are refused. Both stop the firewall generating
        the implicit rules that cover management, VPN and other networks nobody
        has written a rule for, and the failure is silent: traffic simply stops
        being translated.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        action = (params.get("action_mode") or "get").strip()

        try:
            current = await self.client._make_request("GET", SNAT["get"])
            general = (
                current.get("filter", {}).get("general", {})
                if isinstance(current, dict)
                else {}
            )
            mode = _selected(general.get("snat_mode"))

            if action == "get":
                return {
                    "status": "success",
                    "mode": mode,
                    "modes": list(ALL_MODES),
                    "note": (
                        "hybrid keeps the automatically generated rules and adds "
                        "yours, which is what a routed border needs."
                    ),
                }

            wanted = (params.get("mode") or "").strip()
            if wanted not in ALL_MODES:
                return {
                    "status": "error",
                    "error": f"unknown mode {wanted!r}; expected one of: "
                    + ", ".join(ALL_MODES),
                }
            if wanted not in SAFE_MODES:
                return {
                    "status": "error",
                    "error": (
                        f"{wanted!r} stops OPNsense generating the implicit outbound "
                        f"rules that cover management, VPN and any network without "
                        f"an explicit rule. Use one of {', '.join(SAFE_MODES)}, or "
                        f"make the change in the UI where the consequences are shown."
                    ),
                }

            await self.client._make_request(
                "POST",
                SNAT["set"],
                call_class="write",
                json={"filter": {"general": {"snat_mode": wanted}}},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to handle outbound NAT mode")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "mode": wanted, "previous": mode}


class ListNatOutboundTool(_NatToolBase):
    """List outbound source NAT rules."""

    name = "list_nat_outbound"
    description = "List outbound source NAT rules"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the rules, without the display metadata the rows carry."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list outbound NAT rules")
            return {"status": "error", "error": str(exc)}

        rules = [{field: row.get(field, "") for field in _RULE_FIELDS} for row in rows]
        return {"status": "success", "count": len(rules), "rules": rules}


class MkNatOutboundTool(_NatToolBase):
    """Create an outbound source NAT rule."""

    name = "mk_nat_outbound"
    description = "Create an outbound source NAT rule for a source network or alias"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {
                "type": "string",
                "description": "Outgoing interface, usually wan",
            },
            "source_net": {
                "type": "string",
                "description": "Source network or alias name to translate",
            },
            "destination_net": {
                "type": "string",
                "description": "Destination to match (default any)",
                "optional": True,
            },
            "target": {
                "type": "string",
                "description": "Translation address; empty means the interface address",
                "optional": True,
            },
            "static_port": {
                "type": "boolean",
                "description": "Preserve the source port",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "enabled": {
                "type": "boolean",
                "description": "Target state, set explicitly rather than flipped",
                "optional": True,
            },
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
        """Create the rule, keyed on interface and source."""
        params = params or {}
        if not self.client:
            return self._no_client()

        interface = (params.get("interface") or "").strip()
        source_net = (params.get("source_net") or "").strip()
        if not interface:
            return {"status": "error", "error": "interface is required"}
        if not source_net:
            return {
                "status": "error",
                "error": (
                    "source_net is required. A rule without one would translate "
                    "everything leaving the interface, including traffic that is "
                    "already handled."
                ),
            }

        try:
            for row in await self._rows():
                if (
                    row.get("interface") == interface
                    and row.get("source_net") == source_net
                ):
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A rule for this interface and source already exists.",
                    }

            payload = {
                "interface": interface,
                "source_net": source_net,
                "destination_net": params.get("destination_net", "any"),
                "target": params.get("target", ""),
                "staticnatport": "1" if params.get("static_port") else "0",
                "description": params.get("description", ""),
                # Honored, not hardcoded: a rule asked for disabled used to be
                # created live and translate traffic on the next apply.
                "enabled": "0" if params.get("enabled") is False else "1",
            }
            result = await self.client._make_request(
                "POST", SNAT["add"], call_class="write", json={"rule": payload}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create outbound NAT rule")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = False, ""
        if params.get("apply", False):
            try:
                await run_apply(self.client, SNAT["apply"])
                applied = True
            except ApplyError as exc:
                logger.warning(
                    "Outbound NAT rule created but filter reload failed: %s", exc
                )
                apply_error = str(exc)

        out = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                "Rule created and loaded into the packet filter."
                if applied
                else "Staged. Apply the filter to load it."
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class ToggleNatOutboundTool(_NatToolBase):
    """Enable or disable an outbound NAT rule."""

    name = "toggle_nat_outbound"
    description = "Enable or disable an outbound source NAT rule"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Rule uuid"},
            "enabled": {"type": "boolean", "description": "Target state"},
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Set the rule to an explicit state."""
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
                "POST", f"{SNAT['toggle']}/{uuid}/{state}", call_class="write"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle outbound NAT rule")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "enabled": bool(params["enabled"])}


class RmNatOutboundTool(_NatToolBase):
    """Delete an outbound NAT rule."""

    name = "rm_nat_outbound"
    description = "Delete an outbound source NAT rule; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Rule uuid"},
            "confirm": {"type": "string", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Removing the rule silently stops translating a prefix, which looks like
        a routing fault rather than a NAT one, so this takes two calls.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "nat_outbound", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("nat_outbound", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{SNAT['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete outbound NAT rule")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}


class FwPingTool(_NatToolBase):
    """Ping from the firewall."""

    name = "fw_ping"
    description = (
        "Ping a target from the firewall itself, which is the path that matters "
        "when checking a gateway or transit"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Address or hostname to ping"},
            "source_address": {
                "type": "string",
                "description": "Source address, to test a specific path",
                "optional": True,
            },
            "family": {
                "type": "string",
                "description": "inet or inet6 (default inet)",
                "optional": True,
            },
            "count": {
                "type": "number",
                "description": f"Packets to wait for (default {PING_DEFAULT_COUNT}, max {PING_MAX_COUNT})",
                "optional": True,
            },
            "packetsize": {
                "type": "number",
                "description": "Payload bytes, for checking MTU on a transit",
                "optional": True,
            },
        },
        "required": ["target"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run a ping and return its counters.

        The API models this as a long-running job: `start` keeps pinging until
        something stops it, and the job row carries live counters rather than
        command output. So this waits for `count` packets, stops the job, reads
        the final row and removes it. Stop and remove run even when the wait
        fails, because a job left behind pings forever.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        target = (params.get("target") or "").strip()
        if not target:
            return {"status": "error", "error": "target is required"}

        try:
            count = max(
                1, min(int(params.get("count") or PING_DEFAULT_COUNT), PING_MAX_COUNT)
            )
        except (TypeError, ValueError):
            return {"status": "error", "error": "count must be a number"}

        job_id = ""
        row: dict[str, Any] = {}
        try:
            created = await self.client._make_request(
                "POST",
                PING["set"],
                call_class="write",
                json={
                    "ping": {
                        "settings": {
                            "hostname": target,
                            "fam": PING_FAMILIES.get(
                                str(params.get("family", "inet")), "ip"
                            ),
                            "source_address": params.get("source_address", ""),
                            "packetsize": str(params.get("packetsize", "") or ""),
                            "description": "mcp fw_ping",
                        }
                    }
                },
            )
            job_id = created.get("uuid", "") if isinstance(created, dict) else ""
            if not job_id:
                return {
                    "status": "error",
                    "error": f"ping job was not created: {created}",
                }

            await self.client._make_request(
                "POST", f"{PING['start']}/{job_id}", call_class="write"
            )
            row = await self._wait_for_packets(job_id, count)
        except Exception as exc:  # noqa: BLE001
            logger.exception("fw_ping failed")
            return {"status": "error", "error": str(exc)}
        finally:
            if job_id:
                await self._cleanup(job_id)

        sent = int(row.get("send") or 0)
        received = int(row.get("received") or 0)
        return {
            "status": "success",
            "target": target,
            "reachable": received > 0,
            "transmitted": sent,
            "received": received,
            "loss": str(row.get("loss", "")),
            "rtt_ms": {
                "min": row.get("min"),
                "avg": row.get("avg"),
                "max": row.get("max"),
            },
            "last_error": row.get("last_error"),
        }

    async def _wait_for_packets(self, job_id: str, count: int) -> dict[str, Any]:
        """Poll until `count` packets have gone out, or the job ends or times out.

        The deadline matters: an unresolvable hostname or a blackholed address
        never increments the counter, and without it this would poll forever.
        """
        row: dict[str, Any] = {}
        deadline = count + PING_GRACE_POLLS
        for _ in range(int(deadline / PING_POLL_INTERVAL_SECONDS)):
            jobs = await self.client._make_request(
                "POST", PING["jobs"], json={"current": 1, "rowCount": 200}
            )
            rows = jobs.get("rows", []) if isinstance(jobs, dict) else []
            found = next((r for r in rows if r.get("id") == job_id), None)
            if found is None:
                # The job ended and was reaped; the last row we saw is the result.
                break
            row = found
            if int(found.get("send") or 0) >= count:
                break
            if str(found.get("status", "")) not in {"running", "starting", ""}:
                break
            await asyncio.sleep(PING_POLL_INTERVAL_SECONDS)
        return row

    async def _cleanup(self, job_id: str) -> None:
        """Stop the process, then drop the job. Both, in that order."""
        for endpoint in (PING["stop"], PING["remove"]):
            try:
                await self.client._make_request(
                    "POST", f"{endpoint}/{job_id}", call_class="write"
                )
            except Exception:  # noqa: BLE001 - cleanup is best effort
                logger.warning("Could not %s ping job %s", endpoint, job_id)
