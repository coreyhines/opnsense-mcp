"""WireGuard instance and peer writes (#43).

Read tools live in `wireguard.py`; this module is the write half and reuses its
helpers rather than restating them.

Everything here was read off the firmware's own controllers
(`OPNsense/Wireguard/Api/{Client,Server,Service}Controller.php`) and models
(`Server.xml`, `Client.xml`) rather than inferred from responses, because four
of the rules below are invisible from the outside.

**Membership is written through the client, never the server.**
`ClientController::setClientAction` reads the posted `client.servers`, locks the
config, walks every server node and adds or removes this client's uuid from its
`peers`. `delClientAction` strips the uuid from every server before deleting.
So `servers` on the client is the write channel and `peers` on the server is
its output. Posting `server.peers` through `setServer` fights that and
desynchronises the back-reference. `servers` is declared `volatile="true"` in
`Client.xml` and is still the channel.

**A `set*` POST replaces the whole node.** Any field omitted is reset to its
model default, so a partial update has to read, overlay and write everything
back. That is what `merge_for_set` does. It also means `set_instance` handles
the instance private key, because `privkey` is `Required` in `Server.xml` and
dropping it fails the write. The key passes through this process and must never
reach a result or an error string; `redact_keys` covers the error path and
`test_no_write_result_carries_key_material` covers the result path.

**`toggleServerAction($uuid)` and `toggleClientAction($uuid)` take one
parameter.** An extra URL segment does not bind, so the action flips whatever
is there. `SHARED_FIELDS["enabled"]` promises a target state set explicitly, so
both toggles here read the current value first and either no-op or write
through `set`.

**A failure arrives at HTTP 200.** `setBase` answers
`{"result": "failed", "validations": {...}}`, and the transport only raises on
`result == "failed"` without surfacing which field was rejected. `set_or_refuse`
is where that detail is recovered.

And one thing an apply cannot tell you: `ServiceController::reconfigureAction`
returns `['result' => 'ok']` unconditionally after handing off to configd. It
reports that the request was accepted, not that the interface reached the state
asked for, so every apply here re-reads and says whether it matched.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.tools.wireguard import (
    WG_CLIENT,
    WG_SERVER,
    _WgToolBase,
    get_path,
    record_or_none,
    redact_keys,
    rows_or_refuse,
    selected_option_keys,
    split_list,
)
from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.mvc_merge import merge_for_set
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

WG_SERVER_WRITE = {"set": "/api/wireguard/server/setServer"}
WG_CLIENT_WRITE = {
    "add": "/api/wireguard/client/addClient",
    "set": "/api/wireguard/client/setClient",
    "del": "/api/wireguard/client/delClient",
}
WG_RECONFIGURE = "/api/wireguard/service/reconfigure"

# Fields `set_instance` will overlay. Deliberately not the whole model:
# `privkey` and `pubkey` are key material, `instance`, `interface`,
# `cnfFilename` and `statFilename` are assigned by the plugin, and `peers` is
# the server side of a relation this module only ever writes from the client.
INSTANCE_SETTABLE = frozenset(
    {
        "name",
        "port",
        "mtu",
        "dns",
        "tunneladdress",
        "disableroutes",
        "gateway",
        "endpoint",
        "peer_dns",
        "allowed_ips",
    }
)

# Same for a peer. `psk` and `privkey` are key material and are round-tripped
# unchanged by the merge rather than exposed: accepting a pre-shared key as a
# parameter would put it in the transcript, which is the thing #44 decided
# against. `pubkey` is settable because it is public by construction and
# rotating it is an ordinary operation.
PEER_SETTABLE = frozenset(
    {
        "name",
        "pubkey",
        "tunneladdress",
        "keepalive",
        "serveraddress",
        "serverport",
        "endpoint",
    }
)


class WgWriteError(Exception):
    """A write was refused, or did not save.

    Carries `validations` as a field rather than only in the message. Asserting
    that a rejected field name appears in the text passes whether the detail was
    parsed or the whole body was simply dumped into the string, so the wording
    cannot tell a caller -- or a test -- which happened.
    """

    def __init__(self, message: str, validations: dict[str, Any] | None = None):
        """Record the message and, when the body carried one, the field detail."""
        super().__init__(message)
        self.validations = validations or {}


def set_or_refuse(payload: Any, what: str) -> dict[str, Any]:
    """The save result, refusing a validation failure that arrived at HTTP 200.

    `setBase` reports a rejected field in `validations` and the transport does
    not look, so without this a caller is told only that something failed. The
    field name is the whole diagnostic.
    """
    if not isinstance(payload, dict):
        raise WgWriteError(
            f"{what}: expected a save result, got {type(payload).__name__}"
        )
    if str(payload.get("result", "")).strip().lower() == "saved":
        return payload
    validations = payload.get("validations")
    if isinstance(validations, dict) and validations:
        detail = "; ".join(
            f"{field}: {msg}" for field, msg in sorted(validations.items())
        )
        raise WgWriteError(f"{what} was refused: {detail}", validations)
    raise WgWriteError(f"{what} did not save: {redact_keys(payload)}")


def stored_entries(value: Any) -> list[str]:
    """A stored list field as a plain list, whichever shape it arrived in.

    `tunneladdress` is a comma-joined string in a *search* row and a
    `{entry: {value, selected}}` node map in a `get*`. Both read paths are in
    use here, and running the map through a string splitter yields the repr of
    a dict split on its commas -- which compares unequal to everything, so a
    removal check silently reported every write as destructive and every real
    removal as something else.
    """
    if isinstance(value, dict):
        return selected_option_keys(value)
    return split_list(value)


def removed_entries(before: list[str], after: list[str]) -> list[str]:
    """What `after` drops relative to `before`.

    A list field is replaced wholesale, so "set the allowed IPs" and "take an
    address away from this peer" are the same request with different content.
    Only the second needs confirming, and only the caller's own diff can tell
    them apart.
    """
    remaining = set(after)
    return [entry for entry in before if entry not in remaining]


def _write_error(exc: WgWriteError) -> dict[str, Any]:
    """A refused write as a result, with the rejected fields kept structured."""
    out: dict[str, Any] = {"status": "error", "error": str(exc)}
    if exc.validations:
        out["validations"] = exc.validations
    return out


class _WgWriteBase(_WgToolBase):
    """Read-merge-write plumbing shared by the instance and peer setters."""

    async def _get_record(self, base: str, key: str, uuid: str) -> dict[str, Any]:
        """One record, refusing the blank template an empty uuid returns."""
        payload = await self.client._make_request("GET", get_path(base, uuid))
        record = record_or_none(payload, key)
        if record is None:
            raise WgWriteError(
                f"no {key} has uuid {uuid!r}; an unknown uuid answers HTTP 200 "
                f"with an empty array rather than 404"
            )
        return record

    async def _post(self, path: str, key: str, flat: dict[str, str], what: str) -> dict:
        """POST a flattened node and refuse anything that is not a save."""
        payload = await self.client._make_request(
            "POST", path, call_class="write", json={key: flat}
        )
        return set_or_refuse(payload, what)

    async def _apply_and_verify(
        self,
        *,
        should_apply: bool,
        base: str,
        key: str,
        uuid: str,
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        """Reconfigure, then re-read and say whether the state matches.

        `reconfigureAction` returns `{"result": "ok"}` after handing off to
        configd without waiting on it, so its success means the request was
        accepted. Reporting `applied: true` off the back of that is the mistake
        `delete_pipe` and `apply_ula` both made. The re-read is what turns it
        into a claim about state.
        """
        out: dict[str, Any] = {"applied": False, "staged": True}
        if not should_apply:
            out["note"] = "staged; call again with apply=true to load it"
            return out

        try:
            await run_apply(self.client, WG_RECONFIGURE)
        except ApplyError as exc:
            out["apply_error"] = redact_keys(exc)
            return out

        out["staged"] = False
        out["applied"] = True
        try:
            record = await self._get_record(base, key, uuid)
        except (WgWriteError, Exception) as exc:  # noqa: BLE001
            out["verified"] = False
            out["verify_error"] = redact_keys(exc)
            return out

        mismatched = {
            field: {"wanted": wanted, "stored": record.get(field)}
            for field, wanted in expected.items()
            if not _expected_matches(wanted, record.get(field))
        }
        out["verified"] = not mismatched
        if mismatched:
            out["mismatched"] = mismatched
        return out


def _stored_value(value: Any) -> str:
    """A read-back field as the string a write would have sent.

    An enum comes back as `{option: {selected, value}}` and a scalar as a
    string, so comparing the raw read against what was written reports every
    enum as drifted.
    """
    if isinstance(value, dict):
        return ",".join(selected_option_keys(value))
    return str(value if value is not None else "")


def _expected_matches(wanted: Any, stored: Any) -> bool:
    """True when the re-read field matches what the write asked for.

    ``servers`` and ``tunneladdress`` are membership lists: order on the wire
    and in the node map need not match, so compare as sorted sets. Scalars stay
    exact string compares.
    """
    wanted_s = str(wanted)
    stored_s = _stored_value(stored)
    if isinstance(stored, dict) or "," in wanted_s or "," in stored_s:
        return sorted(split_list(wanted_s)) == sorted(split_list(stored_s))
    return stored_s == wanted_s


def _overlay(params: dict[str, Any], settable: frozenset[str]) -> dict[str, Any]:
    """The caller's changes, keeping only fields this tool may set.

    Booleans become "1"/"0" because the model stores BooleanField that way and
    a bare `True` is written as the string "True", which fails validation.
    """
    overlay: dict[str, Any] = {}
    for field in sorted(settable):
        if field not in params or params[field] is None:
            continue
        value = params[field]
        overlay[field] = (
            ("1" if value else "0") if isinstance(value, bool) else str(value)
        )
    return overlay


class SetWgInstanceTool(_WgWriteBase):
    """Update a WireGuard instance."""

    name = "set_wg_instance"
    description = (
        "Update a WireGuard instance's addresses, MTU, DNS, gateway or routing; "
        "stages by default"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Instance uuid"},
            "name": {"type": "string", "optional": True},
            "port": {"type": "string", "description": "Listen port", "optional": True},
            "mtu": {"type": "string", "optional": True},
            "dns": {
                "type": "string",
                "description": "DNS servers pushed to peers, comma-joined",
                "optional": True,
            },
            "tunneladdress": {
                "type": "string",
                "description": (
                    "The instance's own addresses, comma-joined. Replaces the "
                    "whole list; removing one needs a confirm token"
                ),
                "optional": True,
            },
            "disableroutes": {"type": "boolean", "optional": True},
            "gateway": {"type": "string", "optional": True},
            "endpoint": {"type": "string", "optional": True},
            "peer_dns": {"type": "string", "optional": True},
            "allowed_ips": {"type": "string", "optional": True},
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
                "description": (
                    "Load the change now. Omitted, the change is written to "
                    "config and left staged until something else applies it."
                ),
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the instance, overlay the given fields, write it back."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = str(params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        overlay = _overlay(params, INSTANCE_SETTABLE)
        if not overlay:
            return {
                "status": "error",
                "error": (
                    "nothing to change; give at least one of "
                    f"{', '.join(sorted(INSTANCE_SETTABLE))}"
                ),
            }

        try:
            record = await self._get_record(WG_SERVER["get"], "server", uuid)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard instance")
            return {"status": "error", "error": redact_keys(exc)}

        if "tunneladdress" in overlay:
            dropped = removed_entries(
                stored_entries(record.get("tunneladdress")),
                split_list(overlay["tunneladdress"]),
            )
            if dropped and not validate_delete_confirm_token(
                "wg_instance_address", uuid, str(params.get("confirm") or "")
            ):
                token = issue_delete_confirm_token("wg_instance_address", uuid)
                return {
                    "status": "confirmation_required",
                    "uuid": uuid,
                    "removing": dropped,
                    "confirm_token": token["token"],
                    "message": (
                        f"this replaces the instance's addresses and drops "
                        f"{', '.join(dropped)}. {token['message']}"
                    ),
                }

        try:
            flat = merge_for_set(record, overlay)
            await self._post(
                f"{WG_SERVER_WRITE['set']}/{uuid}", "server", flat, "the instance"
            )
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to write WireGuard instance")
            return {"status": "error", "error": redact_keys(exc)}

        result: dict[str, Any] = {"status": "success", "uuid": uuid, "changed": overlay}
        result.update(
            await self._apply_and_verify(
                should_apply=bool(params.get("apply")),
                base=WG_SERVER["get"],
                key="server",
                uuid=uuid,
                expected=overlay,
            )
        )
        return result


class SetWgPeerTool(_WgWriteBase):
    """Update a WireGuard peer."""

    name = "set_wg_peer"
    description = (
        "Update a WireGuard peer's allowed IPs, keepalive, endpoint or instance "
        "membership; stages by default"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Peer uuid"},
            "name": {"type": "string", "optional": True},
            "pubkey": {
                "type": "string",
                "description": "The peer's public key",
                "optional": True,
            },
            "tunneladdress": {
                "type": "string",
                "description": (
                    "Server-side allowed IPs for this peer, comma-joined. "
                    "Replaces the whole list; removing one locks the peer out "
                    "and needs a confirm token"
                ),
                "optional": True,
            },
            "keepalive": {"type": "string", "optional": True},
            "serveraddress": {"type": "string", "optional": True},
            "serverport": {"type": "string", "optional": True},
            "endpoint": {"type": "string", "optional": True},
            "instances": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Instance uuids or names this peer belongs to. Replaces the "
                    "whole membership; removing one needs a confirm token"
                ),
                "optional": True,
            },
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
                "description": (
                    "Load the change now. Omitted, the change is written to "
                    "config and left staged until something else applies it."
                ),
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the peer, overlay the given fields, write it back."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = str(params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        overlay = _overlay(params, PEER_SETTABLE)
        wanted_instances = params.get("instances")
        if not overlay and wanted_instances is None:
            return {
                "status": "error",
                "error": (
                    "nothing to change; give at least one of "
                    f"{', '.join(sorted(PEER_SETTABLE))} or instances"
                ),
            }

        try:
            record = await self._get_record(WG_CLIENT["get"], "client", uuid)
            current_members = selected_option_keys(record.get("servers"))
            if wanted_instances is not None:
                resolved, unknown = await self._resolve_instances(wanted_instances)
                if unknown:
                    return {
                        "status": "error",
                        "error": (
                            f"no WireGuard instance matches {', '.join(unknown)}; "
                            f"refusing rather than writing a membership that "
                            f"names nothing"
                        ),
                    }
                overlay["servers"] = ",".join(resolved)
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard peer")
            return {"status": "error", "error": redact_keys(exc)}

        pending = self._removals(record, overlay, current_members)
        if pending and not validate_delete_confirm_token(
            "wg_peer", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("wg_peer", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "removing": pending,
                "confirm_token": token["token"],
                "message": (
                    f"this replaces a list wholesale and drops {pending}. "
                    f"{token['message']}"
                ),
            }

        try:
            flat = merge_for_set(record, overlay)
            await self._post(
                f"{WG_CLIENT_WRITE['set']}/{uuid}", "client", flat, "the peer"
            )
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to write WireGuard peer")
            return {"status": "error", "error": redact_keys(exc)}

        result: dict[str, Any] = {"status": "success", "uuid": uuid, "changed": overlay}
        result.update(
            await self._apply_and_verify(
                should_apply=bool(params.get("apply")),
                base=WG_CLIENT["get"],
                key="client",
                uuid=uuid,
                expected=overlay,
            )
        )
        return result

    @staticmethod
    def _removals(
        record: dict[str, Any], overlay: dict[str, Any], current_members: list[str]
    ) -> dict[str, list[str]]:
        """Which wholesale replacements take something away."""
        pending: dict[str, list[str]] = {}
        if "tunneladdress" in overlay:
            dropped = removed_entries(
                stored_entries(record.get("tunneladdress")),
                split_list(overlay["tunneladdress"]),
            )
            if dropped:
                pending["allowed_ips"] = dropped
        if "servers" in overlay:
            dropped = removed_entries(current_members, split_list(overlay["servers"]))
            if dropped:
                pending["instances"] = dropped
        return pending

    async def _resolve_instances(self, wanted: Any) -> tuple[list[str], list[str]]:
        """Instance uuids for a list of uuids or names, plus what matched nothing."""
        names = [str(entry).strip() for entry in (wanted or []) if str(entry).strip()]
        if not names:
            # An empty membership is legal: it unenrols the peer everywhere.
            return [], []
        servers = rows_or_refuse(
            await self._search(WG_SERVER["search"]), "wireguard instances"
        )
        by_key = {
            str(row.get(field, "")): str(row.get("uuid", ""))
            for row in servers
            for field in ("uuid", "name")
            if row.get(field)
        }
        resolved = [by_key[name] for name in names if name in by_key]
        unknown = [name for name in names if name not in by_key]
        return list(dict.fromkeys(resolved)), unknown


class CreateWgPeerTool(_WgWriteBase):
    """Create a WireGuard peer from a public key."""

    name = "create_wg_peer"
    description = (
        "Create a WireGuard peer. Takes the peer's public key; never generates "
        "or returns a private key. Stages by default"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Peer name"},
            "pubkey": {
                "type": "string",
                "description": (
                    "The peer's public key, generated on the device. This tool "
                    "never generates one: a private key must not pass through a "
                    "conversation transcript"
                ),
            },
            "instances": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Instance uuids or names to enrol this peer in",
            },
            "tunneladdress": {
                "type": "string",
                "description": "Server-side allowed IPs, comma-joined",
                "optional": True,
            },
            "keepalive": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
                "description": (
                    "Load the change now. Omitted, the peer is written to "
                    "config and left staged until something else applies it."
                ),
            },
        },
        "required": ["name", "pubkey", "instances"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the peer, enrolling it through the client's own `servers`."""
        params = params or {}
        if not self.client:
            return self._no_client()

        name = str(params.get("name") or "").strip()
        pubkey = str(params.get("pubkey") or "").strip()
        if not name:
            return {"status": "error", "error": "name is required"}
        if not pubkey:
            return {
                "status": "error",
                "error": (
                    "pubkey is required. Generate the keypair on the device -- "
                    "the WireGuard app shows its public key -- and pass that. "
                    "This tool does not generate keys, so no private key exists "
                    "for it to return."
                ),
            }

        try:
            resolved, unknown = await SetWgPeerTool._resolve_instances(
                self, params.get("instances")
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to resolve WireGuard instances")
            return {"status": "error", "error": redact_keys(exc)}
        if unknown:
            return {
                "status": "error",
                "error": f"no WireGuard instance matches {', '.join(unknown)}",
            }
        if not resolved:
            return {
                "status": "error",
                "error": (
                    "instances is required and must name at least one instance; "
                    "a peer enrolled nowhere is written but never loaded"
                ),
            }

        payload = {
            "enabled": "1",
            "name": name,
            "pubkey": pubkey,
            "tunneladdress": str(params.get("tunneladdress") or ""),
            "keepalive": str(params.get("keepalive") or ""),
            "servers": ",".join(resolved),
        }

        try:
            saved = await self._post(
                WG_CLIENT_WRITE["add"], "client", payload, "the new peer"
            )
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create WireGuard peer")
            return {"status": "error", "error": redact_keys(exc)}

        uuid = str(saved.get("uuid") or "")
        result: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "name": name,
            "instances": resolved,
        }
        if not uuid:
            # addClient returns the generated uuid only alongside result=saved.
            # Without it there is nothing to re-read, so say so rather than
            # reporting a verification that did not happen.
            result["verified"] = False
            result["verify_error"] = "the save returned no uuid to read back"
            result["applied"] = False
            result["staged"] = True
            return result
        expected: dict[str, Any] = {
            "name": name,
            "pubkey": pubkey,
            # Membership is the write channel; name/pubkey alone can verify a
            # peer that landed with empty servers and never loads.
            "servers": ",".join(resolved),
        }
        tunneladdress = str(params.get("tunneladdress") or "")
        if tunneladdress:
            expected["tunneladdress"] = tunneladdress
        result.update(
            await self._apply_and_verify(
                should_apply=bool(params.get("apply")),
                base=WG_CLIENT["get"],
                key="client",
                uuid=uuid,
                expected=expected,
            )
        )
        return result


class DeleteWgPeerTool(_WgWriteBase):
    """Delete a WireGuard peer."""

    name = "delete_wg_peer"
    description = "Delete a WireGuard peer; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Peer uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
                "description": (
                    "Load the change now. Omitted, the peer is removed from "
                    "config and left staged until something else applies it."
                ),
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        `delClientAction` strips the uuid from every instance's `peers` before
        deleting the record, so the back-reference is cleaned by the firmware
        and nothing here should touch `server.peers`.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = str(params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "wg_peer_delete", uuid, str(params.get("confirm") or "")
        ):
            try:
                record = await self._get_record(WG_CLIENT["get"], "client", uuid)
            except Exception as exc:  # noqa: BLE001
                return {"status": "error", "error": redact_keys(exc)}
            token = issue_delete_confirm_token("wg_peer_delete", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "name": str(record.get("name", "")),
                "instances": selected_option_keys(record.get("servers")),
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST",
                f"{WG_CLIENT_WRITE['del']}/{uuid}",
                call_class="write",
                json={},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete WireGuard peer")
            return {"status": "error", "error": redact_keys(exc)}

        result: dict[str, Any] = {"status": "success", "uuid": uuid, "deleted": True}
        if not params.get("apply"):
            result.update(
                {
                    "applied": False,
                    "staged": True,
                    "note": "staged; call again with apply=true to load it",
                }
            )
            return result

        try:
            await run_apply(self.client, WG_RECONFIGURE)
        except ApplyError as exc:
            result.update(
                {"applied": False, "staged": True, "apply_error": redact_keys(exc)}
            )
            return result

        result.update({"applied": True, "staged": False})
        # For a delete the verification is that the record is gone, which is the
        # opposite read from every other tool here: an unknown uuid answers 200
        # with an empty array, so _get_record raising is the success case.
        try:
            await self._get_record(WG_CLIENT["get"], "client", uuid)
        except WgWriteError:
            result["verified"] = True
        except Exception as exc:  # noqa: BLE001
            result["verified"] = False
            result["verify_error"] = redact_keys(exc)
        else:
            result["verified"] = False
            result["verify_error"] = "the peer is still readable after the delete"
        return result


class ToggleWgTool(_WgWriteBase):
    """Enable or disable a WireGuard instance or peer."""

    name = "toggle_wg"
    description = (
        "Enable or disable a WireGuard instance or peer, to an explicit target "
        "state rather than by flipping it; stages by default"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Instance or peer uuid"},
            "kind": {
                "type": "string",
                "enum": ["instance", "peer"],
                "description": "Which record `uuid` names",
            },
            "enabled": {
                "type": "boolean",
                "description": "Target state, set explicitly rather than flipped.",
            },
            "apply": {
                "type": "boolean",
                "optional": True,
                "default": False,
                "description": (
                    "Load the change now. Omitted, the change is written to "
                    "config and left staged until something else applies it."
                ),
            },
        },
        "required": ["uuid", "kind", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the current state, then write the target only if it differs.

        Not `toggleServer`/`toggleClient`: both controller actions declare a
        single parameter, so a target state cannot be passed and the action
        flips whatever it finds. Two callers racing, or one retrying after a
        timeout, would then land on the state they were trying to leave.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = str(params.get("uuid") or "").strip()
        kind = str(params.get("kind") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if kind not in ("instance", "peer"):
            return {"status": "error", "error": "kind must be 'instance' or 'peer'"}
        if "enabled" not in params or params["enabled"] is None:
            return {
                "status": "error",
                "error": "enabled is required; this sets a target state, it does not flip",
            }
        target = "1" if params["enabled"] else "0"

        base, key, write = (
            (WG_SERVER["get"], "server", WG_SERVER_WRITE["set"])
            if kind == "instance"
            else (WG_CLIENT["get"], "client", WG_CLIENT_WRITE["set"])
        )

        try:
            record = await self._get_record(base, key, uuid)
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard record")
            return {"status": "error", "error": redact_keys(exc)}

        current = _stored_value(record.get("enabled"))
        if current == target:
            return {
                "status": "success",
                "uuid": uuid,
                "kind": kind,
                "enabled": bool(params["enabled"]),
                "changed": False,
                "applied": False,
                "staged": False,
                "note": "already in the requested state; nothing was written",
            }

        try:
            flat = merge_for_set(record, {"enabled": target})
            await self._post(f"{write}/{uuid}", key, flat, f"the {kind}")
        except WgWriteError as exc:
            return _write_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to write WireGuard record")
            return {"status": "error", "error": redact_keys(exc)}

        result: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "kind": kind,
            "enabled": bool(params["enabled"]),
            "changed": True,
        }
        result.update(
            await self._apply_and_verify(
                should_apply=bool(params.get("apply")),
                base=base,
                key=key,
                uuid=uuid,
                expected={"enabled": target},
            )
        )
        return result
