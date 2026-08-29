"""Execute a `plan_dns_ula` mapping: add the ULA record, read it back, delete the GUA one.

`plan_dns_ula` reads and proposes; it changes nothing on purpose. Carrying the
mapping out by hand is one create and one delete per record — 54 records for a
single VLAN on this firewall, so roughly 108 calls with no record of how far it
got. This is that loop, with the two properties the hand-run version cannot
have: it refuses to touch a record that no longer matches the plan, and it
never removes an answer before its replacement has been read back.

Order, per record
-----------------

    read the GUA record  ->  add the ULA record  ->  read the ULA record back
                                                 ->  delete the GUA record

The delete is gated on the read-back, not on the add returning ok. An add that
returns 200 is evidence the request was accepted, not that the record exists;
`ApplyUlaTool` shipped that exact confusion once already. If the read-back does
not find the ULA record at the address the plan asked for, the GUA record is
the only answer left for that name, and deleting it would take the name off the
network. So the run stops there with the add reported and the delete not
issued.

Where the reconfigure happens, and why
--------------------------------------

Once, at the end, and only if something was written.

Unbound reloads its whole configuration on `service/reconfigure`. Doing it per
record means 54 reloads instead of one, each a brief resolution gap on a box
that is answering for the entire site, and it turns a seconds-long operation
into a minutes-long one. Nothing about correctness needs it sooner: the add,
the read-back and the delete all go against the configuration store, which is
what the read-back gate reads, so the gate is just as strong with the reload
deferred.

What deferring the reload does *not* buy is a period where both answers are
served. The two records coexist in the configuration store during the run, but
a single reload publishes the additions and the removals at the same moment.
That is deliberate: a served-zone overlap would need a reload between the add
pass and the delete pass plus a wait longer than the records' TTL, which is an
operator's decision about a maintenance window, not something a single tool
call should sit and block on. What actually protects a client holding a cached
GUA answer is that the delegated address keeps working — the VIP and NPT rules
from `ipv6_stack` — not the presence of the override.

If the run stops partway, whatever was written before the stop is still
reloaded. Leaving a record written but unserved is a third state, which is the
one thing worse than stopping.

No rollback
-----------

If a record fails, earlier records stay moved. Undoing them would mean issuing
more writes down a path that has already proved unreliable, and a half-undone
undo is a state nobody planned for. The result says what landed, what failed
and what was never attempted instead.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from opnsense_mcp.tools.ula_migration import UNBOUND
from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.mvc_merge import flatten_mvc_node

logger = logging.getLogger(__name__)

# `ula_migration.UNBOUND` covers search, get, set and reconfigure. The create
# and delete endpoints are not in it because nothing there creates or deletes.
UNBOUND_ADD = "/api/unbound/settings/addHostOverride"
UNBOUND_DEL = "/api/unbound/settings/delHostOverride"

AAAA = "AAAA"

# Per-record outcomes. A caller distinguishing "did not move" from "was never
# tried" needs these to be separate values, not two shades of one.
OUTCOME_MOVED = "moved"
OUTCOME_WOULD_MOVE = "would_move"
OUTCOME_SKIPPED = "skipped"
OUTCOME_FAILED = "failed"
OUTCOME_NOT_ATTEMPTED = "not_attempted"

OUTCOMES: tuple[str, ...] = (
    OUTCOME_MOVED,
    OUTCOME_WOULD_MOVE,
    OUTCOME_SKIPPED,
    OUTCOME_FAILED,
    OUTCOME_NOT_ATTEMPTED,
)

# Reason codes. Structured, because asserting on message wording is how four
# assertions in this repo passed for the wrong reason.
REASON_KEEP_GUA = "keep_gua"
REASON_INVALID_RECORD = "invalid_plan_record"
REASON_DRIFTED = "plan_drifted"
REASON_ALREADY_MOVED = "already_moved"
REASON_GUA_MISSING = "gua_record_not_found"
REASON_READBACK_FAILED = "ula_readback_failed"
REASON_ADD_NO_UUID = "add_returned_no_uuid"
REASON_DELETE_REJECTED = "gua_delete_rejected"
REASON_API_ERROR = "api_error"
# The plan asks to move a record onto the address it already holds. Acting on
# it deletes the name's only answer: the resume path finds the record itself
# as its own replacement, the read-back gate passes because it is genuinely
# the right name at the right address, and the delete removes it.
REASON_NO_OP_MOVE = "current_equals_proposed"

# What `delHostOverride` says when it worked. Mirrors `rmdns`.
_DELETE_OK = ("deleted", "ok", 1)


def _fqdn(hostname: Any, domain: Any) -> str:
    """Join a host override's two name halves the way `plan_dns_ula` does."""
    return f"{str(hostname or '').strip()}.{str(domain or '').strip()}".strip(
        "."
    ).lower()


def _parse_v6(value: Any) -> ipaddress.IPv6Address | None:
    """Parse an IPv6 address, refusing anything carrying a scope id.

    `ipaddress` accepts a scope id and validates almost nothing inside it, so
    `fe80::1%$(reboot)` parses cleanly. That has already been mistaken here for
    proof that an address is safe to hand onward. A host override address never
    legitimately carries one, so the `%` is rejected before parsing rather than
    trusted to fail.
    """
    text = str(value or "").strip()
    if not text or "%" in text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv6Address) else None


class _Planned:
    """One plan record, normalised, with the reason it cannot be acted on."""

    __slots__ = ("current", "domain", "fqdn", "hostname", "proposed", "skip", "uuid")

    def __init__(self, record: Any) -> None:
        """Normalise one entry of `plan_dns_ula`'s `records` list."""
        record = record if isinstance(record, dict) else {}
        self.uuid = str(record.get("uuid") or "").strip()
        self.hostname = str(record.get("hostname") or "").strip()
        self.domain = str(record.get("domain") or "").strip()
        self.fqdn = _fqdn(self.hostname, self.domain)
        self.current = _parse_v6(record.get("current"))
        self.proposed = _parse_v6(record.get("proposed"))
        self.skip: str | None = None

        if record.get("keep_gua"):
            # The plan already decided this name answers to the outside world.
            self.skip = REASON_KEEP_GUA
        elif not self.uuid or not self.hostname or not self.domain:
            self.skip = REASON_INVALID_RECORD
        elif self.current is None or self.proposed is None:
            # Recomputing a missing target here would mean acting on something
            # the operator never reviewed.
            self.skip = REASON_INVALID_RECORD
        elif self.current == self.proposed:
            # Gate one of three. A move to the address already held is not a
            # move, and every downstream check passes it: the record resolves
            # as its own replacement and the read-back confirms the right name
            # at the right address, so the delete takes the only answer away.
            self.skip = REASON_NO_OP_MOVE

    def result(self, outcome: str, **extra: Any) -> dict[str, Any]:
        """A per-record result carrying the plan's own view of the record."""
        return {
            "uuid": self.uuid,
            "fqdn": self.fqdn,
            "from": str(self.current) if self.current else "",
            "to": str(self.proposed) if self.proposed else "",
            "outcome": outcome,
            **extra,
        }


class ApplyDnsUlaTool:
    """Execute a `plan_dns_ula` mapping, one record at a time."""

    name = "apply_dns_ula"
    description = (
        "Execute a plan_dns_ula mapping: for each record add the ULA host "
        "override, read it back, then delete the GUA one. Refuses any record "
        "that no longer matches the plan. Dry run by default."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "records": {
                "type": "array",
                "description": (
                    "The `records` list from a plan_dns_ula result, verbatim. "
                    "Each entry needs uuid, hostname, domain, current, "
                    "proposed and keep_gua. Targets are never recomputed here, "
                    "so what runs is what was reviewed."
                ),
            },
            "dry_run": {
                "type": "boolean",
                "description": (
                    "Re-read every record and report what would happen without "
                    "writing anything (default true). Set false to move them."
                ),
                "optional": True,
                "default": True,
            },
        },
        "required": ["records"],
    }

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    async def _existing_aaaa(self) -> dict[tuple[str, str], str]:
        """Map (fqdn, address) to uuid for every AAAA override on the box.

        This is what makes a second run a set of skips rather than a set of
        duplicate records.
        """
        data = await self.client._make_request(
            "POST", UNBOUND["search"], json={"current": 1, "rowCount": 5000}
        )
        rows = data.get("rows", []) if isinstance(data, dict) else []
        index: dict[tuple[str, str], str] = {}
        for row in rows:
            if row.get("rr") != AAAA:
                continue
            address = _parse_v6(row.get("server"))
            if address is None:
                continue
            index.setdefault(
                (_fqdn(row.get("hostname"), row.get("domain")), str(address)),
                str(row.get("uuid") or ""),
            )
        return index

    async def _read(self, uuid: str) -> dict[str, str] | None:
        """Fetch one host override, flattened for a `set*`-shaped payload.

        Returns None when the uuid is unknown: OPNsense answers that with an
        empty list rather than an error status.
        """
        current = await self.client._make_request("GET", f"{UNBOUND['get']}/{uuid}")
        node = current.get("host") if isinstance(current, dict) else None
        if not isinstance(node, dict):
            return None
        return flatten_mvc_node(node)

    @staticmethod
    def _matches(
        flat: dict[str, str], fqdn: str, address: ipaddress.IPv6Address
    ) -> bool:
        """Whether a fetched record is that name answering with that address.

        Addresses are compared as parsed addresses. A substring comparison here
        would let `2001:db8::1` satisfy a check for `2001:db8::10`, which is a
        mistake this repository has already shipped once.
        """
        found = _parse_v6(flat.get("server"))
        return (
            found is not None
            and found == address
            and _fqdn(flat.get("hostname"), flat.get("domain")) == fqdn
            and flat.get("rr") == AAAA
        )

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Move each planned record, stopping at the first one that fails.

        `status` says whether the run happened, not what it found: a run in
        which every record had drifted is a success with that many skips.
        Severity lives in `counts`, `stopped_at` and the per-record `reason`.
        """
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        records = params.get("records")
        if not isinstance(records, list) or not records:
            return {
                "status": "error",
                "error": (
                    "records is required: pass the `records` list from a "
                    "plan_dns_ula result. This tool does not compute its own "
                    "targets."
                ),
            }

        dry_run = bool(params.get("dry_run", True))
        planned = [_Planned(record) for record in records]

        existing: dict[tuple[str, str], str] = {}
        if any(entry.skip is None for entry in planned):
            try:
                existing = await self._existing_aaaa()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to read host overrides")
                return {"status": "error", "error": str(exc)}

        results: list[dict[str, Any]] = []
        stopped_at: dict[str, Any] | None = None
        wrote = False

        for index, entry in enumerate(planned):
            if stopped_at is not None:
                results.append(entry.result(OUTCOME_NOT_ATTEMPTED))
                continue
            if entry.skip is not None:
                results.append(entry.result(OUTCOME_SKIPPED, reason=entry.skip))
                continue

            proposed = entry.proposed
            if proposed is None:  # pragma: no cover - _Planned already skipped it
                results.append(
                    entry.result(OUTCOME_SKIPPED, reason=REASON_INVALID_RECORD)
                )
                continue
            ula_uuid = existing.get((entry.fqdn, str(proposed)))
            if ula_uuid == entry.uuid:
                # Gate two of three. The index is built over every AAAA record
                # including the one this entry is about to delete, so a record
                # can resolve as its own replacement. Independent of gate one
                # because the index is keyed on the live address, not the
                # plan's: a record that drifted onto its own target reaches
                # here with current != proposed.
                results.append(entry.result(OUTCOME_SKIPPED, reason=REASON_NO_OP_MOVE))
                continue

            try:
                gua = await self._read(entry.uuid)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to re-read host override %s", entry.uuid)
                results.append(
                    entry.result(
                        OUTCOME_FAILED, reason=REASON_API_ERROR, detail=str(exc)
                    )
                )
                stopped_at = self._stop(index, entry, REASON_API_ERROR)
                continue

            if gua is None:
                # Gone since the plan was taken. If the ULA answer is already
                # there, a previous run finished this one.
                reason = REASON_ALREADY_MOVED if ula_uuid else REASON_GUA_MISSING
                results.append(
                    entry.result(
                        OUTCOME_SKIPPED, reason=reason, ula_uuid=ula_uuid or ""
                    )
                )
                continue

            found_address = _parse_v6(gua.get("server"))
            found_fqdn = _fqdn(gua.get("hostname"), gua.get("domain"))
            if (
                found_address != entry.current
                or found_fqdn != entry.fqdn
                or gua.get("rr") != AAAA
            ):
                # Refusing means leaving it alone. Rewriting it to match the
                # plan would silently overwrite whatever the change was for.
                results.append(
                    entry.result(
                        OUTCOME_SKIPPED,
                        reason=REASON_DRIFTED,
                        expected=str(entry.current),
                        found=str(found_address) if found_address else "",
                        expected_fqdn=entry.fqdn,
                        found_fqdn=found_fqdn,
                        found_rr=gua.get("rr", ""),
                    )
                )
                continue

            if dry_run:
                results.append(
                    entry.result(
                        OUTCOME_WOULD_MOVE,
                        resumed=ula_uuid is not None,
                        ula_uuid=ula_uuid or "",
                    )
                )
                continue

            record_wrote, stop_reason = await self._move(entry, gua, ula_uuid, results)
            wrote = wrote or record_wrote
            if stop_reason is not None:
                stopped_at = self._stop(index, entry, stop_reason)

        counts = dict.fromkeys(OUTCOMES, 0)
        for result in results:
            counts[result["outcome"]] += 1

        reconfigure: dict[str, Any] = {
            "ran": False,
            "reason": "dry_run" if dry_run else "no_changes",
        }
        if wrote and not dry_run:
            try:
                # run_apply, not a bare request: the client raises only on
                # {"result": "failed"}, while a service controller answers with
                # {"status": ...}. A configd refusal arrives as HTTP 200 and was
                # reported here as ok -- on the run that had just deleted every
                # GUA record from the configuration store.
                await run_apply(self.client, UNBOUND["reconfigure"])
                reconfigure = {"ran": True, "ok": True}
            except ApplyError as exc:
                logger.warning("Unbound reconfigure did not complete: %s", exc)
                reconfigure = {"ran": True, "ok": False, "error": str(exc)}

        failed_reload = reconfigure["ran"] and not reconfigure.get("ok")
        payload: dict[str, Any] = {
            "status": ("partial_failure" if stopped_at or failed_reload else "success"),
            "dry_run": dry_run,
            "applied": reconfigure.get("ok") is True,
            "changed": counts[OUTCOME_MOVED],
            "counts": counts,
            "reconfigure": reconfigure,
            "results": results,
        }
        if stopped_at is not None:
            payload["stopped_at"] = stopped_at
            payload["recovery"] = (
                "Nothing was rolled back. Records before the stop stayed moved "
                "and were reloaded. Fix the cause and re-run with the same "
                "plan: records already moved come back as skips."
            )
        return payload

    @staticmethod
    def _stop(index: int, entry: _Planned, reason: str) -> dict[str, Any]:
        """Where the run stopped, in the caller's own terms."""
        return {
            "index": index,
            "uuid": entry.uuid,
            "fqdn": entry.fqdn,
            "reason": reason,
        }

    async def _move(
        self,
        entry: _Planned,
        gua: dict[str, str],
        ula_uuid: str | None,
        results: list[dict[str, Any]],
    ) -> tuple[bool, str | None]:
        """Add, read back, delete. Appends one result; returns (wrote, stop).

        `wrote` says whether any write request was issued for this record, so
        the caller knows whether a reload is owed even when the record failed.
        `stop` is the reason to abandon the rest of the run, or None.

        *gua* is the record as it was just re-read, so the new record is that
        record with a different address rather than a freshly invented stub:
        description, ttl and addptr carry across.
        """
        proposed = entry.proposed
        if proposed is None:  # pragma: no cover - _Planned already skipped it
            return False, REASON_INVALID_RECORD
        added = False
        wrote = False

        if ula_uuid is None:
            payload = dict(gua)
            payload["server"] = str(proposed)
            try:
                response = await self.client._make_request(
                    "POST", UNBOUND_ADD, call_class="write", json={"host": payload}
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to add ULA override for %s", entry.fqdn)
                results.append(
                    entry.result(
                        OUTCOME_FAILED,
                        reason=REASON_API_ERROR,
                        detail=str(exc),
                        added=False,
                        verified=False,
                        deleted=False,
                    )
                )
                return True, REASON_API_ERROR
            wrote = True
            added = True
            ula_uuid = str((response or {}).get("uuid") or "").strip()
            if not ula_uuid:
                # Without a uuid there is nothing to read back, so there is no
                # gate, so the delete does not happen.
                results.append(
                    entry.result(
                        OUTCOME_FAILED,
                        reason=REASON_ADD_NO_UUID,
                        added=True,
                        verified=False,
                        deleted=False,
                    )
                )
                return True, REASON_ADD_NO_UUID

        try:
            back = await self._read(ula_uuid)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read back ULA override for %s", entry.fqdn)
            results.append(
                entry.result(
                    OUTCOME_FAILED,
                    reason=REASON_READBACK_FAILED,
                    detail=str(exc),
                    added=added,
                    verified=False,
                    deleted=False,
                    ula_uuid=ula_uuid,
                )
            )
            return wrote, REASON_READBACK_FAILED

        if back is None or not self._matches(back, entry.fqdn, proposed):
            # The add was accepted and the record is not there, or not there at
            # the address asked for. The GUA record is now the only answer for
            # this name, so it stays.
            results.append(
                entry.result(
                    OUTCOME_FAILED,
                    reason=REASON_READBACK_FAILED,
                    added=added,
                    verified=False,
                    deleted=False,
                    ula_uuid=ula_uuid,
                    found=str(_parse_v6(back.get("server")) or "") if back else "",
                )
            )
            return wrote, REASON_READBACK_FAILED

        try:
            response = await self.client._make_request(
                "POST", f"{UNBOUND_DEL}/{entry.uuid}", call_class="write"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete GUA override for %s", entry.fqdn)
            results.append(
                entry.result(
                    OUTCOME_FAILED,
                    reason=REASON_API_ERROR,
                    detail=str(exc),
                    added=added,
                    verified=True,
                    deleted=False,
                    ula_uuid=ula_uuid,
                )
            )
            return True, REASON_API_ERROR

        wrote = True
        if (response or {}).get("result") not in _DELETE_OK:
            # Both answers now exist. Saying only "failed" would hide that.
            results.append(
                entry.result(
                    OUTCOME_FAILED,
                    reason=REASON_DELETE_REJECTED,
                    detail=str(response),
                    added=added,
                    verified=True,
                    deleted=False,
                    ula_uuid=ula_uuid,
                )
            )
            return True, REASON_DELETE_REJECTED

        results.append(
            entry.result(
                OUTCOME_MOVED,
                added=added,
                resumed=not added,
                verified=True,
                deleted=True,
                ula_uuid=ula_uuid,
            )
        )
        return True, None
