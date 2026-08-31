"""WireGuard instances, peers, and drift between config and the running kernel.

Field names come from the firmware model (`OPNsense/Wireguard/Server.xml` and
`Client.xml`) and were confirmed against captured responses, because the two
read paths disagree in ways a normalizer cannot notice. `dns`, `tunneladdress`,
`carp_depend_on` and `peers` are comma-joined strings in a search row and
`{key: {value, selected}}` maps in a get, while the other eighteen fields are
identical in both. So everything here lists from the search grid, and uses a get
only to read one record.

Two names are traps worth stating once. A peer's server-side Allowed-IPs live in
`tunneladdress`; the field literally named `allowed_ips` exists only on servers
and is empty on every row. And `endpoint` means a live `host:port` on a runtime
peer row, the listen port on a runtime interface row, and an empty string on
every config row.

Nothing here writes.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)

WG_SERVER = {
    "search": "/api/wireguard/server/searchServer",
    "get": "/api/wireguard/server/getServer",
}
WG_CLIENT = {
    "search": "/api/wireguard/client/searchClient",
    "get": "/api/wireguard/client/getClient",
}
WG_SERVICE = {"show": "/api/wireguard/service/show"}
CORE_SERVICE = "/api/core/service/search"
INTERFACES = "/api/interfaces/overview/interfaces_info"

# Both read paths return the instance private key in cleartext, so the public
# shape is an allowlist: a field added upstream is omitted rather than leaked.
INSTANCE_PUBLIC = (
    "uuid",
    "name",
    "enabled",
    "instance",
    "interface",
    "port",
    "mtu",
    "gateway",
    "disableroutes",
)
PEER_PUBLIC = ("uuid", "name", "enabled", "keepalive")


# N818 wants an Error suffix. The name is fixed by the spec and by every test
# and tool that imports it, so the rule is silenced here rather than the name
# changed out from under them.
class TruncatedListing(Exception):  # noqa: N818
    """A search returned fewer rows than it says exist."""


def rows_or_refuse(payload: Any, what: str) -> list[dict[str, Any]]:
    """Rows from a search payload, refusing anything short of the whole set.

    `rowCount` is deliberately never sent, and omitting it returns every row, so
    `total` and the row count agree. Asserting that turns a future change in the
    default into a failure rather than a silently short list.
    """
    if not isinstance(payload, dict):
        raise TruncatedListing(
            f"the {what} listing returned {type(payload).__name__}, not a search result"
        )
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise TruncatedListing(f"the {what} listing carries no rows")
    total = payload.get("total")
    if isinstance(total, int) and total != len(rows):
        raise TruncatedListing(
            f"the {what} listing is truncated ({len(rows)} of {total}); refusing "
            f"rather than acting on a partial view"
        )
    return [row for row in rows if isinstance(row, dict)]


def record_or_none(payload: Any, key: str) -> dict[str, Any] | None:
    """The record under *key*, or None.

    An unknown uuid answers HTTP 200 with `[]`: an empty array, not an object
    and not a 404. Nothing in the transport can see that.
    """
    if not isinstance(payload, dict):
        return None
    record = payload.get(key)
    return record if isinstance(record, dict) else None


def get_path(base: str, uuid: str) -> str:
    """The per-record path, refusing an empty uuid.

    `getServer` with no uuid answers 200 with a fully-formed blank template for
    a new instance, so concatenating an empty uuid reads the template and
    reports it as a record.
    """
    if not uuid:
        raise ValueError(
            "uuid is required; an empty uuid reads a blank new-instance template "
            "at HTTP 200"
        )
    return f"{base}/{uuid}"


def split_list(value: Any) -> list[str]:
    """Split a comma-joined list field.

    Raw uuid lists join on ',' and their %-prefixed resolved twins join on ', ',
    so a shared splitter has to strip or every name after the first keeps a
    leading space.
    """
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def selected_keys(node: Any) -> list[str]:
    """Option keys a node map marks selected, dropping the empty-key entry.

    The map enumerates every candidate on the box with membership carried only
    by the flag, so the keys alone report every peer as belonging to every
    instance. An empty list is encoded as one selected node with an empty key,
    which is why the key is checked as well as the flag.
    """
    if not isinstance(node, dict):
        return []
    return [
        key
        for key, option in node.items()
        if key and isinstance(option, dict) and str(option.get("selected", "0")) == "1"
    ]


def is_host_route(entry: str) -> bool:
    """True when the entry addresses one host rather than a network."""
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return network.prefixlen == network.max_prefixlen


def networks_of(entries: list[str]) -> list[Any]:
    """The networks a list of interface-style addresses belongs to.

    An entry with no prefix length becomes a host network, which is what the
    firewall means by it: one instance carries a bare address as its whole
    tunnel address.
    """
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_interface(entry).network)
        except ValueError:
            logger.debug("unreadable tunnel address %r", entry)
    return networks


def public_instance(row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """One instance as a caller sees it. Allowlisted; no key material."""
    public: dict[str, Any] = {field: row.get(field, "") for field in INSTANCE_PUBLIC}
    public["tunnel_addresses"] = split_list(row.get("tunneladdress"))
    public["dns"] = split_list(row.get("dns"))
    public["peer_uuids"] = split_list(row.get("peers"))
    # `%peers` is emitted only when a name differs from the uuid, and is absent
    # rather than empty when nothing resolves. Display only.
    public["peer_names"] = split_list(row.get("%peers", ""))
    public["has_privkey"] = bool(row.get("privkey"))
    public.update(extra)
    return public


def public_peer(row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """One peer as a caller sees it. Allowlisted; no key material."""
    public: dict[str, Any] = {field: row.get(field, "") for field in PEER_PUBLIC}
    # Server-side Allowed-IPs. Not `allowed_ips`, which is a server field and is
    # empty on every row.
    public["allowed_ips"] = split_list(row.get("tunneladdress"))
    public["instance_uuids"] = split_list(row.get("servers"))
    public["instance_names"] = split_list(row.get("%servers", ""))
    public["has_psk"] = bool(row.get("psk"))
    public.update(extra)
    return public


class _WgToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        """The uniform answer when no client was supplied."""
        return {"status": "error", "error": "No client available"}

    async def _search(self, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        """POST a search with no `rowCount`, so the whole set comes back."""
        return await self.client._make_request(
            "POST", endpoint, json=body if body is not None else {}
        )


def instance_shape(
    row: dict[str, Any], peers: list[dict[str, Any]]
) -> tuple[str, list[str]]:
    """A label for a human reader, always returned with its evidence.

    Never used as a gate anywhere. A site-to-site instance and a road-warrior
    one differ only in how they happen to be configured, so a wrong guess must
    not change what any check does.
    """
    evidence: list[str] = []
    if str(row.get("disableroutes", "")) == "1":
        evidence.append("disableroutes=1")
    if row.get("gateway"):
        evidence.append(f"gateway={row['gateway']}")
    wide = [
        entry
        for peer in peers
        for entry in split_list(peer.get("tunneladdress"))
        if not is_host_route(entry)
    ]
    if wide:
        evidence.append(f"peer networks {', '.join(sorted(wide))}")
    if evidence:
        return "site_to_site", evidence
    if peers:
        return "road_warrior", [f"{len(peers)} peers, all host routes"]
    return "unknown", ["no resolvable peers"]


class ListWgInstancesTool(_WgToolBase):
    """List WireGuard instances, config joined to runtime state."""

    name = "list_wg_instances"
    description = (
        "List WireGuard instances with their tunnel addresses, peers and running state"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Only the instance with this name",
                "optional": True,
            },
        },
        "required": [],
    }

    async def _running_uuids(self) -> set[str]:
        """Server uuids the service manager reports as running.

        `/api/wireguard/service/status` cannot answer this: the plugin declares
        no configd status action, so it returns the literal string "unknown"
        while the interface is up and moving traffic. The core service grid
        embeds the server uuid in its row id and is the reliable signal.
        """
        payload = await self._search(CORE_SERVICE)
        running = set()
        for row in rows_or_refuse(payload, "services"):
            identifier = str(row.get("id", ""))
            if identifier.startswith("wireguard/") and str(row.get("running")) == "1":
                running.add(identifier.split("/", 1)[1])
        return running

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """List instances, or the one named."""
        params = params or {}
        if not self.client:
            return self._no_client()
        try:
            servers = rows_or_refuse(
                await self._search(WG_SERVER["search"]), "wireguard instances"
            )
            clients = rows_or_refuse(
                await self._search(WG_CLIENT["search"]), "wireguard peers"
            )
            running = await self._running_uuids()
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard instances")
            return {"status": "error", "error": str(exc)}

        by_uuid = {str(c.get("uuid", "")): c for c in clients}
        wanted = str(params.get("name") or "")

        instances = []
        for row in servers:
            if wanted and row.get("name") != wanted:
                continue
            peer_uuids = split_list(row.get("peers"))
            members = [by_uuid[u] for u in peer_uuids if u in by_uuid]
            shape, evidence = instance_shape(row, members)
            instances.append(
                public_instance(
                    row,
                    dangling_peers=[u for u in peer_uuids if u not in by_uuid],
                    running=str(row.get("uuid", "")) in running,
                    shape=shape,
                    shape_evidence=evidence,
                )
            )

        return {"status": "success", "count": len(instances), "instances": instances}


def runtime_by_name(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Kernel peer state keyed by peer name.

    `service/show` returns one array holding two row schemas discriminated by
    `type`, and the missing keys are absent rather than empty. The interface row
    carries peer-status 'offline' and a name that looks like a peer's, so it has
    to be filtered out before anything else reads the array.

    Kernel rows carry no uuid, so name is the only join back to a config row.
    """
    runtime = {}
    for row in rows:
        if row.get("type") != "peer":
            continue
        handshake = row.get("latest-handshake") or 0
        runtime[str(row.get("name", ""))] = {
            "device": row.get("if", ""),
            "endpoint": row.get("endpoint", ""),
            "kernel_allowed_ips": split_list(row.get("allowed-ips")),
            "handshake_epoch": handshake,
            "handshake_age": row.get("latest-handshake-age"),
            "transfer_rx": row.get("transfer-rx", 0),
            "transfer_tx": row.get("transfer-tx", 0),
            # The only field that separates a peer which has never connected
            # from one that connected and went idle. Transfer counters do not:
            # every never-connected peer here has a non-zero tx.
            "connected": bool(handshake),
            # Reported, not interpreted. Only two of the three values were ever
            # observed, so the enum is not encoded anywhere.
            "peer_status_raw": row.get("peer-status", ""),
        }
    return runtime


class ListWgPeersTool(_WgToolBase):
    """List WireGuard peers, config joined to runtime state."""

    name = "list_wg_peers"
    description = (
        "List WireGuard peers with their server-side allowed IPs, instance "
        "membership and last handshake"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "instance": {
                "type": "string",
                "description": "Only peers of this instance, by name or uuid",
                "optional": True,
            },
            "name": {
                "type": "string",
                "description": "Only the peer with this name",
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """List peers, optionally narrowed to one instance."""
        params = params or {}
        if not self.client:
            return self._no_client()
        wanted_instance = str(params.get("instance") or "")
        wanted_name = str(params.get("name") or "")

        try:
            servers = rows_or_refuse(
                await self._search(WG_SERVER["search"]), "wireguard instances"
            )
            body: dict[str, Any] = {}
            if wanted_instance:
                # `servers` is the filter key and must be an array. `server_uuid`
                # is accepted and ignored, and a bare string returns HTTP 500.
                match = [
                    str(s.get("uuid", ""))
                    for s in servers
                    if wanted_instance in (s.get("name", ""), s.get("uuid", ""))
                ]
                body["servers"] = match
            clients = rows_or_refuse(
                await self._search(WG_CLIENT["search"], body), "wireguard peers"
            )
            show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        except TruncatedListing as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read WireGuard peers")
            return {"status": "error", "error": str(exc)}

        enabled = {
            str(s.get("uuid", "")): str(s.get("enabled", "0")) == "1" for s in servers
        }
        runtime = runtime_by_name(show)

        peers = []
        for row in clients:
            if wanted_name and row.get("name") != wanted_name:
                continue
            name = str(row.get("name", ""))
            state = runtime.get(name)
            absent = ""
            if state is None:
                members = split_list(row.get("servers"))
                if members and not any(enabled.get(u, False) for u in members):
                    absent = "every instance this peer belongs to is disabled"
                else:
                    absent = "no kernel peer with this name"
            peers.append(public_peer(row, runtime=state, runtime_absent=absent))

        return {
            "status": "success",
            "count": len(peers),
            "peers": peers,
            "note": (
                "Allowed IPs here are the addresses belonging to each peer, which "
                "fixes routing to that peer. What a peer sends through the tunnel "
                "lives in its own client config, which this API cannot read."
            ),
        }
