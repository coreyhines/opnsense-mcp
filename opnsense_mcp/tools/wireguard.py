"""WireGuard instances, peers, and drift between config and the running kernel.

Field names come from the firmware model (`OPNsense/Wireguard/Server.xml` and
`Client.xml`) and were confirmed against captured responses, because the two
read paths disagree in ways a normalizer cannot notice. `dns`, `tunneladdress`,
`carp_depend_on` and `peers` are comma-joined strings in a search row and
`{key: {value, selected}}` maps in a get, while the other eighteen fields are
identical in both. So everything here lists from the search grid. The get path
(`WG_SERVER["get"]`, `get_path`, `record_or_none`, `selected_option_keys`) is
characterised by tests against a captured `getServer`, but no tool calls it
yet: nothing here reads a single record.

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
import re
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

# Key material never belongs in an error string either. The transport folds a
# response body into the exception text by design, so a body with no named
# message key arrives here whole. Same predicate as tests/test_no_key_material.
_KEY_SHAPED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
REDACTED = "<redacted key>"


def redact_keys(text: Any) -> str:
    """*text* with anything shaped like a Curve25519 key replaced."""
    # PHP's json_encode escapes '/', so a key can arrive spelled `a\/b`. The
    # escape is undone first or the character class stops at the backslash.
    return _KEY_SHAPED.sub(REDACTED, str(text).replace("\\/", "/"))


class TruncatedListingError(Exception):
    """A search returned fewer rows than it says exist."""


def rows_or_refuse(payload: Any, what: str) -> list[dict[str, Any]]:
    """Rows from a search payload, refusing anything short of the whole set.

    `rowCount` is deliberately never sent, and omitting it returns every row, so
    `total` and the row count agree. Asserting that turns a future change in the
    default into a failure rather than a silently short list.
    """
    if not isinstance(payload, dict):
        raise TruncatedListingError(
            f"the {what} listing returned {type(payload).__name__}, not a search result"
        )
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise TruncatedListingError(f"the {what} listing carries no rows")
    total = payload.get("total")
    if isinstance(total, int) and total != len(rows):
        raise TruncatedListingError(
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


def selected_option_keys(node: Any) -> list[str]:
    """Option keys a node map marks selected, dropping the empty-key entry.

    Named apart from `utils.mvc_merge.selected_keys`, which has a different
    contract: it comma-joins and keeps the empty-key sentinel, which is what a
    `set*` POST wants and the opposite of what membership needs.

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


def bare_networks(entries: list[str]) -> list[Any]:
    """The networks of the entries that carry no prefix length.

    Those entries state an address, not a network, so nothing can be judged
    contained in them: `networks_of` turns one into a host network and every
    peer of that instance then reads as outside its own tunnel. Kept separate so
    containment can say so rather than report drift it cannot know about.
    """
    return networks_of([entry for entry in entries if "/" not in entry])


# The computed fields each public shape accepts. `**extra` is allowlisted for
# the same reason the row fields are: without it, one caller splatting a raw row
# puts the private key straight back into the output the allowlist above exists
# to keep it out of.
INSTANCE_EXTRA = frozenset(
    {
        "dangling_peers",
        "running",
        "running_signal",
        "device_status",
        "running_disagrees",
        "shape",
        "shape_evidence",
    }
)
PEER_EXTRA = frozenset({"runtime", "runtime_absent", "runtime_absent_reason"})


def _computed(extra: dict[str, Any], allowed: frozenset[str], what: str) -> dict:
    """The extras a public shape declares, dropping anything else."""
    unknown = sorted(set(extra) - allowed)
    if unknown:
        logger.warning("dropping undeclared %s field(s) %s", what, ", ".join(unknown))
    return {key: value for key, value in extra.items() if key in allowed}


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
    public.update(_computed(extra, INSTANCE_EXTRA, "instance"))
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
    public.update(_computed(extra, PEER_EXTRA, "peer"))
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
            "uuid": {
                "type": "string",
                "description": "Only the instance with this uuid",
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
            show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        except TruncatedListingError as exc:
            return {"status": "error", "error": redact_keys(exc)}
        except Exception as exc:  # noqa: BLE001
            # Not `logger.exception`: the traceback carries the same body the
            # message does, and only the message can be redacted.
            logger.error("Failed to read WireGuard instances: %s", redact_keys(exc))
            return {"status": "error", "error": redact_keys(exc)}

        by_uuid = {str(c.get("uuid", "")): c for c in clients}
        wanted = str(params.get("name") or "")
        wanted_uuid = str(params.get("uuid") or "")
        # The one independent signal for `running`. The core-service row id is
        # an uncaptured shape, so a change in it silently reports every
        # instance as stopped; the interface row's status is what says so.
        status_by_device = {
            str(row.get("if", "")): str(row.get("status", ""))
            for row in show
            if row.get("type") == "interface"
        }

        instances = []
        for row in servers:
            if wanted and row.get("name") != wanted:
                continue
            if wanted_uuid and str(row.get("uuid", "")) != wanted_uuid:
                continue
            peer_uuids = split_list(row.get("peers"))
            members = [by_uuid[u] for u in peer_uuids if u in by_uuid]
            shape, evidence = instance_shape(row, members)
            is_running = str(row.get("uuid", "")) in running
            device_status = status_by_device.get(str(row.get("interface", "")), "")
            instances.append(
                public_instance(
                    row,
                    dangling_peers=[u for u in peer_uuids if u not in by_uuid],
                    running=is_running,
                    running_signal=CORE_SERVICE,
                    device_status=device_status,
                    running_disagrees=bool(device_status)
                    and is_running != (device_status == "up"),
                    shape=shape,
                    shape_evidence=evidence,
                )
            )

        return {"status": "success", "count": len(instances), "instances": instances}


def runtime_by_peer(
    rows: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Kernel peer state keyed by (device, peer name).

    `service/show` returns one array holding two row schemas discriminated by
    `type`, and the missing keys are absent rather than empty. The interface row
    carries peer-status 'offline' and a name that looks like a peer's, so it has
    to be filtered out before anything else reads the array.

    Keyed on the device as well as the name. Kernel rows carry no uuid, and
    peer names are unique per instance at most: two same-named peers on two
    instances collapse under a name-only key, and the survivor is then reported
    as the live state of a peer on a device it is not on. The public key is on
    both sides and would be the better join, but every captured fixture
    redacts it to one placeholder, so it cannot be tested here.
    """
    runtime: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if row.get("type") != "peer":
            continue
        handshake = row.get("latest-handshake") or 0
        device = str(row.get("if", ""))
        endpoint = str(row.get("endpoint", ""))
        runtime[device, str(row.get("name", ""))] = {
            "device": device,
            # `wg show` writes "(none)" for a peer that has never been reached,
            # and a non-empty string reads as an endpoint to every caller.
            "endpoint": "" if endpoint == "(none)" else endpoint,
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
            match: list[str] = []
            if wanted_instance:
                # `servers` is the filter key and must be an array. `server_uuid`
                # is accepted and ignored, and a bare string returns HTTP 500.
                match = [
                    str(s.get("uuid", ""))
                    for s in servers
                    if wanted_instance in (s.get("name", ""), s.get("uuid", ""))
                ]
                if not match:
                    # An empty array is the grid's idiom for "no filter", so a
                    # name that resolves to nothing would return every peer on
                    # the firewall and report them as this instance's.
                    return {
                        "status": "error",
                        "error": (
                            f"no WireGuard instance is named {wanted_instance!r}; "
                            f"refusing rather than sending an empty filter, which "
                            f"asks for every peer on the firewall"
                        ),
                    }
                body["servers"] = match
            clients = rows_or_refuse(
                await self._search(WG_CLIENT["search"], body), "wireguard peers"
            )
            show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        except TruncatedListingError as exc:
            return {"status": "error", "error": redact_keys(exc)}
        except Exception as exc:  # noqa: BLE001
            # Not `logger.exception`: see ListWgInstancesTool.
            logger.error("Failed to read WireGuard peers: %s", redact_keys(exc))
            return {"status": "error", "error": redact_keys(exc)}

        enabled = {
            str(s.get("uuid", "")): str(s.get("enabled", "0")) == "1" for s in servers
        }
        device_of = {
            str(s.get("uuid", "")): str(s.get("interface", "")) for s in servers
        }
        runtime = runtime_by_peer(show)

        # Narrowed again here, on the rows that came back. Unknown parameters
        # are accepted and ignored on every grid, so a filter the firewall did
        # not apply is invisible in a 200 and the whole box would be reported as
        # one instance's peers.
        wanted_uuids = set(match)

        peers = []
        for row in clients:
            if wanted_uuids and not wanted_uuids & set(split_list(row.get("servers"))):
                continue
            if wanted_name and row.get("name") != wanted_name:
                continue
            name = str(row.get("name", ""))
            members = split_list(row.get("servers"))
            # Only the devices this peer's own instances carry. A name-keyed
            # lookup would hand it the state of a same-named peer elsewhere.
            state = next(
                (
                    runtime[device_of[u], name]
                    for u in members
                    if (device_of.get(u, ""), name) in runtime
                ),
                None,
            )
            absent = ""
            reason = ""
            if state is None:
                if members and not any(enabled.get(u, False) for u in members):
                    reason = "instance_disabled"
                    absent = "every instance this peer belongs to is disabled"
                else:
                    reason = "no_kernel_peer"
                    absent = "no kernel peer with this name on this peer's devices"
            peers.append(
                public_peer(
                    row,
                    runtime=state,
                    runtime_absent=absent,
                    runtime_absent_reason=reason,
                )
            )

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


def classify_entry(
    entry: str,
    networks: list[Any],
    bare: list[Any] | None = None,
    has_instance: bool = True,
) -> tuple[str, str]:
    """Classify one server-side allowed-IP entry against its instance networks.

    Prefix width carries the meaning, not membership alone. A host route belongs
    to the peer and must sit inside the tunnel network; anything wider is a
    network routed through the tunnel and is expected to sit outside it. Without
    that distinction a site-to-site instance's remote LAN reads as drift, and
    the only alternative is an exception carved out for one instance.

    *bare* names the networks that came from a tunnel address written with no
    prefix length. An entry whose whole family is bare is unjudgeable, not
    drifted: one instance here carries `192.168.11.1` as its entire tunnel
    address, and measuring peers against the resulting /32 reports every one of
    them as a host route outside its own tunnel.
    """
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError as exc:
        return "unreadable_address", f"{entry!r} is not a network: {exc}"

    bare = bare or []
    family = [n for n in networks if n.version == network.version]
    if not family:
        return (
            "no_interface",
            (
                f"the instance carries no IPv{network.version} tunnel address, "
                f"so {entry} cannot be judged"
            )
            if has_instance
            else (
                f"this peer belongs to no instance that exists, so {entry} "
                f"cannot be judged"
            ),
        )
    if any(network.subnet_of(n) for n in family):
        return "current", ""
    carried = ", ".join(str(n) for n in family)
    if all(n in bare for n in family):
        return (
            "no_prefix_length",
            f"the instance's IPv{network.version} tunnel address carries no "
            f"prefix length, so {carried} states an address rather than a "
            f"network and {entry} cannot be judged against it",
        )
    if network.prefixlen == network.max_prefixlen:
        return "drifted", f"{entry} is a host route outside {carried}"
    return (
        "routed_prefix",
        f"{entry} is a network routed through the tunnel rather than an address "
        f"on it; its path depends on {carried} and the static routes",
    )


def _parses(entry: str) -> bool:
    """True when the entry reads as an address with an optional prefix length."""
    try:
        ipaddress.ip_interface(entry)
    except ValueError:
        return False
    return True


def _as_network(destination: str) -> Any:
    """A route destination or allowed IP as a network.

    Route destinations omit the prefix length on host routes, so a bare address
    means the family maximum rather than a parse failure.
    """
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return None


def _networks_and_rest(entries: list[str]) -> tuple[set[Any], list[str]]:
    """The entries that read as networks, and the raw strings that do not."""
    networks: set[Any] = set()
    unreadable: list[str] = []
    for entry in entries:
        network = _as_network(entry)
        if network is None:
            unreadable.append(entry)
        else:
            networks.add(network)
    return networks, unreadable


class ReconcileWgTool(_WgToolBase):
    """Report where the stored WireGuard config and the running kernel disagree.

    Report only. Nothing here writes, so `status` says whether the audit ran and
    every finding lives in the payload: a caller cannot otherwise tell an audit
    that found problems from one that failed to look.
    """

    name = "reconcile_wg"
    description = (
        "Report drift between WireGuard config and the running kernel: peer "
        "addresses outside their tunnel network, interface addresses no config "
        "accounts for, and routes that do not match the loaded allowed IPs"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def _read(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:
        """The four reads every check runs on: servers, clients, kernel, devices.

        Reads only. Nothing in this tool may reach a write or a service verb,
        which `test_reconcile_calls_only_the_four_read_endpoints` pins as an
        allowlist rather than a list of forbidden verbs.
        """
        servers = rows_or_refuse(
            await self._search(WG_SERVER["search"]), "wireguard instances"
        )
        clients = rows_or_refuse(
            await self._search(WG_CLIENT["search"]), "wireguard peers"
        )
        show = rows_or_refuse(await self._search(WG_SERVICE["show"]), "wg runtime")
        devices = rows_or_refuse(await self._search(INTERFACES), "interfaces")
        return servers, clients, show, devices

    def _peer_containment(
        self, servers: list[dict[str, Any]], clients: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check A: every peer address against its instance's tunnel networks.

        Membership is checked in both directions. A peer naming an instance
        that does not exist and an instance naming a peer that does not exist
        are different defects, and only the first is visible from the peer row.
        """
        by_uuid = {str(s.get("uuid", "")): s for s in servers}
        known_peers = {str(c.get("uuid", "")) for c in clients}
        results = []
        for peer in clients:
            members = [
                by_uuid[u] for u in split_list(peer.get("servers")) if u in by_uuid
            ]
            addresses = [a for s in members for a in split_list(s.get("tunneladdress"))]
            networks = networks_of(addresses)
            bare = bare_networks(addresses)
            entries = split_list(peer.get("tunneladdress"))
            for entry in entries:
                outcome, detail = classify_entry(entry, networks, bare, bool(members))
                results.append(
                    {
                        "check": "peer_containment",
                        "peer": peer.get("name", ""),
                        "peer_uuid": peer.get("uuid", ""),
                        "instances": [s.get("name", "") for s in members],
                        "entry": entry,
                        "outcome": outcome,
                        "detail": detail,
                    }
                )
            # Only when the per-entry rows said nothing. One membership problem
            # is one finding; the summary row used to be an extra row on top of
            # a `no_interface` row per address, so N addresses read as N+1
            # problems and inflated `checked` and the counts by the same N.
            if not members and not entries:
                results.append(
                    {
                        "check": "peer_containment",
                        "peer": peer.get("name", ""),
                        "peer_uuid": peer.get("uuid", ""),
                        "instances": [],
                        "entry": "",
                        "outcome": "no_interface",
                        "detail": "this peer belongs to no instance that exists",
                    }
                )

        for server in servers:
            for uuid in split_list(server.get("peers")):
                if uuid in known_peers:
                    continue
                results.append(
                    {
                        "check": "peer_containment",
                        "peer": "",
                        "peer_uuid": uuid,
                        "instances": [server.get("name", "")],
                        "entry": "",
                        "outcome": "dangling_peer",
                        "detail": (
                            f"{server.get('name', '')} names peer {uuid} and no "
                            f"client record has that uuid"
                        ),
                    }
                )
        return results

    def _summarise(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Tally the outcomes, with the two a caller always reads present.

        `current` and `drifted` are defaulted so "no drift" is a zero rather
        than a missing key a caller has to read as one.
        """
        counts: dict[str, int] = {}
        for result in results:
            counts[result["outcome"]] = counts.get(result["outcome"], 0) + 1
        counts.setdefault("current", 0)
        counts.setdefault("drifted", 0)
        return counts

    @staticmethod
    def _config_networks(device: dict[str, Any], tunnel: list[str]) -> list[Any]:
        """Every network a device's configuration accounts for.

        Two sources, because the tunnel device is the only interface whose
        address comes from a WireGuard tunnel address rather than from an
        interface assignment or an ipalias virtual IP.

        An assignment keeps its prefix length in its own key (`subnet` /
        `subnetv6`), not on the address. Reading the address alone makes every
        assignment a /32 or /128, so a second address in the assigned subnet —
        an ipalias VIP is the usual one — is reported as accounted for by
        nothing.
        """
        config = device.get("config") or {}
        assigned = []
        for key, bits_key in (("ipaddr", "subnet"), ("ipaddrv6", "subnetv6")):
            address = str(config.get(key, ""))
            if address in ("", "none", "dhcp", "dhcp6", "track6"):
                continue
            bits = str(config.get(bits_key, ""))
            assigned.append(
                f"{address}/{bits}" if bits and "/" not in address else address
            )
        return networks_of([*tunnel, *assigned])

    def _address_liveness(
        self, servers: list[dict[str, Any]], devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check B: kernel addresses against config, in both directions.

        The predicate is "no config accounts for this address", never "this
        prefix looks retired". The delegated prefix is live and carried by many
        interfaces, so a rule keyed on the prefix flags the healthy ones and
        misses the orphan.
        """
        by_name = {str(d.get("device", "")): d for d in devices}
        results = []
        # Iterate the config, not the devices. A disabled instance has no device
        # at all, so a loop over devices emits nothing for it and the caller
        # cannot tell "disabled" from "never checked".
        for server in servers:
            name = str(server.get("interface", ""))
            instance = str(server.get("name", ""))
            if str(server.get("enabled", "0")) != "1":
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "instance_disabled",
                        "detail": (
                            "the instance is disabled, so it holds no kernel state "
                            "and absence is not a fault"
                        ),
                    }
                )
                continue
            device = by_name.get(name)
            if device is None:
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "device_absent",
                        "detail": (
                            f"{instance} is enabled and no device named {name} "
                            f"exists, so the kernel never brought it up"
                        ),
                    }
                )
                continue

            tunnel = split_list(server.get("tunneladdress"))
            accounted = self._config_networks(device, tunnel)
            held = [
                str(item.get("ipaddr", ""))
                for family in ("ipv4", "ipv6")
                for item in (device.get(family) or [])
                if item.get("ipaddr")
            ]

            for entry in held:
                try:
                    address = ipaddress.ip_interface(entry)
                except ValueError:
                    results.append(
                        {
                            "check": "address_liveness",
                            "instance": instance,
                            "device": name,
                            "entry": entry,
                            "outcome": "unreadable_address",
                            "detail": f"{entry!r} is not an address",
                        }
                    )
                    continue
                if address.network.is_link_local:
                    continue
                outcome = (
                    "current"
                    if any(address.ip in n for n in accounted)
                    else "unaccounted_address"
                )
                results.append(
                    {
                        "check": "address_liveness",
                        "instance": instance,
                        "device": name,
                        "entry": entry,
                        "outcome": outcome,
                        "detail": ""
                        if outcome == "current"
                        else (
                            f"{name} holds {entry}, which neither the instance "
                            f"tunnel address nor the interface assignment accounts "
                            f"for"
                        ),
                    }
                )

            held_addresses = {ipaddress.ip_interface(e).ip for e in held if _parses(e)}
            for entry in tunnel:
                if not _parses(entry):
                    continue
                if ipaddress.ip_interface(entry).ip not in held_addresses:
                    results.append(
                        {
                            "check": "address_liveness",
                            "instance": instance,
                            "device": name,
                            "entry": entry,
                            "outcome": "missing_address",
                            "detail": (
                                f"the instance configures {entry} and {name} does "
                                f"not hold it"
                            ),
                        }
                    )
        return results

    def _route_crosscheck(
        self,
        servers: list[dict[str, Any]],
        show: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        clients: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Check C: routes against the allowed IPs the kernel actually holds.

        Both directions, because the captured state holds one defect of each
        kind: a route whose allowed IP is gone, and an allowed IP whose route
        was never created.

        Route destinations omit the prefix length on host routes, so the implied
        maximum is supplied before comparison.
        """
        by_name = {str(d.get("device", "")): d for d in devices}
        # Keyed on the device as well as the name, for the reason
        # `runtime_by_peer` is: two same-named peers on two instances otherwise
        # collapse, and one kernel row is then compared against the other one's
        # config and reported as drift.
        device_of = {
            str(s.get("uuid", "")): str(s.get("interface", "")) for s in servers
        }
        config_by_peer = {
            (device_of.get(uuid, ""), str(c.get("name", ""))): c
            for c in clients
            for uuid in split_list(c.get("servers"))
        }
        results = []

        # Same reason as check B: driven by the config, so a disabled instance
        # is reported as disabled rather than skipped silently.
        for server in servers:
            name = str(server.get("interface", ""))
            instance = str(server.get("name", ""))
            if str(server.get("enabled", "0")) != "1":
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": "",
                        "outcome": "instance_disabled",
                        "detail": "the instance is disabled, so it holds no routes",
                    }
                )
                continue
            device = by_name.get(name)
            if device is None:
                continue
            # The same accounting check B uses. Reading only the tunnel address
            # here made one state produce two opposite verdicts in one report:
            # check B accounted for an address from the interface assignment
            # while check C called the route to it stale.
            tunnel = self._config_networks(
                device, split_list(server.get("tunneladdress"))
            )

            loaded: set[Any] = set()
            for row in show:
                if row.get("type") != "peer" or row.get("if") != name:
                    continue
                for entry in split_list(row.get("allowed-ips")):
                    if _parses(entry):
                        loaded.add(ipaddress.ip_network(entry, strict=False))

            routed = set()
            for destination in device.get("routes") or []:
                network = _as_network(str(destination))
                if network is None:
                    continue
                routed.add(network)
                if network in loaded or network in tunnel:
                    continue
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": str(destination),
                        "outcome": "stale_route",
                        "detail": (
                            f"{name} routes {destination}, and no allowed IP or "
                            f"tunnel network behind it"
                        ),
                    }
                )

            for network in sorted(loaded, key=str):
                if network in routed:
                    continue
                # A /128 with no route of its own is still reachable when a
                # route on the same device covers it: traffic reaches the
                # device and crypto-routing dispatches on the allowed IP. Only
                # the uncovered case can claim no route reaches it.
                covers = [
                    r
                    for r in routed
                    if r.version == network.version and network.subnet_of(r)
                ]
                results.append(
                    {
                        "check": "route_crosscheck",
                        "instance": instance,
                        "device": name,
                        "entry": str(network),
                        "outcome": "route_covered_by_prefix"
                        if covers
                        else "missing_route",
                        "covered_by": sorted(str(r) for r in covers),
                        "detail": (
                            f"the kernel holds {network} as an allowed IP on {name} "
                            f"with no route of its own; "
                            f"{', '.join(sorted(str(r) for r in covers))} covers it"
                        )
                        if covers
                        else (
                            f"the kernel holds {network} as an allowed IP on {name} "
                            f"and no route reaches it"
                        ),
                    }
                )

        for row in show:
            if row.get("type") != "peer":
                continue
            peer = str(row.get("name", ""))
            device = str(row.get("if", ""))
            config = config_by_peer.get((device, peer))
            if config is None:
                results.append(
                    {
                        "check": "kernel_matches_config",
                        "peer": peer,
                        "entry": "",
                        "outcome": "dangling_peer",
                        "detail": (
                            f"the kernel holds peer {peer!r} on {device} and no "
                            f"config row of an instance on {device} does"
                        ),
                    }
                )
                continue
            # Sets, not strings. The kernel emits v6 first while the config keeps
            # entry order, so a string comparison fails only on a dual-stack peer.
            kernel, kernel_bad = _networks_and_rest(split_list(row.get("allowed-ips")))
            stored, stored_bad = _networks_and_rest(
                split_list(config.get("tunneladdress"))
            )
            if kernel_bad or stored_bad:
                # Parsed apart rather than folded into the sets: two different
                # unparseable strings both became None and compared equal, so
                # the one case nobody can judge was reported as agreement.
                results.append(
                    {
                        "check": "kernel_matches_config",
                        "peer": peer,
                        "entry": "",
                        "outcome": "unreadable_address",
                        "detail": (
                            f"kernel {sorted(kernel_bad)} config {sorted(stored_bad)} "
                            f"do not read as addresses, so the two sides cannot be "
                            f"compared"
                        ),
                    }
                )
                continue
            results.append(
                {
                    "check": "kernel_matches_config",
                    "peer": peer,
                    "entry": "",
                    "outcome": "current" if kernel == stored else "drifted",
                    "detail": ""
                    if kernel == stored
                    else (
                        f"kernel {sorted(map(str, kernel))} "
                        f"config {sorted(map(str, stored))}"
                    ),
                }
            )
        return results

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run every check and report. Writes nothing."""
        if not self.client:
            return self._no_client()
        try:
            servers, clients, show, devices = await self._read()
        except TruncatedListingError as exc:
            return {"status": "error", "error": redact_keys(exc)}
        except Exception as exc:  # noqa: BLE001
            # Not `logger.exception`: see ListWgInstancesTool.
            logger.error("Failed to read WireGuard state: %s", redact_keys(exc))
            return {"status": "error", "error": redact_keys(exc)}

        results = [
            *self._peer_containment(servers, clients),
            *self._address_liveness(servers, devices),
            *self._route_crosscheck(servers, show, devices, clients),
        ]

        return {
            "status": "success",
            "checked": len(results),
            "counts": self._summarise(results),
            "results": results,
            "note": (
                "Server-side allowed IPs fix routing to a peer. What a peer sends "
                "through the tunnel lives in its own client config, which this "
                "API cannot read, so a clean report is not proof of end-to-end "
                "reachability."
            ),
        }
