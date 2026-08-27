"""Set an interface's address over SSH, because the API cannot.

This is the only place the project writes configuration outside the API, so the
reasoning matters as much as the code.

`NetworkInterface.xml` on the 26.7 series defines six fields — descr,
identifier, icon, optgroup, if, lock — and `AssignmentController` exposes
whatever the model defines. An address posted to `set_item` returns
`{"result": "saved"}` and is discarded. Confirmed against the OPNsense source
and against a live firewall.

That is a different case from `ssh_fw_rule`, which this project removed. There
the API worked and three separate bugs made it look broken; a fallback was the
wrong answer to a diagnosis problem. Here the API genuinely cannot do the
thing. A fallback is for what the API cannot do, not for what it appears to do
badly.

The addressing fields exist in OPNsense master, so this tool has a known
expiry. It checks the live model and refuses when they appear, rather than
quietly remaining the path of least resistance on firmware that has outgrown
it.

Safety, given this runs PHP as root:

* the interface identifier must appear in the API's own assignment list;
* the address is parsed by `ipaddress`, never pattern-matched, so an injection
  attempt fails to parse rather than being escaped;
* the prefix is an int bounded by the parsed address's family;
* none of those values are interpolated into the PHP. The script is a fixed
  constant and the values arrive as environment variables;
* success is confirmed by reading the address back off the interface, because
  `interface_configure()` throws after applying it and the exit code means
  nothing either way.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import shlex
from typing import Any

from opnsense_mcp.utils.ssh_client import OPNsenseSSHClient

logger = logging.getLogger(__name__)

ASSIGNMENT_SEARCH = "/api/interfaces/assignment/search_item"
ASSIGNMENT_BLANK = "/api/interfaces/assignment/get_item/"

# If the model grows any of these, the API can do this and the tool should not.
API_ADDRESS_FIELDS = ("ipaddr", "ipaddrv6", "type4", "type6")

# The remote path comes from mktemp rather than being fixed. A predictable
# name in a world-writable directory is something another local user can
# pre-create or symlink, and the file briefly holds the configuration change.
REMOTE_TEMPLATE = "opnsense-mcp-setaddr.XXXXXXXX"

# A fixed constant. Values arrive through the environment, so nothing the
# caller supplies is ever part of the program text.
PHP_SCRIPT = """<?php
require_once("config.inc");
require_once("util.inc");      // write_config() needs shell_safe() from here
require_once("interfaces.inc");
global $config;
$if = getenv("MCP_IF");
if (!isset($config["interfaces"][$if])) {
    fwrite(STDERR, "interface $if is not assigned\\n");
    exit(1);
}
$config["interfaces"][$if]["enable"] = "1";
$config["interfaces"][$if][getenv("MCP_FIELD")] = getenv("MCP_ADDR");
$config["interfaces"][$if][getenv("MCP_BITS_FIELD")] = getenv("MCP_BITS");
write_config(getenv("MCP_REASON"));
interface_configure(false, $if);
echo "done\\n";
"""


class SetInterfaceAddressTool:
    """Give an assigned interface a static address."""

    name = "set_interface_address"
    description = (
        "Set a static IPv4 or IPv6 address on an assigned interface. Uses SSH, "
        "because the 26.7 API model has no address field and discards one silently"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {
                "type": "string",
                "description": "Interface identifier, e.g. opt12, from the assignment list",
            },
            "address": {"type": "string", "description": "IPv4 or IPv6 address"},
            "subnet_bits": {
                "type": "number",
                "description": "Prefix length; 32 or 128 for a loopback",
            },
            "reason": {
                "type": "string",
                "description": "Recorded in the configuration history",
                "optional": True,
            },
        },
        "required": ["interface", "address", "subnet_bits"],
    }

    def __init__(self, client: Any) -> None:
        """Store the API client and prepare an SSH client."""
        self.client = client
        self._ssh = OPNsenseSSHClient(client)

    def _run(self, command: str) -> dict[str, Any]:
        return self._ssh.execute_command(command)

    async def _api_can_do_this(self) -> bool:
        """Has the model gained address fields since 26.7?"""
        blank = await self.client._make_request("GET", ASSIGNMENT_BLANK)
        node = blank.get("interface", {}) if isinstance(blank, dict) else {}
        return any(field in node for field in API_ADDRESS_FIELDS)

    async def _assigned_identifiers(self) -> set[str]:
        rows = await self.client._make_request(
            "POST", ASSIGNMENT_SEARCH, json={"current": 1, "rowCount": 500}
        )
        return {
            r.get("uuid", "")
            for r in (rows.get("rows", []) if isinstance(rows, dict) else [])
        }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate everything, write it, then confirm by reading it back."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        interface = (params.get("interface") or "").strip()
        raw_address = (params.get("address") or "").strip()

        try:
            if await self._api_can_do_this():
                return {
                    "status": "error",
                    "error": (
                        "the assignment API now exposes address fields, so this "
                        "firmware can set an address without SSH. Use the API "
                        "path and retire this tool."
                    ),
                }

            assigned = await self._assigned_identifiers()
            if interface not in assigned:
                return {
                    "status": "error",
                    "error": (
                        f"{interface!r} is not an assigned interface. Known: "
                        f"{', '.join(sorted(assigned)) or 'none'}."
                    ),
                }

            # Parsed, not matched. Anything shell-shaped fails here.
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"{raw_address!r} is not an IP address",
                }

            try:
                bits = int(params.get("subnet_bits"))
            except (TypeError, ValueError):
                return {"status": "error", "error": "subnet_bits must be a number"}
            limit = 32 if address.version == 4 else 128
            if not 0 <= bits <= limit:
                return {
                    "status": "error",
                    "error": f"subnet_bits must be between 0 and {limit} for IPv{address.version}",
                }
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to validate the address change")
            return {"status": "error", "error": str(exc)}

        field = "ipaddr" if address.version == 4 else "ipaddrv6"
        bits_field = "subnet" if address.version == 4 else "subnetv6"
        reason = params.get("reason") or f"mcp: set {interface} to {address}/{bits}"

        blob = base64.b64encode(PHP_SCRIPT.encode()).decode()
        remote = ""
        try:
            made = self._run(
                "/bin/sh -c "
                + shlex.quote(
                    f"f=$(mktemp -t {REMOTE_TEMPLATE}) && "
                    f'echo {blob} | b64decode -r > "$f" && echo "$f"'
                )
            )
            remote = str(made.get("stdout", "")).strip().splitlines()[-1:] or [""]
            remote = remote[0].strip()
            if not remote.startswith("/"):
                return {
                    "status": "error",
                    "error": f"could not stage the script remotely: {made}",
                }

            env = " ".join(
                f"{k}={shlex.quote(str(v))}"
                for k, v in (
                    ("MCP_IF", interface),
                    ("MCP_ADDR", str(address)),
                    ("MCP_BITS", bits),
                    ("MCP_FIELD", field),
                    ("MCP_BITS_FIELD", bits_field),
                    ("MCP_REASON", reason),
                )
            )
            run = self._run(
                f"/bin/sh -c {shlex.quote(f'env {env} sudo -E php {shlex.quote(remote)} 2>&1')}"
            )

            # interface_configure() throws after applying the address, so the
            # exit code is not evidence either way. Read the interface instead.
            device = await self._device_for(interface)
            check = self._run(f"/bin/sh -c {shlex.quote(f'ifconfig {device} 2>&1')}")
            observed = str(check.get("stdout", "")) + str(check.get("stderr", ""))
            verified = str(address) in observed
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to set the interface address")
            return {"status": "error", "error": str(exc)}
        finally:
            if remote:
                self._run(f"/bin/sh -c {shlex.quote(f'rm -f {shlex.quote(remote)}')}")

        if not verified:
            return {
                "status": "error",
                "error": (
                    f"{address} is not on {interface} after the write. "
                    f"Script output: {str(run.get('stdout', ''))[:200]}"
                    f"{str(run.get('stderr', ''))[:200]}"
                ),
            }
        return {
            "status": "success",
            "interface": interface,
            "address": f"{address}/{bits}",
            "verified": True,
            "note": (
                "Written to the configuration and applied. Confirmed by reading "
                "the address back off the interface, not from the exit code."
            ),
        }

    async def _device_for(self, identifier: str) -> str:
        """Map opt12 to lo1, so the read-back looks at the right device."""
        rows = await self.client._make_request(
            "POST", ASSIGNMENT_SEARCH, json={"current": 1, "rowCount": 500}
        )
        for row in rows.get("rows", []) if isinstance(rows, dict) else []:
            if row.get("uuid") == identifier:
                return str(row.get("if") or identifier)
        return identifier
