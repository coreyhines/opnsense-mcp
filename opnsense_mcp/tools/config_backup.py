"""Config backup, revision history and ZFS snapshot tools.

The firewall keeps a configuration backup per change, so the history is already
there; these tools expose it and let a copy be pulled to disk before a risky
change.

Two things this module deliberately does not do:

* It never returns the configuration XML. That file holds credentials, keys and
  every secret on the box, so callers get a receipt (path, size, checksum) and
  the bytes go straight to a file.
* It does not offer a revert. Restoring a configuration is a console or UI
  operation, and a tool that could roll a firewall back over the network is a
  bigger risk than the convenience is worth.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PROVIDER = "this"

# core/snapshots needs ZFS boot environments. Probed on 26.7.2: not supported.
SNAPSHOT_UNSUPPORTED_REASON = (
    "This firewall does not run on ZFS boot environments, so core/snapshots "
    "reports supported=false. Use download_config for a recovery artifact."
)


class _BackupToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}


class ListBackupProvidersTool(_BackupToolBase):
    """List the configured backup providers."""

    name = "list_backup_providers"
    description = "List OPNsense configuration backup providers"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each provider id with its description."""
        if not self.client:
            return self._no_client()
        try:
            data = await self.client._make_request("GET", "/api/core/backup/providers")
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller
            logger.exception("Failed to list backup providers")
            return {"status": "error", "error": str(exc)}

        items = data.get("items", {}) if isinstance(data, dict) else {}
        return {
            "status": "success",
            "providers": [
                {
                    "id": key,
                    "description": value.get("description", key),
                    "dirname": value.get("dirname", ""),
                }
                for key, value in items.items()
            ],
        }


class ListConfigBackupsTool(_BackupToolBase):
    """List stored configuration revisions."""

    name = "list_config_backups"
    description = "List stored OPNsense configuration revisions, newest first"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Backup provider id (default 'this')",
                "optional": True,
            },
            "limit": {
                "type": "number",
                "description": "Maximum revisions to return (default 25)",
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return revision ids, timestamps, descriptions and sizes.

        The raw rows carry the username and source address of whoever made each
        change, which callers do not need, so only the useful fields are kept.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        provider = params.get("provider") or DEFAULT_PROVIDER
        limit = int(params.get("limit") or 25)
        try:
            data = await self.client._make_request(
                "GET", f"/api/core/backup/backups/{provider}"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list config backups")
            return {"status": "error", "error": str(exc)}

        items = data.get("items", []) if isinstance(data, dict) else []
        backups = [
            {
                "id": row.get("id", ""),
                "time": row.get("time_iso", ""),
                "description": row.get("description", ""),
                "bytes": row.get("filesize", 0),
            }
            for row in items[:limit]
        ]
        return {
            "status": "success",
            "provider": provider,
            "count": len(backups),
            "total_available": len(items),
            "backups": backups,
        }


class DiffConfigBackupsTool(_BackupToolBase):
    """Compare two stored configuration revisions."""

    name = "diff_config_backups"
    description = "Show the differences between two stored configuration revisions"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "rev_a": {
                "type": "string",
                "description": "Older revision id, from list_config_backups",
            },
            "rev_b": {
                "type": "string",
                "description": "Newer revision id, from list_config_backups",
            },
            "provider": {
                "type": "string",
                "description": "Backup provider id (default 'this')",
                "optional": True,
            },
        },
        "required": ["rev_a", "rev_b"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the unified diff between two revisions.

        The endpoint takes two revisions; it compares saved backups and cannot
        report staged-but-unapplied changes.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        rev_a = params.get("rev_a")
        rev_b = params.get("rev_b")
        if not rev_a or not rev_b:
            return {
                "status": "error",
                "error": (
                    "rev_a and rev_b are both required; this compares two stored "
                    "revisions. Use list_config_backups to find ids."
                ),
            }

        provider = params.get("provider") or DEFAULT_PROVIDER
        try:
            data = await self.client._make_request(
                "GET", f"/api/core/backup/diff/{provider}/{rev_a}/{rev_b}"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to diff config backups")
            return {"status": "error", "error": str(exc)}

        lines = data.get("items", []) if isinstance(data, dict) else []
        changed = [
            ln for ln in lines if ln[:1] in {"+", "-"} and ln[:3] not in {"---", "+++"}
        ]
        return {
            "status": "success",
            "rev_a": rev_a,
            "rev_b": rev_b,
            "changed_lines": len(changed),
            "diff": lines,
        }


class DownloadConfigTool(_BackupToolBase):
    """Download the running configuration to a file on the MCP host."""

    name = "download_config"
    description = (
        "Download the firewall configuration to a file on the MCP host and "
        "return its path, size and checksum. The XML is never returned."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Backup provider id (default 'this')",
                "optional": True,
            },
            "revision": {
                "type": "string",
                "description": "Revision id to fetch; omit for the running config",
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch the config and write it out, returning only metadata."""
        params = params or {}
        if not self.client:
            return self._no_client()

        target_dir = os.environ.get("OPNSENSE_BACKUP_DIR", "").strip()
        if not target_dir:
            return {
                "status": "error",
                "error": (
                    "OPNSENSE_BACKUP_DIR is not set. Point it at a directory "
                    "outside the git repository to store configuration backups."
                ),
            }

        destination = Path(target_dir).expanduser().resolve()
        repo_root = Path(__file__).resolve().parents[2]
        if destination == repo_root or repo_root in destination.parents:
            return {
                "status": "error",
                "error": (
                    f"Refusing to write a firewall configuration inside the "
                    f"repository ({destination}). Choose a path outside it."
                ),
            }

        provider = params.get("provider") or DEFAULT_PROVIDER
        revision = params.get("revision")
        endpoint = f"/api/core/backup/download/{provider}"
        if revision:
            endpoint = f"{endpoint}/{revision}"

        try:
            body = await self.client._make_request(
                "GET", endpoint, call_class="download", raw=True
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to download configuration")
            return {"status": "error", "error": str(exc)}

        if not isinstance(body, bytes | bytearray):
            return {
                "status": "error",
                "error": "Expected raw bytes from the download endpoint",
            }

        digest = hashlib.sha256(body).hexdigest()
        try:
            destination.mkdir(parents=True, exist_ok=True)
            path = destination / f"opnsense-config-{digest[:12]}.xml"
            # Create with owner-only permissions before any bytes land.
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "wb") as fh:
                fh.write(body)
            path.chmod(0o600)
        except OSError as exc:
            logger.exception("Failed to store configuration backup")
            return {"status": "error", "error": f"Could not write backup: {exc}"}

        logger.info("Stored configuration backup (%d bytes)", len(body))
        return {
            "status": "success",
            "backup_id": digest[:12],
            "sha256": digest,
            "byte_size": len(body),
            "stored_path": str(path),
            "note": "Configuration contents are not returned; read the file if needed.",
        }


class _SnapshotToolBase(_BackupToolBase):
    """Snapshot tools share a support check."""

    async def _supported(self) -> bool:
        data = await self.client._make_request(
            "GET", "/api/core/snapshots/is_supported"
        )
        if isinstance(data, dict):
            return bool(data.get("supported"))
        return False

    def _unsupported(self) -> dict[str, Any]:
        return {"status": "unsupported", "reason": SNAPSHOT_UNSUPPORTED_REASON}


class ListSnapshotsTool(_SnapshotToolBase):
    """List ZFS boot environment snapshots."""

    name = "list_snapshots"
    description = (
        "List ZFS boot environment snapshots, where the platform supports them"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return snapshots, or report that the platform has none."""
        if not self.client:
            return self._no_client()
        try:
            if not await self._supported():
                return self._unsupported()
            data = await self.client._make_request("POST", "/api/core/snapshots/search")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list snapshots")
            return {"status": "error", "error": str(exc)}

        rows = data.get("rows", []) if isinstance(data, dict) else []
        return {"status": "success", "count": len(rows), "snapshots": rows}


class MkSnapshotTool(_SnapshotToolBase):
    """Create a ZFS boot environment snapshot."""

    name = "mk_snapshot"
    description = (
        "Create a ZFS boot environment snapshot, where the platform supports it"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "description": {
                "type": "string",
                "description": "Label for the snapshot",
            },
        },
        "required": ["description"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a snapshot, or report that the platform has none."""
        params = params or {}
        if not self.client:
            return self._no_client()
        description = (params.get("description") or "").strip()
        if not description:
            return {"status": "error", "error": "description is required"}
        try:
            if not await self._supported():
                return self._unsupported()
            data = await self.client._make_request(
                "POST",
                "/api/core/snapshots/add",
                call_class="write",
                json={"snapshot": {"name": description}},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create snapshot")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "result": data}
