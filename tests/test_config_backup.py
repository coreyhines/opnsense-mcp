"""Config backup tools, and the raw-bytes client path they need.

`core/backup/download` returns XML, and every response used to be JSON-parsed,
so the endpoint could not be fetched at all. The client needs a path that
returns bytes.

The XML is a full firewall configuration: credentials, keys, the lot. It is
written to a file and never returned to the caller, so these tests assert on
what the tool gives back as much as on what it fetches.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.config_backup import (
    DiffConfigBackupsTool,
    DownloadConfigTool,
    ListBackupProvidersTool,
    ListConfigBackupsTool,
    ListSnapshotsTool,
    MkSnapshotTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

SAMPLE_XML = (
    b'<?xml version="1.0"?>\n<opnsense>\n  <theme>opnsense</theme>\n</opnsense>\n'
)

PROVIDERS = {
    "items": {"this": {"description": "This Firewall", "dirname": "/conf/backup"}}
}
BACKUPS = {
    "items": [
        {
            "id": "config-1787686218.1032.xml",
            "time_iso": "2026-08-25T14:30:18-05:00",
            "time": "1787686218.10",
            "description": 'user "apiuser" changed',
            "username": "operator@2001:db8::1",
            "filesize": 386338,
        },
        {
            "id": "config-1787678115.9739.xml",
            "time_iso": "2026-08-25T12:15:15-05:00",
            "time": "1787678115.97",
            "description": "firewall rules changed",
            "username": "operator@2001:db8::1",
            "filesize": 386102,
        },
    ]
}


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _stub(client: OPNsenseClient, responses: dict[str, Any]) -> list[str]:
    """Answer by endpoint substring; record the order of calls."""
    seen: list[str] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        seen.append(endpoint)
        for key, value in responses.items():
            if key in endpoint:
                return value
        raise AssertionError(f"unexpected endpoint {endpoint}")

    client._make_request = AsyncMock(side_effect=fake)
    return seen


# --- client raw path -------------------------------------------------------


@pytest.mark.asyncio
async def test_raw_request_returns_bytes_not_parsed_json() -> None:
    """The XML body must survive; parsing it as JSON is what broke this."""
    client = _client()
    response = MagicMock(status_code=200, content=SAMPLE_XML)
    response.json.side_effect = AssertionError("must not parse XML as JSON")
    client.long_session.request.return_value = response

    body = await client._make_request(
        "GET", "/api/core/backup/download/this", call_class="download", raw=True
    )

    assert body == SAMPLE_XML


@pytest.mark.asyncio
async def test_raw_request_uses_the_download_timeout() -> None:
    client = _client()
    seen: dict[str, Any] = {}

    def capture(method: str, url: str, **kwargs: Any) -> MagicMock:
        seen["timeout"] = kwargs.get("timeout")
        return MagicMock(status_code=200, content=SAMPLE_XML)

    client.long_session.request.side_effect = capture

    await client._make_request(
        "GET", "/api/core/backup/download/this", call_class="download", raw=True
    )

    assert seen["timeout"] == 60


# --- read-only tools -------------------------------------------------------


@pytest.mark.asyncio
async def test_list_backup_providers_returns_provider_ids() -> None:
    client = _client()
    _stub(client, {"providers": PROVIDERS})

    result = await ListBackupProvidersTool(client).execute({})

    assert result["status"] == "success"
    assert result["providers"][0]["id"] == "this"
    assert result["providers"][0]["description"] == "This Firewall"


@pytest.mark.asyncio
async def test_list_config_backups_projects_fields() -> None:
    """The raw rows carry the operator's address; the tool must not pass it on."""
    client = _client()
    _stub(client, {"backups": BACKUPS})

    result = await ListConfigBackupsTool(client).execute({})

    assert result["count"] == 2
    first = result["backups"][0]
    assert first["id"] == "config-1787686218.1032.xml"
    assert first["description"] == 'user "apiuser" changed'
    assert "username" not in first


@pytest.mark.asyncio
async def test_diff_requires_two_revisions() -> None:
    """The endpoint compares two saved backups; one revision is a 404."""
    client = _client()

    result = await DiffConfigBackupsTool(client).execute({"rev_a": "config-a.xml"})

    assert result["status"] == "error"
    assert "rev_b" in result["error"]


@pytest.mark.asyncio
async def test_diff_returns_the_changed_lines() -> None:
    client = _client()
    _stub(client, {"diff": {"items": ["--- a", "+++ b", "-old", "+new"]}})

    result = await DiffConfigBackupsTool(client).execute(
        {"rev_a": "config-a.xml", "rev_b": "config-b.xml"}
    )

    assert result["status"] == "success"
    assert result["changed_lines"] == 2
    assert "+new" in result["diff"]


# --- snapshots, unsupported on this platform -------------------------------


@pytest.mark.asyncio
async def test_snapshot_tools_report_unsupported_with_the_reason() -> None:
    """This firewall is not on ZFS boot environments, so these cannot work."""
    client = _client()
    _stub(client, {"is_supported": {"supported": False}})

    listed = await ListSnapshotsTool(client).execute({})
    made = await MkSnapshotTool(client).execute({"description": "before change"})

    for result in (listed, made):
        assert result["status"] == "unsupported"
        assert "boot environment" in result["reason"].lower()


@pytest.mark.asyncio
async def test_snapshot_tools_work_when_the_platform_supports_them() -> None:
    client = _client()
    _stub(
        client,
        {
            "is_supported": {"supported": True},
            "snapshots/search": {"rows": [{"uuid": "abc", "name": "pre-change"}]},
        },
    )

    result = await ListSnapshotsTool(client).execute({})

    assert result["status"] == "success"
    assert result["snapshots"][0]["uuid"] == "abc"


# --- download --------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_writes_a_file_and_returns_only_metadata(
    tmp_path: Path,
) -> None:
    """The config holds credentials, so the caller gets a receipt, not the XML."""
    client = _client()
    client._make_request = AsyncMock(return_value=SAMPLE_XML)

    with patch.dict("os.environ", {"OPNSENSE_BACKUP_DIR": str(tmp_path)}):
        result = await DownloadConfigTool(client).execute({})

    assert result["status"] == "success"
    assert result["sha256"] == hashlib.sha256(SAMPLE_XML).hexdigest()
    assert result["byte_size"] == len(SAMPLE_XML)

    stored = Path(result["stored_path"])
    assert stored.read_bytes() == SAMPLE_XML

    blob = str(result)
    assert "<opnsense>" not in blob
    assert "xml version" not in blob


@pytest.mark.asyncio
async def test_download_file_is_owner_readable_only(tmp_path: Path) -> None:
    client = _client()
    client._make_request = AsyncMock(return_value=SAMPLE_XML)

    with patch.dict("os.environ", {"OPNSENSE_BACKUP_DIR": str(tmp_path)}):
        result = await DownloadConfigTool(client).execute({})

    assert (Path(result["stored_path"]).stat().st_mode & 0o777) == 0o600


@pytest.mark.asyncio
async def test_download_refuses_to_write_inside_the_repository() -> None:
    """A firewall config committed by accident is not recoverable."""
    client = _client()
    client._make_request = AsyncMock(return_value=SAMPLE_XML)
    repo = Path(__file__).parent.parent

    with patch.dict("os.environ", {"OPNSENSE_BACKUP_DIR": str(repo / "tmp-backups")}):
        result = await DownloadConfigTool(client).execute({})

    assert result["status"] == "error"
    assert "repository" in result["error"].lower()


@pytest.mark.asyncio
async def test_download_requires_a_configured_directory() -> None:
    client = _client()
    client._make_request = AsyncMock(return_value=SAMPLE_XML)

    with patch.dict("os.environ", {}, clear=True):
        result = await DownloadConfigTool(client).execute({})

    assert result["status"] == "error"
    assert "OPNSENSE_BACKUP_DIR" in result["error"]
