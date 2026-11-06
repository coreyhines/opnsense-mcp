"""Backup provider and revision cannot steer the API path (#159).

Both became URL path segments with no validation, so `revision='../x'`
sent the GET to a different endpoint on a root API client.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.config_backup import (
    DiffConfigBackupsTool,
    DownloadConfigTool,
    ListConfigBackupsTool,
)

# The shape 26.7 lists revisions in, from a live list read.
REAL_REVISION = "config-1793827417.2691.xml"


def _client() -> MagicMock:
    client = MagicMock()
    client._make_request = AsyncMock(return_value={"items": {}})
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "params"),
    [
        (DownloadConfigTool, {"revision": "../../../core/firmware/status"}),
        (DownloadConfigTool, {"provider": "this/../../core"}),
        (DiffConfigBackupsTool, {"rev_a": REAL_REVISION, "rev_b": "../x"}),
        (DiffConfigBackupsTool, {"rev_a": "a/b", "rev_b": REAL_REVISION}),
        (ListConfigBackupsTool, {"provider": "../core"}),
    ],
)
async def test_a_path_shaped_value_is_refused_before_any_request(
    tool: type, params: dict, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPNSENSE_BACKUP_DIR", str(tmp_path))
    client = _client()

    result = await tool(client).execute(params)

    assert result["status"] == "error"
    client._make_request.assert_not_called()


@pytest.mark.asyncio
async def test_a_real_revision_id_is_accepted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPNSENSE_BACKUP_DIR", str(tmp_path))
    client = _client()
    client._make_request = AsyncMock(return_value=b"<opnsense/>")

    result = await DownloadConfigTool(client).execute({"revision": REAL_REVISION})

    assert result["status"] == "success"
    endpoint = client._make_request.call_args.args[1]
    assert endpoint == f"/api/core/backup/download/this/{REAL_REVISION}"
