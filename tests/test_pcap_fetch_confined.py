"""A fetched capture lands only in the capture directory (#158).

`fetch_pcap` handed the caller's `local_path` to `sftp.get`, so any bearer
holder could overwrite any file the server could write.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opnsense_mcp.tools import packet_capture
from opnsense_mcp.tools.packet_capture import PacketCaptureTool2, resolve_capture_path


@pytest.fixture
def capdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "captures"
    monkeypatch.setenv("OPNSENSE_CAPTURE_DIR", str(directory))
    return directory


def _tool_with_sftp() -> tuple[PacketCaptureTool2, MagicMock]:
    with patch.object(packet_capture, "OPNsenseSSHClient") as ssh_cls:
        ssh_cls.return_value.get_config.return_value = {
            "host": "fw.example",
            "user": "root",
            "key": None,
            "port": 22,
        }
        tool = PacketCaptureTool2(client=None)
    sftp = MagicMock()
    ssh = MagicMock()
    ssh.open_sftp.return_value = sftp
    tool._get_client = MagicMock(return_value=ssh)
    return tool, sftp


@pytest.mark.parametrize(
    "bad",
    ["../../etc/passwd", "/etc/passwd", "sub/dir.pcap", "..", "..\\\\x.pcap"],
)
def test_a_path_is_refused_before_any_sftp_call(capdir: Path, bad: str) -> None:
    tool, sftp = _tool_with_sftp()

    result = tool.fetch_pcap(bad)

    assert result["status"] == "error"
    sftp.get.assert_not_called()


def test_a_symlink_escaping_the_directory_is_refused(
    capdir: Path, tmp_path: Path
) -> None:
    capdir.mkdir(parents=True)
    (capdir / "trap.pcap").symlink_to(tmp_path / "outside.pcap")

    with pytest.raises(ValueError):
        resolve_capture_path("trap.pcap")


def test_a_bare_name_lands_in_the_capture_dir(capdir: Path) -> None:
    tool, sftp = _tool_with_sftp()

    result = tool.fetch_pcap("today.pcap")

    assert result["status"] == "success"
    target = Path(sftp.get.call_args.args[1])
    assert target.parent == capdir.resolve()
    assert target.name == "today.pcap"


def test_the_default_lands_in_the_capture_dir(capdir: Path) -> None:
    tool, sftp = _tool_with_sftp()

    tool.fetch_pcap(None)

    assert Path(sftp.get.call_args.args[1]).parent == capdir.resolve()


def test_the_backup_dir_supplies_the_default_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployed unit mounts OPNSENSE_BACKUP_DIR rw; captures go beside it."""
    monkeypatch.delenv("OPNSENSE_CAPTURE_DIR", raising=False)
    monkeypatch.setenv("OPNSENSE_BACKUP_DIR", str(tmp_path / "backups"))

    assert (
        resolve_capture_path("x.pcap").parent
        == (tmp_path / "backups" / "captures").resolve()
    )
