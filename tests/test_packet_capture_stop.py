"""Packet capture stop must not kill foreign tcpdump processes (#94)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opnsense_mcp.tools.packet_capture import PacketCaptureTool2


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeStdout:
    def __init__(self, exit_status: int) -> None:
        self.channel = _FakeChannel(exit_status)

    def read(self) -> bytes:
        return b""


class _FakeStderr:
    def read(self) -> bytes:
        return b""


def test_stop_capture_scopes_pkill_to_tool_capture_file() -> None:
    """A bare ``tcpdump -i`` pattern kills every capture on the firewall."""
    tool = PacketCaptureTool2()
    client = MagicMock()
    client.exec_command.return_value = (MagicMock(), _FakeStdout(0), _FakeStderr())
    client.close = MagicMock()

    with patch.object(tool, "_get_client", return_value=client):
        result = tool.stop_capture()

    cmd = client.exec_command.call_args[0][0]
    assert "mcp_capture.pcap" in cmd
    assert "tcpdump -i" not in cmd
    assert result["status"] == "success"
    assert result["stopped"] is True


def test_stop_capture_reports_not_stopped_when_pkill_matches_nothing() -> None:
    """pkill exit 1 means no tool-owned process; do not claim success."""
    tool = PacketCaptureTool2()
    client = MagicMock()
    client.exec_command.return_value = (MagicMock(), _FakeStdout(1), _FakeStderr())
    client.close = MagicMock()

    with patch.object(tool, "_get_client", return_value=client):
        result = tool.stop_capture()

    assert result["status"] == "error"
    assert result["stopped"] is False
    assert result["exit_status"] == 1
