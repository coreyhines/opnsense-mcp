"""Tests for workstation Ollama probe and bucket routing."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PB_HOME = (
    Path(
        os.environ.get(
            "PARALLEL_BUCKETS_HOME",
            Path.home() / "code" / "parallel-buckets",
        )
    )
    .expanduser()
    .resolve()
)
SCRIPTS = PB_HOME / "scripts"
_OLLAMA_WORKSTATION_SCRIPT = SCRIPTS / "ollama_workstation.py"
_RECOMMEND_BUCKET_OWNER_SCRIPT = SCRIPTS / "recommend_bucket_owner.py"

pytestmark = pytest.mark.skipif(
    not (
        _OLLAMA_WORKSTATION_SCRIPT.is_file()
        and _RECOMMEND_BUCKET_OWNER_SCRIPT.is_file()
    ),
    reason=(
        "parallel-buckets scripts not installed "
        "(expected under PARALLEL_BUCKETS_HOME/scripts)"
    ),
)


def _load_module(name: str):
    path = SCRIPTS / f"{name}.py"
    if not path.is_file():
        pytest.skip(f"missing parallel-buckets script: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ws_mod():
    return _load_module("ollama_workstation")


@pytest.fixture
def recommend_mod():
    return _load_module("recommend_bucket_owner")


def _json_response(payload: dict) -> bytes:
    return json.dumps(payload).encode()


class TestWorkstationProbe:
    def test_not_configured_without_host(
        self, ws_mod, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OLLAMA_WORKSTATION_HOST", raising=False)
        probe = ws_mod.probe_workstation()
        assert probe["configured"] is False
        assert probe["available"] is False
        assert probe["reason"] == "not_configured"

    def test_ready_when_model_present(
        self, ws_mod, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OLLAMA_WORKSTATION_HOST", "http://ws:11434")
        monkeypatch.setenv("OLLAMA_WORKSTATION_MODEL", "qwen3:32b")

        def fake_open(req, timeout=0):  # noqa: ARG001
            url = req.full_url
            if url.endswith("/api/version"):
                return _FakeResp({"version": "0.24.0"})
            if url.endswith("/api/tags"):
                return _FakeResp({"models": [{"name": "qwen3:32b"}]})
            if url.endswith("/api/ps"):
                return _FakeResp({"models": []})
            if url.endswith("/api/show"):
                return _FakeResp({"capabilities": ["completion", "tools"]})
            msg = f"unexpected url {url}"
            raise AssertionError(msg)

        with patch.object(ws_mod.urllib.request, "urlopen", fake_open):
            probe = ws_mod.probe_workstation()
        assert probe["ok"] is True
        assert probe["available"] is True
        assert probe["model_ready"] is True
        assert probe["reason"] == "ready"

    def test_busy_blocks_when_not_allowed(
        self, ws_mod, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OLLAMA_WORKSTATION_HOST", "http://ws:11434")

        def fake_open(req, timeout=0):  # noqa: ARG001
            url = req.full_url
            if url.endswith("/api/version"):
                return _FakeResp({"version": "0.24.0"})
            if url.endswith("/api/tags"):
                return _FakeResp({"models": [{"name": "qwen3:32b"}]})
            if url.endswith("/api/ps"):
                return _FakeResp(
                    {
                        "models": [
                            {
                                "name": "qwen3:32b",
                                "processor": "100% GPU",
                                "size_vram": 15000000000,
                                "size": 20000000000,
                            }
                        ]
                    }
                )
            if url.endswith("/api/show"):
                return _FakeResp({"capabilities": ["completion", "tools"]})
            msg = f"unexpected url {url}"
            raise AssertionError(msg)

        with patch.object(ws_mod.urllib.request, "urlopen", fake_open):
            probe = ws_mod.probe_workstation()
        assert probe["busy"] is True
        assert probe["available"] is False
        assert probe["reason"] == "busy"

    def test_profile_fit_pure_logic(self, ws_mod) -> None:
        fit = ws_mod.assess_profile_fit("pure_logic")
        assert fit["fit"] == "good"
        assert fit["suitable"] is True

    def test_profile_fit_mcp_wiring_unsupported(self, ws_mod) -> None:
        fit = ws_mod.assess_profile_fit("mcp_wiring")
        assert fit["fit"] == "unsupported"
        assert fit["suitable"] is False


class TestRecommendWorkstation:
    def test_recommend_farm_when_ready(self, ws_mod) -> None:
        probe = {
            "configured": True,
            "ok": True,
            "available": True,
            "host": "http://ws:11434",
            "model": "qwen3:32b",
        }
        rec = ws_mod.recommend_workstation("pure_logic", probe)
        assert rec["farm"] is True
        assert rec["owner"] == "Ollama-workstation"
        assert rec["fit"] == "good"

    def test_write_crud_marginal_requires_gate(self, ws_mod) -> None:
        probe = {
            "configured": True,
            "ok": True,
            "available": True,
            "host": "http://ws:11434",
            "model": "qwen3:32b",
        }
        rec = ws_mod.recommend_workstation("write_crud", probe)
        assert rec["farm"] is True
        assert rec["fit"] == "marginal"
        assert rec["coordinator_gate_required"] is True


class TestRecommendBucketOwnerWorkstation:
    def test_pure_logic_falls_back_to_workstation(
        self, recommend_mod, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OLLAMA_WORKSTATION_HOST", "http://ws:11434")
        ollama = {
            "local": {"ok": False, "models": []},
            "workstation": {
                "configured": True,
                "ok": True,
                "available": True,
                "host": "http://ws:11434",
                "model": "qwen3:32b",
            },
            "cloud_limits": {"usage": {}},
            "cloud": {"ok": False, "models": []},
        }
        claude = {"ok": False}
        rec = recommend_mod.recommend("pure_logic", claude=claude, ollama=ollama)
        assert rec["owner"] == "Ollama-workstation"
        assert rec["model"] == "qwen3:32b"

    def test_write_crud_prefers_workstation_when_local_primary_blocked(
        self, recommend_mod, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OLLAMA_WORKSTATION_HOST", "http://ws:11434")
        ollama = {
            "local": {"ok": True, "models": ["qwen3.6:35b-a3b-mxfp8"]},
            "workstation": {
                "configured": True,
                "ok": True,
                "available": True,
                "host": "http://ws:11434",
                "model": "qwen3:32b",
            },
            "cloud_limits": {"usage": {}},
            "cloud": {"ok": False, "models": []},
        }
        claude = {"ok": True, "session_pct": 95, "week_pct": 50}
        rec = recommend_mod.recommend("write_crud", claude=claude, ollama=ollama)
        assert rec["owner"] == "Ollama-workstation"
        assert rec["model"] == "qwen3:32b"


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return _json_response(self._payload)
