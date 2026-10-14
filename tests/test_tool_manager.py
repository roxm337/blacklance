"""Tests for backend-aware tool scanning.

--tools used to scan the host PATH even under tools.backend=docker,
reporting image-backed tools as missing while the pipeline resolved
them fine. scan() now probes the image (one container) when the
configured backend is docker and reachable.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.external as external
from tools.tool_manager import TOOL_DEFINITIONS, ToolManager


@pytest.fixture
def _globals_snapshot():
    defs = [(t.available, t.path, t.version) for t in TOOL_DEFINITIONS]
    mode, image, ok = (external._BACKEND["mode"],
                       external._BACKEND["image"], external._DOCKER_OK)
    yield
    for tool, (available, path, version) in zip(TOOL_DEFINITIONS, defs):
        tool.available, tool.path, tool.version = available, path, version
    external._BACKEND["mode"] = mode
    external._BACKEND["image"] = image
    external._DOCKER_OK = ok


def _fake_docker_run_factory(stdout):
    def fake_run(args, **kwargs):
        assert args[:3] == ["docker", "run", "--rm"]
        assert "sh" in args

        class P:
            pass
        proc = P()
        proc.stdout = stdout
        proc.stderr = ""
        proc.returncode = 0
        return proc
    return fake_run


def test_scan_docker_maps_binaries(monkeypatch, _globals_snapshot):
    import subprocess
    monkeypatch.setattr(
        subprocess, "run",
        _fake_docker_run_factory("OK kr\nOK nuclei\nMISS arjun\n"))
    tm = ToolManager()
    tm.scan_docker("img:t")
    by_name = {t.name: t for t in tm.tools.values()}
    # kiterunner ships as `kr`: the definition name resolves via binary.
    assert by_name["kiterunner"].available is True
    assert by_name["kiterunner"].path == "kr"
    assert by_name["nuclei"].available is True
    assert by_name["arjun"].available is False
    assert by_name["arjun"].path == ""


def test_scan_uses_image_under_docker_backend(monkeypatch, _globals_snapshot):
    import subprocess
    monkeypatch.setenv("OSINT_TOOLS_BACKEND", "")
    monkeypatch.setenv("OSINT_TOOLS_IMAGE", "")
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    monkeypatch.setattr(
        subprocess, "run",
        _fake_docker_run_factory("OK kr\n"))
    tm = ToolManager({"tools": {"backend": "docker", "image": "img:t"}})
    tm.scan()
    assert "via docker image img:t" in tm.backend_note
    assert tm.backend_warning == ""
    assert tm.tools["kiterunner"].available is True


def test_scan_falls_back_with_warning_when_daemon_down(monkeypatch,
                                                       _globals_snapshot):
    monkeypatch.setenv("OSINT_TOOLS_BACKEND", "")
    monkeypatch.setenv("OSINT_TOOLS_IMAGE", "")
    monkeypatch.setattr(external, "_docker_ready", lambda: False)
    tm = ToolManager({"tools": {"backend": "docker", "image": "img:t"}})
    tm.scan()
    assert "unreachable" in tm.backend_warning
    # Fell back to a host scan rather than reporting everything missing.
    assert tm.tools


def test_scan_without_config_stays_local(_globals_snapshot):
    tm = ToolManager()
    tm.scan()
    assert "host binaries" in tm.backend_note
    assert tm.backend_warning == ""
