"""I2 adapter tests: argv construction (no secrets), exit-code semantics,
auth config perms, version gating, and temp-dir lifecycle. The subprocess
launcher is faked — no schemathesis needed."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

import tools.schemathesis as adapter
from tools import external as external_mod


class FakeRunCommand:
    def __init__(self, exit_code=0, report_records=None, stderr=""):
        self.exit_code = exit_code
        self.report_records = report_records or []
        self.stderr = stderr
        self.calls = []

    async def __call__(self, argv, timeout=120, stdin_data=""):
        self.calls.append({"argv": list(argv), "timeout": timeout})
        # Write the report where the adapter expects it (the workdir is
        # the parent of report.json's configured path — the adapter creates
        # the temp dir itself, so find it via the spec path's parent).
        spec = next((a for a in argv
                     if a.endswith("schema.json")), "")
        if spec:
            workdir = Path(spec).parent
            (workdir / "report.json").write_text(
                json.dumps(self.report_records), encoding="utf-8")
        return {"stdout": "", "stderr": self.stderr,
                "exit_code": self.exit_code, "error": None}


@pytest.fixture(autouse=True)
def cleanup_workdirs(monkeypatch):
    """Remove the adapter's staged workdirs after every test.

    run_schemathesis stages into a cwd tempdir by design; callers own the
    cleanup. Tests must not leak schemathesis-* directories into the repo.
    """
    import tools.schemathesis as adapter_mod
    dirs = []
    original = adapter_mod.run_schemathesis

    async def wrapped(*args, **kwargs):
        result = await original(*args, **kwargs)
        if isinstance(result, dict) and result.get("workdir"):
            dirs.append(result["workdir"])
        return result

    monkeypatch.setattr(adapter_mod, "run_schemathesis", wrapped)
    yield
    for workdir in dirs:
        adapter_mod.cleanup_workdir(workdir)


@pytest.fixture()
def fake_launcher(monkeypatch):
    fake = FakeRunCommand()
    monkeypatch.setattr(adapter, "run_command", fake)
    monkeypatch.setattr(adapter, "schemathesis_available",
                        lambda: {"available": True, "backend": "local",
                                 "version": "4.32.5", "unsupported": False})
    return fake


def _run(argv_build):
    async def _go():
        return await adapter.run_schemathesis(**argv_build)
    return asyncio.run(_go())


def test_missing_tool_is_unsupported(monkeypatch):
    monkeypatch.setattr(adapter, "schemathesis_available",
                        lambda: {"available": False, "version": None,
                                 "unsupported": False,
                                 "reason": "schemathesis not installed"})
    result = _run({"spec_path": "x.json", "base_url": "https://x"})
    assert result["available"] is False
    assert result["reason"] == "schemathesis not installed"


def test_below_min_version_is_unsupported(monkeypatch):
    monkeypatch.setattr(adapter, "schemathesis_available",
                        lambda: {"available": False, "version": "3.20.0",
                                 "unsupported": True,
                                 "reason": "schemathesis 3.20.0 < 3.21.0"})
    result = _run({"spec_path": "x.json", "base_url": "https://x"})
    assert result["unsupported"] is True
    assert "3.20.0" in result["reason"]


def test_argv_carries_stateful_links_and_never_secrets(tmp_path, fake_launcher):
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")
    result = _run({
        "spec_path": str(spec), "base_url": "https://lab.local",
        "headers": ["Authorization: Bearer sekret-token-123"],
        "max_cases": 50, "deadline_ms": 1500,
    })
    argv = " ".join(fake_launcher.calls[0]["argv"])
    assert "--phases coverage,fuzzing,stateful" in argv
    assert "--max-examples 50" in argv
    assert "sekret-token-123" not in argv
    assert "Bearer" not in argv
    config_flag = next(a for a in fake_launcher.calls[0]["argv"]
                       if a == "--config-file")
    config_path = fake_launcher.calls[0]["argv"][
        fake_launcher.calls[0]["argv"].index(config_flag) + 1]
    assert config_path.endswith("auth.toml")
    mode = stat.S_IMODE(os.stat(config_path).st_mode)
    assert mode == 0o600
    assert result["available"] is True


def test_exit_one_means_findings_not_error(tmp_path, fake_launcher):
    fake_launcher.exit_code = 1
    fake_launcher.report_records = [{
        "path": "/api/o", "method": "POST", "status": "failure",
        "seed": 3, "interactions": 2,
        "checks": [{"name": "not_a_server_error", "value": "FAIL",
                    "message": "500", "response": {"status_code": 500},
                    "example": {}}]}]
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")
    result = _run({"spec_path": str(spec), "base_url": "https://x"})
    assert result["error"] is None
    assert result["exit_code"] == 1
    assert len(result["failures"]) == 1
    assert result["failures"][0]["check"] == "not_a_server_error"


def test_exit_above_one_is_error(tmp_path, fake_launcher):
    fake_launcher.exit_code = 2
    fake_launcher.stderr = "schemathesis crashed"
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")
    result = _run({"spec_path": str(spec), "base_url": "https://x"})
    assert result["error"] == "schemathesis exited 2"
    assert "schemathesis crashed" in result["tool_output_tail"]


def test_junit_fallback_when_report_missing(tmp_path, fake_launcher,
                                            monkeypatch):
    fake_launcher.exit_code = 1
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")

    async def write_junit(argv, timeout=120, stdin_data=""):
        workdir = Path(next(a for a in argv
                            if a.endswith("schema.json"))).parent
        (workdir / "junit.xml").write_text(
            '<testsuite name="x"><testcase classname="/api/a GET" '
            'name="n"><failure message="500">x</failure></testcase>'
            '</testsuite>', encoding="utf-8")
        return {"stdout": "", "stderr": "", "exit_code": 1, "error": None}

    import tools.schemathesis as adapter_mod
    monkeypatch.setattr(adapter_mod, "run_command", write_junit)
    result = _run({"spec_path": str(spec), "base_url": "https://x"})
    assert result["failures"][0]["path"] == "/api/a"


def test_cleanup_workdir_removes_temp(tmp_path):
    workdir = tmp_path / "schemathesis-abc"
    workdir.mkdir()
    (workdir / "cassettes").mkdir()
    (workdir / "cassettes" / "c.yaml").write_text("x")
    adapter.cleanup_workdir(str(workdir))
    assert not workdir.exists()


def test_auth_config_omitted_without_headers(tmp_path, fake_launcher):
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")
    _run({"spec_path": str(spec), "base_url": "https://x"})
    argv = fake_launcher.calls[0]["argv"]
    assert "--config-file" not in argv


def test_tool_backend_provenance_in_result(tmp_path, fake_launcher):
    spec = tmp_path / "schema.json"
    spec.write_text("{}", encoding="utf-8")
    result = _run({"spec_path": str(spec), "base_url": "https://x"})
    assert result["backend"] in ("local", "docker")
    assert result["version"] == "4.32.5"
    assert result["workdir"].startswith(
        str(Path(os.getcwd()) / "schemathesis-"))
