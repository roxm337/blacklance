"""I4 lab gate: the SPA path-traversal defect is proven on the vulnerable
twin and absent on the fixed twin.

Spawns the CSPT twin in both modes, runs the real CSPTAudit module (real
Playwright, real HTTP), and asserts:

- vulnerable twin: a verified ``cspt_impact_observed`` finding, a
  ``path_altered`` pair resolving to /admin/secrets, a persisted report;
- fixed twin: no verified findings and no path_altered pair.

Skip, don't fail, when the lab or browser is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8301 \\
    OSINT_LAB_URL_FIXED=http://localhost:8302 \\
    .venv/bin/python -m pytest benchmarks/cspt_lab.py -v
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytestmark = pytest.mark.lab

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8301")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8302")
ADMIN_MARKER = "osint-cspt-admin-marker"


def _reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "/openapi.json", timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def _wait_port(url: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _reachable(url):
            return True
        time.sleep(0.25)
    return False


class Twin:
    def __init__(self, mode: str, url: str):
        self.mode = mode
        self.url = url
        self.proc = None

    def start(self):
        env = dict(os.environ, TWIN_MODE=self.mode)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn",
             "benchmarks.labs.cspt_twin:app",
             "--host", "127.0.0.1",
             "--port", str(self.url.rsplit(":", 1)[1]),
             "--log-level", "warning"],
            env=env, cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return _wait_port(self.url)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture()
def twins():
    uvicorn = shutil.which("uvicorn") or (
        Path(sys.executable).parent / "uvicorn")
    if not Path(uvicorn).exists():
        pytest.skip("uvicorn not installed")
    try:
        import playwright.async_api  # noqa: F401
    except Exception:
        pytest.skip("playwright not installed")
    vuln = Twin("vuln", VULN_URL)
    fixed = Twin("fixed", FIXED_URL)
    if not vuln.start():
        pytest.skip(f"vulnerable twin unreachable at {VULN_URL}")
    if not fixed.start():
        vuln.stop()
        pytest.skip(f"fixed twin unreachable at {FIXED_URL}")
    yield vuln, fixed
    fixed.stop()
    vuln.stop()


def _module_config(base_url: str) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": {"alice": {
            "login": {"url": "/api/login", "method": "POST", "json": True,
                      "data": {"username": "alice",
                               "password": "alice-pass"},
                      "extract_token": True},
            "verify_url": "/api/reports/1",
            "success_marker": "alice",
        }}},
        "modules": {"cspt_audit": {
            "enabled": True,
            "targets": [base_url + "/app"],
            "max_payloads": 4,
            "max_targets": 1,
            "wait_ms": 400,
            "inject_points": ["query"],
            "inject_names": ["r"],
            "canary_route": {"sibling_paths": ["/admin/secrets"]},
            "impact_probe": {
                "enabled": True,
                "expect": {"type": "jsonpath", "path": "secret"},
                "equals": ADMIN_MARKER,
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.cspt_audit import CSPTAudit
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = CSPTAudit(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "cspt_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_cspt_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    assert vuln_result == "done"
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    assert proofs, "vulnerable twin produced no verified CSPT finding"
    assert proofs[0]["verification"].get("method") == "cspt_impact_observed"
    vuln_report = _report(vuln_state)
    altered = [p for p in vuln_report["pairs"]
               if p["state"] == "path_altered"]
    assert altered, "no path_altered pair recorded on the vulnerable twin"
    assert any(p["probe_path"].endswith("/admin/secrets")
               for p in altered), altered
    assert vuln_state.mutations.outstanding() == []

    assert fixed_result == "done"
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert not [p for p in fixed_report["pairs"]
                if p["state"] == "path_altered"]
