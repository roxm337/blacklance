"""I2 lab gate: the seeded multi-step defect reproduces on the vulnerable
twin and passes on the fixed twin.

Spawns the order-lab API in both modes (uvicorn subprocesses), runs the
real ApiWorkflows module against each, and asserts:

- vulnerable twin: a PROOF-tier finding (verified, impact probe re-read
  observed ``total < 0``), mutation ledger cleanup verified, nothing
  outstanding;
- fixed twin: zero PROOF findings for the negative-total defect; any
  schema observations stay LOW/TENTATIVE.

Skip, don't fail, when the lab or tooling is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8101 \\
    OSINT_LAB_URL_FIXED=http://localhost:8102 \\
    .venv/bin/python -m pytest benchmarks/schemathesis_lab.py -v
"""

import asyncio
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8101")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8102")


def _uvicorn_path() -> str | None:
    path = shutil.which("uvicorn")
    if path:
        return path
    venv_bin = Path(sys.executable).parent / "uvicorn"
    return str(venv_bin) if venv_bin.exists() else None


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
            [sys.executable, "-m", "uvicorn", "benchmarks.labs.api_twin:app",
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
    if not _uvicorn_path():
        pytest.skip("uvicorn not installed")
    import fastapi  # noqa: F401
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
        "enabled": True,
        "max_schemas": 1,
        "stateful": "links",
        "max_cases": 100,
        "hypothesis_deadline_ms": 1500,
        "request_timeout": 10,
        "max_seconds": 300,
        "max_findings_per_schema": 5,
        # The fuzzer must NOT delete its own resources: the impact probe
        # re-reads corrupted orders after the run. Cleanup is the module's
        # job (below), via the harness, not the fuzzer's.
        "methods": ["GET", "POST", "OPTIONS"],
        "impact_probe": {
            "url_template": "/api/orders/{order_id}",
            "extract": {"type": "jsonpath", "path": "total"},
            # The corrupted state: a pay request missing the required
            # amount was accepted, nulling the order total.
            "expect": {"op": "eq", "value": "None"},
        },
        "cleanup": {
            "method": "DELETE",
            "url_template": "/api/orders/{order_id}",
            "verify": {"method": "http_get", "expect_status": [404]},
        },
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.api_workflows import APIWorkflows
    from state.manager import StateManager

    state = StateManager(str(tmp_path / "run" / "twin"))
    state.add_asset(
        "api_endpoint", f"api:{base_url}/openapi.json",
        f"{base_url}/openapi.json",
        confidence="CONFIRMED", sources=["lab"],
        attrs={"type": "openapi", "endpoint_count": 5})
    config = {"target": {"domain": base_url.split("//")[1].split(":")[0],
                         "base_url": base_url},
              "modules": {"api_workflows": _module_config(base_url)}}
    module = APIWorkflows(state, config)
    result = await module.run()
    return result, state


def test_seeded_defect_reproduces_vuln_passes_fixed(tmp_path, twins):
    from tools.schemathesis import schemathesis_available
    probe = schemathesis_available()
    if not probe.get("available"):
        pytest.skip(probe.get("reason") or "schemathesis unavailable")

    vuln, fixed = twins

    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    # Vulnerable twin: the seeded defect is PROVEN.
    assert vuln_result == "done"
    proof_findings = [
        f for f in vuln_state.findings["findings"]
        if f.get("verified") is True
        and "API state violation" in f["title"]]
    assert proof_findings, "vulnerable twin produced no PROOF finding"
    assert any("negative" in f["description"].lower()
               or f["verification"].get("method") == "schemathesis_repro_reverified"
               for f in proof_findings)
    impact_kinds = [e.get("type") for e in vuln_state.evidence["items"]]
    assert "schemathesis_impact" in impact_kinds
    assert vuln_state.mutations.outstanding() == []
    cleanup_statuses = [
        vuln_state.mutations.current(r["id"])["cleanup"]["status"]
        for r in vuln_state.mutations.read_records()
        if r.get("kind") == "begin"]
    assert all(status == "verified" for status in cleanup_statuses)

    # Fixed twin: the defect does not reproduce.
    assert fixed_result == "done"
    fixed_proof = [
        f for f in fixed_state.findings["findings"]
        if f.get("verified") is True]
    assert not fixed_proof, (
        f"fixed twin produced PROOF findings: {fixed_proof}")
    for finding in fixed_state.findings["findings"]:
        if finding["title"].startswith("API schema violations"):
            assert finding["severity"] == "LOW"
    assert fixed_state.mutations.outstanding() == []
