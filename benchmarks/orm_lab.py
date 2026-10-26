"""I5 lab gate: the filter-inclusion defect is proven by a seeded canary
on the vulnerable twin and absent on the fixed twin.

Spawns the ORM twin in both modes, runs the real ORMFilterAudit module
(real HTTP), and asserts:

- vulnerable twin: verified ``filter_canary_observed`` finding, canary
  direct read 404, seed intact, cleanup verified, nothing outstanding;
- fixed twin: no verified findings, cleanup still verified (the canary
  lifecycle is exercised on both), nothing outstanding.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8401 \\
    OSINT_LAB_URL_FIXED=http://localhost:8402 \\
    .venv/bin/python -m pytest benchmarks/orm_lab.py -v
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8401")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8402")


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
             "benchmarks.labs.orm_twin:app",
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
    login = {"url": "/api/login", "method": "POST", "json": True,
             "extract_token": True}
    identities = {
        name: {
            "login": {**login,
                      "data": {"username": name, "password": f"{name}-pass"}},
            "verify_url": "/api/me",
            "success_marker": name,
        }
        for name in ("alice", "bob")
    }
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": identities},
        "modules": {"orm_filter_audit": {
            "enabled": True,
            "surfaces": [{"url": base_url + "/api/items",
                          "filter_params": ["q"]}],
            "traffic_surfaces": False,
            "augment_collections": False,
            "max_surfaces": 1,
            "max_payloads": 0,
            "vector_values": [],
            "canary": {
                "enabled": True,
                "owner_identity": "bob",
                "forbidden_identity": "alice",
                "max": 1,
                "record": {"method": "POST",
                           "url_template": "/api/items",
                           "body_template": '{"name": "{run}"}',
                           "extract_id": {"type": "jsonpath",
                                          "path": "id"}},
                "read": {"direct_url_template": "/api/items/{id}",
                         "extract": {"type": "jsonpath",
                                     "path": "name"}},
                "probes": [{"name": "items-q",
                            "url_template": "/api/items",
                            "param": "q",
                            "bind": "seed",
                            "extract": {"type": "jsonpath",
                                        "path": "data.0.name"}}],
                "cleanup": {"method": "DELETE",
                            "url_template": "/api/items/{id}",
                            "verify": {"method": "http_get",
                                       "expect_status": [404, 410]}},
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.orm_filter_audit import ORMFilterAudit
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = ORMFilterAudit(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "orm_filter_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_filter_leak_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    assert vuln_result == "done"
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    assert proofs, "vulnerable twin produced no verified filter finding"
    assert proofs[0]["verification"].get("method") == "filter_canary_observed"
    vuln_report = _report(vuln_state)
    assert vuln_report["state_counts"]["proof"] >= 1
    canary = vuln_report["canaries"][0]
    assert canary["proven"] is True
    assert canary["direct_read_status"] in (403, 404)
    assert canary["seed_intact"] is True
    assert canary["cleanup_status"] == "verified"
    assert vuln_state.mutations.outstanding() == []

    assert fixed_result == "done"
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert fixed_report["state_counts"]["proof"] == 0
    assert fixed_report["canaries"][0]["proven"] is False
    assert fixed_state.mutations.outstanding() == []
