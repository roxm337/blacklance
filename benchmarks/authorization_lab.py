"""I3 lab gate: the seeded cross-tenant invoice leak is proven by a canary
on the vulnerable twin and absent on the fixed twin.

Spawns the authz twin in both modes, runs the real IdorDiffer module with
the authorization matrix + canary enabled, and asserts:

- vulnerable twin: canary PROOF finding (verified, method
  canary_read_attributed), mutation cleanup verified, revocation proven;
- fixed twin: zero verified findings and zero leak candidates.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8201 \\
    OSINT_LAB_URL_FIXED=http://localhost:8202 \\
    .venv/bin/python -m pytest benchmarks/authorization_lab.py -v
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8201")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8202")

IDENTITIES = {
    "alice": {"password": "alice-pass"},
    "bob": {"password": "bob-pass"},
}


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
             "benchmarks.labs.authz_twin:app",
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
    login = {
        "url": "/api/login", "method": "POST", "json": True,
        "success_marker": "token",
    }
    identities = {
        name: {
            "password": spec["password"],
            "login": {**login, "data": {"username": name,
                                        "password": spec["password"]},
                      "extract_token": True},
            "verify_url": "/dashboard",
            "success_marker": f"welcome {name}",
            "logout_url": "/api/logout",
            "logout_method": "POST",
        }
        for name, spec in IDENTITIES.items()
    }
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": identities},
        "modules": {"idor_differ": {
            "endpoints": [f"{base_url}/api/invoices/1",
                          f"{base_url}/api/invoices/2"],
            "matrix": {
                "enabled": True,
                "max_cells": 20,
                "sharing": [{"read_probe": "/api/shared/{id}", "ids": [9]}],
                "revocation": {"enabled": True},
                "canaries": {
                    "max": 1,
                    "specs": [{
                        "name": "invoice-read",
                        "owner_identity": "bob",
                        "forbidden_identity": "alice",
                        "seed": "osint-canary-lab",
                        "create": {
                            "method": "POST",
                            "url_template": "/api/invoices",
                            "body_template": '{"note": "osint-canary-lab"}',
                            "extract_id": {"type": "jsonpath", "path": "id"},
                        },
                        "read_probe": {
                            "url_template": "/api/invoices/{id}",
                            "extract": {"type": "jsonpath", "path": "note"},
                            "expect": {"op": "eq",
                                       "value": "osint-canary-lab"},
                        },
                        "cleanup": {
                            "method": "DELETE",
                            "url_template": "/api/invoices/{id}",
                            "verify": {"method": "http_get",
                                       "expect_status": [404]},
                        },
                    }],
                },
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.idor_differ import IdorDiffer
    from state.manager import StateManager
    from tools import wrappers
    # Loopback lab: the module walks hundreds of URLs; the production
    # per-minute cap would turn this acceptance into an hour-long queue.
    # Same convention as the aiohttp fixtures in tests/.
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    config = _module_config(base_url)
    module = IdorDiffer(state, config)
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def test_canary_proven_vuln_absent_fixed(tmp_path, twins):
    vuln, fixed = twins
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    # Vulnerable twin: canary PROOF + verified cleanup + revocation.
    assert vuln_result == "done"
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    assert proofs, "vulnerable twin produced no verified canary finding"
    assert proofs[0]["verification"].get("method") == "canary_read_attributed"
    assert vuln_state.mutations.outstanding() == []
    matrix_evidence = next(
        e for e in vuln_state.evidence["items"]
        if e.get("type") == "matrix_report")
    import json
    payload = json.loads(
        (Path(vuln_state.output_dir) / matrix_evidence["path"])
        .read_text(encoding="utf-8"))
    assert payload["data"]["checks"]["revocation"]["status"] == "proven"
    assert payload["data"]["checks"]["sharing"]["ok"] >= 1

    # Fixed twin: no verified findings, no leak candidates.
    assert fixed_result == "done"
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    assert not [f for f in fixed_state.findings["findings"]
                if "Authorization matrix leak" in f["title"]]
    assert fixed_state.mutations.outstanding() == []
