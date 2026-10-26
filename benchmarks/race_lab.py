"""I6 lab gate: seeded race defects are proven by serial/concurrent
contrast on the vulnerable twin and absent on the fixed twin.

Spawns the race twin in both modes, runs the real BusinessLogic module
with the race pass enabled (real HTTP, bounded concurrency), and asserts:

- vulnerable twin: both invariants (coupon single-redeem, payment
  idempotency) reach PROOF — serial replay legal, concurrent batch breaks
  the invariant, cleanup verified, nothing outstanding;
- fixed twin: no verified race findings, cleanup still verified.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8501 \\
    OSINT_LAB_URL_FIXED=http://localhost:8502 \\
    .venv/bin/python -m pytest benchmarks/race_lab.py -v
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8501")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8502")


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
             "benchmarks.labs.race_twin:app",
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


def _invariants() -> list[dict]:
    return [
        {
            "name": "coupon-single-redeem",
            "kind": "single_use",
            "identity": "alice",
            "limit_semantics": "a one-time coupon must never grant more than once",
            "setup": {
                "method": "POST", "url_template": "/api/coupons",
                "body_template": '{"code": "RACE-{run}", "value": 10}',
                "headers": {"Content-Type": "application/json"},
                "extract_ids": [{"type": "jsonpath", "path": "id"}],
            },
            "operation": {
                "method": "POST", "url_template": "/api/coupons/{id}/redeem",
                "headers": {"Content-Type": "application/json"},
                "success_status": [200],
            },
            "serial_control": {"enabled": True, "expect_second": "rejected",
                               "settle_ms": 120},
            "invariant": {
                "read_probe": {"method": "GET",
                               "url_template": "/api/coupons/{id}"},
                "extract": {"type": "jsonpath", "path": "grants"},
                "expect": [{"op": "lte", "value": 1}],
                "settle_ms": 150, "read_attempts": 2,
            },
            "cleanup": {
                "method": "DELETE", "url_template": "/api/coupons/{id}",
                "verify": {"method": "http_get",
                           "expect_status": [404, 410]},
            },
        },
        {
            "name": "payment-idempotency",
            "kind": "idempotency",
            "identity": "alice",
            "limit_semantics": "one idempotency key must produce exactly one payment",
            "idempotency_key": {"mode": "header",
                                "header": "Idempotency-Key",
                                "value_template": "idem-{run}"},
            "operation": {
                "method": "POST", "url_template": "/api/payments",
                "body_template": '{"amount": 10}',
                "headers": {"Content-Type": "application/json"},
                "success_status": [200, 201],
                "extract_ids": [{"type": "jsonpath", "path": "id"}],
            },
            "serial_control": {"enabled": True,
                               "expect_second": "single_effect",
                               "settle_ms": 120},
            "invariant": {
                "read_probe": {"method": "GET",
                               "url_template": "/api/account"},
                "extract": {"type": "jsonpath", "path": "payment_count"},
                "expect": [{"op": "eq", "value": 1, "delta": True}],
                "settle_ms": 150, "read_attempts": 2,
            },
            "cleanup": {
                "effects": {
                    "method": "DELETE",
                    "url_template": "/api/payments/{id}",
                    "verify": {"method": "http_get",
                               "expect_status": [404, 410]},
                },
            },
        },
    ]


def _module_config(base_url: str) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": {"alice": {
            "login": {"url": "/api/login", "method": "POST", "json": True,
                      "data": {"username": "alice",
                               "password": "alice-pass"},
                      "extract_token": True},
            "verify_url": "/api/me",
            "success_marker": "alice",
        }}},
        "modules": {"business_logic": {
            "enabled": True,
            "max_probes": 0,
            "endpoints": [],
            "race": {
                "enabled": True,
                "max_invariants": 3,
                "trials": 4,
                "concurrency": 4,
                "max_seconds": 120,
                "invariants": _invariants(),
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.business_logic import BusinessLogic
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = BusinessLogic(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "race_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_race_defects_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    # Vulnerable twin: both invariants proven.
    assert vuln_result == "done"
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    assert len(proofs) >= 2, [f["title"] for f in vuln_state.findings["findings"]]
    assert all(f["verification"].get("method") == "race_invariant_violated"
               for f in proofs)
    vuln_report = _report(vuln_state)
    assert vuln_report["state_counts"]["proof"] >= 2, vuln_report["state_counts"]
    by_name = {entry["name"]: entry for entry in vuln_report["invariants"]}
    coupon = by_name["coupon-single-redeem"]
    assert coupon["serial"]["second_accepted"] is False
    assert coupon["concurrent"]["accepted"] >= 2
    assert coupon["state"] == "proof"
    payment = by_name["payment-idempotency"]
    assert payment["concurrent"]["accepted"] >= 2
    assert payment["state"] == "proof"
    assert vuln_state.mutations.outstanding() == []

    # Fixed twin: no proofs, cleanup still verified.
    assert fixed_result == "done"
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert fixed_report["state_counts"]["proof"] == 0
    assert fixed_state.mutations.outstanding() == []
