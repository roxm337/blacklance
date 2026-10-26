"""I7 lab gate: WebSocket authorization defects are proven by seeded
canaries on the vulnerable twin and absent on the fixed twin.

Spawns the aiohttp twin in both modes, runs the real WebSocketAudit module
(real handshakes, real frames, real HTTP controls), and asserts:

- vulnerable twin: message, subscription, cross-origin and post-logout
  canaries reach PROOF; cleanup verified; nothing outstanding;
- fixed twin: no verified findings, foreign-origin handshake rejected,
  cleanup still verified.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8503 \\
    OSINT_LAB_URL_FIXED=http://localhost:8504 \\
    .venv/bin/python -m pytest benchmarks/websocket_lab.py -v
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytestmark = pytest.mark.lab

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8503")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8504")


def _reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "/health", timeout=3) as response:
            return response.status == 200
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
            [sys.executable, "-m", "benchmarks.labs.ws_twin",
             "--host", "127.0.0.1",
             "--port", str(self.url.rsplit(":", 1)[1])],
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
    import aiohttp  # noqa: F401  (twin runtime dependency)
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


def _identity(name: str) -> dict:
    return {
        "name": name,
        "login": {"url": "/api/login", "method": "POST", "json": True,
                  "data": {"username": name, "password": f"{name}-pass"}},
        "verify_url": "/api/me",
        "success_marker": name,
        "logout_url": "/api/logout",
    }


def _canary_probes() -> list[dict]:
    return [
        {"name": "message-authz", "mode": "message",
         "send_template": '{"type":"read","id":"{id}","req":"{run}"}',
         "extract": {"type": "jsonpath", "path": "name"}},
        {"name": "subscription-leak", "mode": "subscription",
         "send_template": '{"type":"subscribe","channel":"obj-{id}",'
                          '"req":"{run}"}',
         "extract": {"type": "jsonpath", "path": "name"}},
        {"name": "cross-origin-read", "mode": "origin",
         "send_template": '{"type":"read","id":"{id}","req":"{run}"}',
         "extract": {"type": "jsonpath", "path": "name"}},
        {"name": "stale-session", "mode": "revocation", "identity": "alice",
         "send_template": '{"type":"read","id":"{id}","req":"{run}"}',
         "extract": {"type": "jsonpath", "path": "name"}},
    ]


def _module_config(base_url: str) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": [_identity("alice"), _identity("bob")]},
        "modules": {"websocket_audit": {
            "enabled": True,
            "sockets": [{"url": "/ws"}],
            "capture": {"enabled": False},
            "origin_probe": "https://evil.example",
            "max_seconds": 90,
            "connect_timeout": 5,
            "read_timeout": 1,
            "window": 2,
            "max_frames": 20,
            "canary": {
                "enabled": True,
                "owner_identity": "bob",
                "forbidden_identity": "alice",
                "max": 4,
                "record": {
                    "method": "POST", "url_template": "/api/objects",
                    "body_template": '{"name": "{run}"}',
                    "extract_id": {"type": "jsonpath", "path": "id"},
                },
                "read": {
                    "direct_url_template": "/api/objects/{id}",
                    "extract": {"type": "jsonpath", "path": "name"},
                },
                "probes": _canary_probes(),
                "cleanup": {
                    "method": "DELETE", "url_template": "/api/objects/{id}",
                    "verify": {"method": "http_get",
                               "expect_status": [404, 410]},
                },
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.websocket_audit import WebSocketAudit
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = WebSocketAudit(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "websocket_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_websocket_authorization_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    # Vulnerable twin: every seeded canary lane is proven.
    assert vuln_result == "done", vuln_state.module
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    methods = {f["verification"].get("method") for f in proofs}
    assert {"ws_message_canary", "ws_subscription_canary",
            "ws_origin_canary", "ws_revocation_canary"} <= methods, \
        [f["title"] for f in vuln_state.findings["findings"]]
    vuln_report = _report(vuln_state)
    assert vuln_report["state_counts"]["proof"] >= 4, \
        vuln_report["state_counts"]
    by_name = {entry["name"]: entry for entry in vuln_report["canaries"]}
    assert by_name["message-authz"]["proven"] is True
    assert by_name["subscription-leak"]["proven"] is True
    assert by_name["cross-origin-read"]["proven"] is True
    assert by_name["stale-session"]["proven"] is True
    assert by_name["stale-session"]["post_logout_http_denied"] is True
    assert vuln_state.mutations.outstanding() == []

    # Fixed twin: no proofs, origin rejected, cleanup still verified.
    assert fixed_result == "done", fixed_state.module
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert fixed_report["state_counts"]["proof"] == 0
    handshake = fixed_report["handshakes"][0]
    assert handshake["foreign_origin"]["accepted"] is False
    assert all(not entry["proven"] for entry in fixed_report["canaries"])
    assert fixed_state.mutations.outstanding() == []
