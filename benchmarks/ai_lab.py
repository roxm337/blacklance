"""I8 lab gate: AI conversation isolation defects are proven by seeded
canaries on the vulnerable twin and absent on the fixed twin.

Spawns the aiohttp chat/retrieval twin in both modes, runs the real
AIConversationAudit module, and asserts:

- vulnerable twin: thread-read, cross-identity continue and retrieval
  canaries reach PROOF; cleanup verified; nothing outstanding;
- fixed twin: no verified findings, cleanup still verified;
- hostile reply prose never reaches the report in either mode.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8507 \\
    OSINT_LAB_URL_FIXED=http://localhost:8508 \\
    .venv/bin/python -m pytest benchmarks/ai_lab.py -v
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8507")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8508")


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
            [sys.executable, "-m", "benchmarks.labs.ai_twin",
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
    }


def _module_config(base_url: str) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": [_identity("alice"), _identity("bob")]},
        "modules": {"ai_conversation_audit": {
            "enabled": True,
            "max_seconds": 120,
            "canary": {
                "enabled": True,
                "owner_identity": "bob",
                "forbidden_identity": "alice",
                "max": 3,
                "thread": {
                    "create": {
                        "method": "POST", "url_template": "/api/threads",
                        "body_template": '{"title":"canary thread"}',
                        "extract_id": {"type": "jsonpath", "path": "id"},
                    },
                    "post": {
                        "method": "POST",
                        "url_template": "/api/threads/{id}/messages",
                        "body_template": '{"text":"{run}"}',
                    },
                    "read": {
                        "method": "GET",
                        "url_template": "/api/threads/{id}",
                        "extract": {"type": "jsonpath",
                                    "path": "messages.0.text"},
                    },
                    "list": {"method": "GET", "url_template": "/api/threads"},
                    "continue": {
                        "method": "POST",
                        "url_template": "/api/threads/{id}/messages",
                        "body_template": '{"text":"continue"}',
                    },
                    "cleanup": {
                        "method": "DELETE",
                        "url_template": "/api/threads/{id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404, 410]},
                    },
                },
                "retrieval": {
                    "create": {
                        "method": "POST", "url_template": "/api/documents",
                        "body_template": '{"text":"{run}"}',
                        "extract_id": {"type": "jsonpath", "path": "id"},
                    },
                    "ask": {
                        "method": "POST", "url_template": "/api/ask",
                        "body_template": '{"query":"{seed}"}',
                        "extract": {"type": "jsonpath", "path": "answer"},
                    },
                    "cleanup": {
                        "method": "DELETE",
                        "url_template": "/api/documents/{id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404, 410]},
                    },
                },
                "probes": [
                    {"name": "thread-read", "mode": "thread"},
                    {"name": "thread-continue", "mode": "continue"},
                    {"name": "retrieval-leak", "mode": "retrieval"},
                ],
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.ai_conversation_audit import AIConversationAudit
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = AIConversationAudit(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "ai_conversation_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_conversation_isolation_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    assert vuln_result == "done", vuln_state.module
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    methods = {f["verification"].get("method") for f in proofs}
    assert {"ai_thread_canary", "ai_continue_canary",
            "ai_retrieval_canary"} <= methods, \
        [f["title"] for f in vuln_state.findings["findings"]]
    vuln_report = _report(vuln_state)
    assert vuln_report["state_counts"]["proof"] >= 3, \
        vuln_report["state_counts"]
    by_name = {entry["name"]: entry for entry in vuln_report["canaries"]}
    assert by_name["thread-read"]["proven"] is True
    assert by_name["thread-continue"]["proven"] is True
    assert by_name["retrieval-leak"]["proven"] is True
    assert vuln_report["hostile_responses"] >= 1
    assert "ignore previous instructions" not in json.dumps(vuln_report)
    assert "system prompt" not in json.dumps(vuln_report)
    assert vuln_state.mutations.outstanding() == []

    assert fixed_result == "done", fixed_state.module
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert fixed_report["state_counts"]["proof"] == 0
    assert all(not entry["proven"] for entry in fixed_report["canaries"])
    assert "ignore previous instructions" not in json.dumps(fixed_report)
    assert fixed_state.mutations.outstanding() == []
