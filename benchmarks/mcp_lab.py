"""I8 lab gate: MCP authorization defects are proven by seeded canaries on
the vulnerable twin and absent on the fixed twin.

Spawns the aiohttp MCP twin in both modes, runs the real MCPAudit module
(real JSON-RPC, sessions, tools and resources), and asserts:

- vulnerable twin: tool, resource, session-ownership and cross-audience
  canaries reach PROOF; cleanup verified; nothing outstanding;
- fixed twin: no verified findings, foreign-audience initialize rejected,
  cleanup still verified.

Skip, don't fail, when the lab is unavailable:
    OSINT_LAB_URL_VULN=http://localhost:8505 \\
    OSINT_LAB_URL_FIXED=http://localhost:8506 \\
    .venv/bin/python -m pytest benchmarks/mcp_lab.py -v
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

VULN_URL = os.environ.get("OSINT_LAB_URL_VULN", "http://localhost:8505")
FIXED_URL = os.environ.get("OSINT_LAB_URL_FIXED", "http://localhost:8506")


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
            [sys.executable, "-m", "benchmarks.labs.mcp_twin",
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


def _identity(name: str, token: str, verify_url: str) -> dict:
    return {
        "name": name,
        "headers": {"Authorization": f"Bearer {token}"},
        "verify_url": verify_url,
        "success_marker": name.split("_")[0],
    }


def _canary_probes() -> list[dict]:
    read_tool = {"tool": "read_note", "arguments": {"id": "{id}"},
                 "extract": {"type": "jsonpath",
                             "path": "structuredContent.text"}}
    return [
        {"name": "tool-authz", "mode": "tool", "server": "app",
         "read": read_tool},
        {"name": "resource-authz", "mode": "resource", "server": "app",
         "read": {"uri_template": "note://{id}",
                  "extract": {"type": "jsonpath",
                              "path": "contents.0.text"}}},
        {"name": "session-ownership", "mode": "session", "server": "app",
         "identity": "alice", "read": read_tool},
        {"name": "audience-cross", "mode": "audience", "server": "alt",
         "owner_identity": "bob_alt", "forbidden_identity": "alice",
         "read": read_tool},
    ]


def _module_config(base_url: str) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "auth": {"identities": [
            _identity("alice", "token-alice", "/a/me"),
            _identity("bob", "token-bob", "/a/me"),
            _identity("bob_alt", "token-bob-alt", "/b/me"),
        ]},
        "modules": {"mcp_audit": {
            "enabled": True,
            "servers": [
                {"name": "app", "url": "/a/mcp"},
                {"name": "alt", "url": "/b/mcp"},
            ],
            "audience_checks": [{
                "name": "alice-on-alt", "identity": "alice",
                "server": "alt", "expected": "rejected"}],
            "max_seconds": 120,
            "timeout": 10,
            "protocol_version": "2025-03-26",
            "canary": {
                "enabled": True,
                "owner_identity": "bob",
                "forbidden_identity": "alice",
                "server": "app",
                "max": 4,
                "seed": {
                    "tool": "create_note",
                    "arguments": {"text": "{run}"},
                    "extract": {"type": "jsonpath",
                                "path": "structuredContent.id"},
                },
                "cleanup": {
                    "tool": "delete_note",
                    "arguments": {"id": "{id}"},
                    "verify": {"tool": "read_note",
                               "arguments": {"id": "{id}"},
                               "expect": "error"},
                },
                "probes": _canary_probes(),
            },
        }},
    }


async def _run_against(base_url: str, tmp_path: Path):
    from modules.mcp_audit import MCPAudit
    from state.manager import StateManager
    from tools import wrappers
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    state = StateManager(str(tmp_path / "run" / "twin"))
    module = MCPAudit(state, _module_config(base_url))
    try:
        result = await module.run()
    finally:
        await wrappers.close_engine()
    return result, state


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "mcp_report")
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


def test_mcp_authorization_proven_vuln_absent_fixed(tmp_path, twins):
    vuln_result, vuln_state = asyncio.run(
        _run_against(VULN_URL, tmp_path / "vuln"))
    fixed_result, fixed_state = asyncio.run(
        _run_against(FIXED_URL, tmp_path / "fixed"))

    assert vuln_result == "done", vuln_state.module
    proofs = [f for f in vuln_state.findings["findings"]
              if f.get("verified") is True]
    methods = {f["verification"].get("method") for f in proofs}
    assert {"mcp_tool_canary", "mcp_resource_canary", "mcp_session_canary",
            "mcp_audience_canary"} <= methods, \
        [f["title"] for f in vuln_state.findings["findings"]]
    vuln_report = _report(vuln_state)
    assert vuln_report["state_counts"]["proof"] >= 4, \
        vuln_report["state_counts"]
    by_name = {entry["name"]: entry for entry in vuln_report["canaries"]}
    assert by_name["tool-authz"]["proven"] is True
    assert by_name["resource-authz"]["proven"] is True
    assert by_name["session-ownership"]["proven"] is True
    assert by_name["audience-cross"]["proven"] is True
    assert vuln_report["audience_checks"][0]["accepted"] is True
    assert "ignore previous instructions" not in json.dumps(vuln_report)
    assert "system prompt" not in json.dumps(vuln_report)
    assert vuln_state.mutations.outstanding() == []

    assert fixed_result == "done", fixed_state.module
    assert not [f for f in fixed_state.findings["findings"]
                if f.get("verified") is True]
    fixed_report = _report(fixed_state)
    assert fixed_report["state_counts"]["proof"] == 0
    assert fixed_report["audience_checks"][0]["accepted"] is False
    assert all(not entry["proven"] for entry in fixed_report["canaries"])
    assert fixed_state.mutations.outstanding() == []
