"""H2.CL/H2.TE oracle: only stream 3 answering the ghost counts."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.http_smuggling import HTTPSmuggling, h2_verdict
from state.manager import StateManager


def _module():
    config = {
        "target": {"domain": "acme.test", "base_url": "https://acme.test"},
        "modules": {"http_smuggling": {"h2": True}},
        "waf": {}, "paths": {}, "auth": {},
    }
    return HTTPSmuggling(
        StateManager(str(Path(tempfile.mkdtemp()) / "acme.test")), config)


def test_a_marker_on_the_next_stream_is_proof():
    responses = {1: {"status": 200, "body": "ok"},
                 3: {"status": 404, "body": "not found: h2ghost-abcd"}}
    proven, note = h2_verdict(responses, "h2ghost-abcd")
    assert proven is True
    assert "stream 3" in note


def test_an_echo_on_the_attacker_stream_is_not_proof():
    responses = {1: {"status": 200, "body": "you sent: h2ghost-abcd"},
                 3: {"status": 200, "body": "welcome"}}
    proven, note = h2_verdict(responses, "h2ghost-abcd")
    assert proven is False
    assert "no marker" in note


def test_a_missing_stream_is_not_proof():
    assert h2_verdict({}, "h2ghost-abcd")[0] is False
    assert h2_verdict({3: {"status": 0, "body": ""}}, "")[0] is False


def test_h2_desync_files_a_confirmed_finding(monkeypatch):
    module = _module()

    def fake_probe(target, mode):
        return True, "stream 3 answered the ghost path (HTTP 404)"

    monkeypatch.setattr(module, "_h2_probe", fake_probe)
    proven = asyncio.run(module._h2_desync("https://acme.test/"))
    assert proven is True
    finding = module.state.findings["findings"][0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verification"]["method"] == "h2_cl_desync_oracle"
    assert finding["category"] == "HTTP Request Smuggling"


def test_no_alpn_means_no_finding(monkeypatch):
    module = _module()

    def no_h2(target, mode):
        return False, "no h2: ALPN did not negotiate h2"

    monkeypatch.setattr(module, "_h2_probe", no_h2)
    assert asyncio.run(module._h2_desync("https://acme.test/")) is False
    assert module.state.findings["findings"] == []
