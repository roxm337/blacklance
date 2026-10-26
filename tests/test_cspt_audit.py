"""I4 CSPT module tests: skip paths, three-state classification, impact
grading (candidate vs proof), and evidence. The browser driver is faked —
no Playwright needed."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from modules.cspt_audit import CSPTAudit
from state.manager import StateManager


class FakeHarness:
    def __init__(self, responder=None):
        self.mutations = None
        self.responder = responder or (lambda url: {"status": 404, "body": ""})
        self.identities = {}
        self.requests = []

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url=""):
        return list(self.identities.values())

    async def request(self, identity, url, method="GET", **kwargs):
        self.requests.append(("identity", identity, url))
        return self.responder(url)

    async def request_anonymous(self, url, method="GET", **kwargs):
        self.requests.append(("anonymous", url))
        return self.responder(url)


class FakeIdentity:
    def __init__(self, name):
        self.name = name
        self.verified = True

    def request_headers(self):
        return {"Authorization": "Bearer tok"}


TOKEN = "czabc123"


def _module(tmp_path, cfg=None, targets=None, fake_epochs=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    config = {"target": {"domain": "example.com",
                         "base_url": "https://example.com"},
              "modules": {"cspt_audit": dict(cfg or {})}}
    module = CSPTAudit(state, config)
    module._fake_epochs = fake_epochs
    if targets:
        config["modules"]["cspt_audit"]["targets"] = targets
    return module, state


def _run(module, monkeypatch, harness=None):
    import modules.cspt_audit as mod

    async def default_drive(url, point, name, token, payloads, wait_ms,
                            headers=None):
        return []

    async def drive(*args, **kwargs):
        return await (module._fake_epochs or default_drive)(*args, **kwargs)

    monkeypatch.setattr(mod, "_drive_epochs", drive)
    monkeypatch.setattr(mod, "AuthHarness", lambda config: harness or FakeHarness())
    return asyncio.run(module.run())


def test_skips_when_disabled(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": False})
    assert _run(module, monkeypatch) == "skipped"
    assert "disabled" in module.state.module["skipped"][-1]["reason"]


def test_skips_without_identities(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": True})
    assert _run(module, monkeypatch) == "skipped"
    assert "no verified identities" in module.state.module["skipped"][-1]["reason"]


def test_skips_without_playwright_when_no_driver_is_injected(monkeypatch,
                                                             tmp_path):
    import builtins

    module, state = _module(tmp_path, cfg={"enabled": True})
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if str(name).startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert asyncio.run(module.run()) == "skipped"
    assert "playwright not installed" in \
        state.module["skipped"][-1]["reason"]


def _epochs(token, natural_path, payloads, altered):
    from urllib.parse import unquote

    from core.urlpaths import server_view_path

    events = [{"epoch": "baseline", "method": "GET",
               "url": "https://example.com/api/reports/1"}]
    events.append({"epoch": "natural", "method": "GET",
                   "url": f"https://example.com{natural_path}",
                   "natural_url": f"https://example.com{natural_path}"})
    for payload in payloads:
        if altered:
            # Simulate `fetch('/api/' + input)`: the browser resolves dots.
            resolved = server_view_path(
                "https://example.com/api/" + unquote(payload))
            events.append({"epoch": "payload", "method": "GET",
                           "url": resolved,
                           "payload": payload,
                           "natural_url": f"https://example.com{natural_path}"})
        else:
            events.append({"epoch": "payload", "method": "GET",
                           "url": f"https://example.com{natural_path}",
                           "payload": payload,
                           "natural_url": f"https://example.com{natural_path}"})
    return events


def test_not_reached_is_observation_only(monkeypatch, tmp_path):
    async def drive(url, point, name, token, payloads, wait_ms, headers=None):
        return [{"epoch": "baseline", "method": "GET", "url": url}]

    harness = FakeHarness()
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(tmp_path, cfg={"enabled": True},
                            fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    assert state.findings["findings"] == []
    report = _report(state)
    assert report["state_counts"].get("not_reached", 0) >= 1


def test_unchanged_is_no_signal(monkeypatch, tmp_path):
    async def drive(url, point, name, token, payloads_arg, wait_ms, headers=None):
        return _epochs(token, f"/api/reports/{token}", payloads_arg,
                       altered=False)

    harness = FakeHarness()
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(tmp_path, cfg={"enabled": True,
                                           "inject_points": ["query"]},
                            fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    assert state.findings["findings"] == []
    report = _report(state)
    assert report["state_counts"].get("unchanged", 0) >= 1


def test_altered_without_impact_probe_is_candidate(monkeypatch, tmp_path):
    async def drive(url, point, name, token, payloads, wait_ms, headers=None):
        return _epochs(token, f"/api/reports/{token}", payloads, altered=True)

    harness = FakeHarness()
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(
        tmp_path, cfg={"enabled": True, "inject_points": ["query"],
                       "impact_probe": {"enabled": False}},
        fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    findings = state.findings["findings"]
    assert findings and findings[0]["verified"] is False


def test_altered_without_configured_expect_stays_candidate(monkeypatch, tmp_path):
    async def drive(url, point, name, token, payloads, wait_ms, headers=None):
        return _epochs(token, f"/api/reports/{token}", payloads, altered=True)

    def responder(url):
        if "/admin/" in url and "zz-absent" not in url:
            return {"status": 200, "body": '{"note": "different"}'}
        if "/api/reports/" in url:
            return {"status": 200, "body": '{"note": "base"}'}
        return {"status": 404, "body": ""}

    harness = FakeHarness(responder=responder)
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(
        tmp_path, cfg={"enabled": True, "inject_points": ["query"],
                       "impact_probe": {"enabled": True}},
        fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    findings = state.findings["findings"]
    assert findings and findings[0]["verified"] is False
    assert "candidate" in findings[0]["title"].lower()


def test_altered_with_expect_proves_impact(monkeypatch, tmp_path):
    async def drive(url, point, name, token, payloads, wait_ms, headers=None):
        events = _epochs(token, f"/api/reports/{token}", payloads, altered=False)
        events.append({"epoch": "payload", "method": "GET",
                       "url": f"https://example.com/admin/secrets?cspt={token}",
                       "payload": "..%2f..%2fadmin%2fsecrets",
                       "natural_url": f"https://example.com/api/reports/{token}"})
        return events

    def responder(url):
        if "/admin/secrets" in url and "zz-absent" not in url:
            return {"status": 200, "body": '{"secret": "osint-marker"}'}
        if "/admin/zz-absent-secrets" in url:
            return {"status": 200, "body": '{"error": "no such secret"}'}
        if "/api/reports/" in url:
            return {"status": 200, "body": '{"secret": null}'}
        return {"status": 404, "body": ""}

    harness = FakeHarness(responder=responder)
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(
        tmp_path, cfg={"enabled": True, "inject_points": ["query"],
                       "impact_probe": {
                           "enabled": True,
                           "expect": {"type": "jsonpath", "path": "secret"},
                           "equals": "osint-marker"}},
        fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    findings = state.findings["findings"]
    assert len(findings) == 1
    assert findings[0]["verified"] is True
    assert findings[0]["verification"]["method"] == "cspt_impact_observed"
    assert "cspt_impact" in [e["type"] for e in state.evidence["items"]]
    assert "cspt_report" in [e["type"] for e in state.evidence["items"]]


def test_segment_prefix_sibling_is_not_an_escape(monkeypatch, tmp_path):
    """A sibling sharing a string prefix must not classify as altered."""
    async def drive(url, point, name, token, payloads, wait_ms, headers=None):
        return [
            {"epoch": "natural", "method": "GET",
             "url": f"https://example.com/api/reports/{token}",
             "natural_url": f"https://example.com/api/reports/{token}"},
            {"epoch": "payload", "method": "GET",
             "url": "https://example.com/api/reports-archive/1",
             "payload": "reports-archive/1",
             "natural_url": f"https://example.com/api/reports/{token}"},
        ]

    harness = FakeHarness()
    harness.identities = {"alice": FakeIdentity("alice")}
    module, state = _module(tmp_path, cfg={"enabled": True,
                                           "inject_points": ["query"]},
                            fake_epochs=drive)
    assert _run(module, monkeypatch, harness=harness) == "done"
    report = _report(state)
    altered = [p for p in report["pairs"] if p["state"] == "path_altered"]
    assert altered == []


def _report(state) -> dict:
    item = next(e for e in state.evidence["items"]
                if e.get("type") == "cspt_report")
    path = Path(state.output_dir) / item["path"]
    return json.loads(path.read_text(encoding="utf-8"))["data"]
