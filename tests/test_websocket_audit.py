"""I7 websocket_audit tests: skip paths, handshake grading, canary PROOF
modes (message/subscription/origin/revocation), candidate caps, and
cleanup discipline. Transport is faked — the engine has its own loopback
tests in tests/test_websocket_engine.py."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

from modules.websocket_audit import WebSocketAudit
from state.manager import StateManager
from tools import websocket_engine as ws

EVIL = "https://evil.example"


class FakeIdentity:
    def __init__(self, name, markers=()):
        self.name = name
        self.verified = True
        self.cookies = {"sid": name}
        self.headers = {}
        self._markers = tuple(markers)
        self.logged_out = False

    def own_markers(self):
        return set(self._markers)

    def request_headers(self):
        return {"Authorization": f"Bearer {self.name}"}

    def has_credentials(self):
        return True

    async def logout(self, base_url=""):
        self.logged_out = True
        self.cookies = {}
        return True

    async def establish(self, base_url=""):
        self.logged_out = False
        return True


class FakeHarness:
    def __init__(self, identities=None):
        self.mutations = None
        self.identities = {i.name: i for i in (identities or [])}
        self.responder = lambda i, u, m, d: {"status": 404, "body": ""}
        self.calls = []

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url=""):
        return list(self.identities.values())

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        self.calls.append((identity, method, url, data))
        return self.responder(identity, url, method, data)

    async def request_anonymous(self, url, method="GET", headers=None,
                                data=None, **kwargs):
        self.calls.append(("anonymous", method, url, data))
        return self.responder("anonymous", url, method, data)


class Store:
    def __init__(self):
        self.objects = {}
        self.seq = 0
        self.seed = ""


def _http_responder(store, identities, *, direct_leak=False,
                    cleanup_fails=False):
    def responder(identity, url, method, data):
        parsed = urlparse(url)
        if method == "POST" and parsed.path == "/api/objects":
            body = json.loads(data or "{}")
            store.seq += 1
            store.seed = str(body.get("name") or "")
            store.objects[store.seq] = {
                "id": store.seq, "name": store.seed, "owner": identity}
            return {"status": 201, "body": json.dumps({"id": store.seq})}
        if parsed.path.startswith("/api/objects/"):
            ref = parsed.path.rsplit("/", 1)[-1]
            ident = identities.get(identity)
            if ident is not None and getattr(ident, "logged_out", False):
                return {"status": 401, "body": ""}
            if method == "DELETE":
                if not cleanup_fails:
                    store.objects.pop(int(ref), None)
                return {"status": 204, "body": ""}
            obj = store.objects.get(int(ref))
            if not obj:
                return {"status": 404, "body": ""}
            if direct_leak or obj["owner"] == identity:
                return {"status": 200, "body": json.dumps(obj)}
            return {"status": 404, "body": ""}
        return {"status": 404, "body": ""}
    return responder


def _ws_responder(store, *, ws_leaks=True, public=False,
                  push_on_connect=False, accept_origin=True):
    def allowed(identity, obj):
        if identity == "anonymous":
            return public
        return identity == obj["owner"] or ws_leaks

    def responder(identity, sends, origin):
        if origin == EVIL and not accept_origin:
            return []
        if not sends:
            return ([json.dumps({"name": store.seed})]
                    if push_on_connect else [])
        texts = []
        for raw in sends:
            try:
                message = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if message.get("type") == "read":
                ref = str(message.get("id"))
                obj = store.objects.get(int(ref)) if ref.isdigit() else None
            elif message.get("type") == "subscribe":
                ref = str(message.get("channel") or "").removeprefix("obj-")
                obj = store.objects.get(int(ref)) if ref.isdigit() else None
            else:
                continue
            if obj and allowed(identity, obj):
                texts.append(json.dumps({"name": obj["name"]}))
            else:
                texts.append(json.dumps({"error": "denied"}))
        return texts
    return responder


def _fake_session(responder, *, accept_origin=True):
    async def fake(harness, socket, identity_name, sends, extract, *,
                   seed="", origin=""):
        if origin == EVIL and not accept_origin:
            return ws.SocketSession(url=socket["url"], status=403,
                                    accepted=False)
        texts = responder(identity_name, sends, origin)
        return ws.SocketSession(
            url=socket["url"], status=101, accepted=True,
            frames=[ws.Frame("received", t) for t in texts])
    return fake


class FakeClient:
    def __init__(self, replies, accepted=True):
        self.replies = list(replies)
        self.accepted = accepted
        self.sent = []
        self._index = 0

    async def send(self, text):
        self.sent.append(text)
        return True

    async def read_until(self, *, stop_on=None, max_frames=None, window=10.0):
        if self._index < len(self.replies):
            reply = self.replies[self._index]
            self._index += 1
            return reply
        return []

    async def close(self):
        pass


def _cfg(**overrides):
    cfg = {
        "enabled": True,
        "sockets": [{"url": "/ws"}],
        "capture": {"enabled": False},
        "origin_probe": EVIL,
        "max_seconds": 30,
        "connect_timeout": 1,
        "read_timeout": 0.2,
        "window": 0.5,
        "max_frames": 10,
        "canary": {
            "enabled": True,
            "owner_identity": "bob",
            "forbidden_identity": "alice",
            "max": 3,
            "record": {
                "method": "POST", "url_template": "/api/objects",
                "body_template": '{"name": "{run}"}',
                "extract_id": {"type": "jsonpath", "path": "id"},
            },
            "read": {
                "direct_url_template": "/api/objects/{id}",
                "extract": {"type": "jsonpath", "path": "name"},
            },
            "probes": [{
                "name": "message-authz", "mode": "message",
                "send_template": '{"type":"read","id":"{id}"}',
                "extract": {"type": "jsonpath", "path": "name"},
            }],
            "cleanup": {
                "method": "DELETE", "url_template": "/api/objects/{id}",
                "verify": {"method": "http_get", "expect_status": [404, 410]},
            },
        },
    }
    cfg.update(overrides)
    return cfg


def _module(tmp_path, cfg=None, identities=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    config = {"target": {"domain": "example.com", "base_url": "https://x"},
              "modules": {"websocket_audit": cfg if cfg is not None
                          else _cfg()}}
    module = WebSocketAudit(state, config)
    if identities is None:
        identities = [FakeIdentity("alice", markers=("alice@x.com",)),
                      FakeIdentity("bob", markers=("bob@x.com",))]
    harness = FakeHarness(identities=identities)
    return module, state, harness


def _run(module, monkeypatch, harness, *, accept_foreign=False,
         responder=None, accept_origin=True, client=None):
    import modules.websocket_audit as mod

    async def handshake(url, *, headers=None, origin="", subprotocols=(),
                        timeout=10.0, verify_tls=True):
        if origin and not accept_foreign:
            return ws.HandshakeResult(url=url, status=403, accepted=False)
        return ws.HandshakeResult(url=url, status=101, accepted=True)

    monkeypatch.setattr(mod, "AuthHarness", lambda config: harness)
    monkeypatch.setattr(mod.ws, "probe_handshake", handshake)
    if responder is not None:
        monkeypatch.setattr(module, "_session",
                            _fake_session(responder,
                                          accept_origin=accept_origin))
    if client is not None:
        monkeypatch.setattr(module, "_open", client)
    return asyncio.run(module.run())


def _report(state, kind="websocket_report"):
    item = next(e for e in state.evidence["items"] if e["type"] == kind)
    return json.loads(
        (Path(state.output_dir) / item["path"]).read_text(encoding="utf-8")
    )["data"]


# ── skips and handshake grading ─────────────────────────────────

def test_skips_when_disabled(monkeypatch, tmp_path):
    module, state, harness = _module(tmp_path, cfg={"enabled": False})
    assert asyncio.run(module.run()) == "skipped"


def test_skips_without_sockets(monkeypatch, tmp_path):
    module, state, harness = _module(
        tmp_path, cfg=_cfg(sockets=[], capture={"enabled": False}))
    assert asyncio.run(module.run()) == "skipped"
    assert "no websocket endpoints" in state.module["skipped"][-1]["reason"]


def test_foreign_origin_handshake_is_candidate_not_proof(monkeypatch, tmp_path):
    cfg = _cfg(canary={"enabled": False}, probes=[])
    module, state, harness = _module(tmp_path, cfg=cfg)
    result = _run(module, monkeypatch, harness, accept_foreign=True)

    assert result == "done"
    findings = state.findings["findings"]
    assert len(findings) == 1
    assert findings[0]["verified"] is False
    assert findings[0]["severity"] == "LOW"
    report = _report(state)
    assert report["handshakes"][0]["foreign_origin"]["accepted"] is True
    assert report["state_counts"]["proof"] == 0
    assert state.mutations.outstanding() == []


# ── canary PROOF modes ──────────────────────────────────────────

def test_message_canary_proof_with_verified_cleanup(monkeypatch, tmp_path):
    store = Store()
    module, state, harness = _module(tmp_path)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=True))

    assert result == "done"
    proofs = [f for f in state.findings["findings"] if f.get("verified") is True]
    assert len(proofs) == 1
    assert proofs[0]["verification"]["method"] == "ws_message_canary"
    assert state.mutations.outstanding() == []
    report = _report(state)
    assert report["state_counts"]["proof"] == 1
    canary = report["canaries"][0]
    assert canary["proven"] is True
    assert canary["observed_seed"] is True
    assert canary["absent_seed"] is False
    assert canary["baseline_seed"] is False
    assert canary["cleanup_status"] == "verified"


def test_fixed_message_denied_is_not_proof(monkeypatch, tmp_path):
    store = Store()
    module, state, harness = _module(tmp_path)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=False))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    report = _report(state)
    assert report["state_counts"]["proof"] == 0
    assert report["canaries"][0]["cleanup_status"] == "verified"
    assert state.mutations.outstanding() == []


def test_http_direct_leak_is_idor_lane_not_ws_proof(monkeypatch, tmp_path):
    store = Store()
    module, state, harness = _module(tmp_path)
    harness.responder = _http_responder(store, harness.identities,
                                        direct_leak=True)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=True))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    canary = _report(state)["canaries"][0]
    assert canary["http_direct_seed"] is True
    assert "IDOR" in canary.get("reason", "")
    assert state.mutations.outstanding() == []


def test_subscription_canary_proof(monkeypatch, tmp_path):
    store = Store()
    cfg = _cfg()
    cfg["canary"]["probes"] = [{
        "name": "channel-leak", "mode": "subscription",
        "send_template": '{"type":"subscribe","channel":"obj-{id}"}',
        "extract": {"type": "jsonpath", "path": "name"},
    }]
    module, state, harness = _module(tmp_path, cfg=cfg)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=True))

    assert result == "done"
    proofs = [f for f in state.findings["findings"] if f.get("verified") is True]
    assert len(proofs) == 1
    assert proofs[0]["verification"]["method"] == "ws_subscription_canary"
    assert state.mutations.outstanding() == []


def test_origin_canary_proof(monkeypatch, tmp_path):
    store = Store()
    cfg = _cfg()
    cfg["canary"]["probes"] = [{
        "name": "cross-origin", "mode": "origin",
        "send_template": '{"type":"read","id":"{id}"}',
        "extract": {"type": "jsonpath", "path": "name"},
    }]
    module, state, harness = _module(tmp_path, cfg=cfg)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness, accept_foreign=True,
                  responder=_ws_responder(store, ws_leaks=False))

    assert result == "done"
    proofs = [f for f in state.findings["findings"] if f.get("verified") is True]
    assert len(proofs) == 1
    assert proofs[0]["verification"]["method"] == "ws_origin_canary"
    assert state.mutations.outstanding() == []


def test_public_canary_blocks_origin_proof(monkeypatch, tmp_path):
    store = Store()
    cfg = _cfg()
    cfg["canary"]["probes"] = [{
        "name": "cross-origin", "mode": "origin",
        "send_template": '{"type":"read","id":"{id}"}',
        "extract": {"type": "jsonpath", "path": "name"},
    }]
    module, state, harness = _module(tmp_path, cfg=cfg)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness, accept_foreign=True,
                  responder=_ws_responder(store, ws_leaks=False, public=True))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    canary = _report(state)["canaries"][0]
    assert "public" in canary.get("reason", "")
    assert state.mutations.outstanding() == []


def test_revocation_canary_proof(monkeypatch, tmp_path):
    store = Store()
    cfg = _cfg()
    cfg["canary"]["probes"] = [{
        "name": "stale-session", "mode": "revocation", "identity": "alice",
        "send_template": '{"type":"read","id":"{id}"}',
        "extract": {"type": "jsonpath", "path": "name"},
    }]
    module, state, harness = _module(tmp_path, cfg=cfg)
    harness.responder = _http_responder(store, harness.identities)

    async def open_client(harness_arg, socket, identity_name, *, origin=""):
        return FakeClient([
            [json.dumps({"name": store.seed})],
            [json.dumps({"name": store.seed})],
        ])

    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=False),
                  client=open_client)

    assert result == "done"
    proofs = [f for f in state.findings["findings"] if f.get("verified") is True]
    assert len(proofs) == 1
    assert proofs[0]["verification"]["method"] == "ws_revocation_canary"
    canary = _report(state)["canaries"][0]
    assert canary["post_logout_http_denied"] is True
    assert canary["pre_logout_seed"] is True
    assert canary["cleanup_status"] == "verified"
    assert state.mutations.outstanding() == []


# ── candidates and failure paths ────────────────────────────────

def test_candidate_probe_marks_other_identity(monkeypatch, tmp_path):
    cfg = _cfg(canary={"enabled": False})
    cfg["probes"] = [{
        "name": "chat-read", "send_template": '{"type":"read","id":"9"}',
        "extract": {"type": "jsonpath", "path": "data.owner_email"},
    }]
    module, state, harness = _module(tmp_path, cfg=cfg)

    def responder(identity, sends, origin):
        if identity == "bob":
            return [json.dumps({"data": {"owner_email": "alice@x.com"}})]
        return []

    result = _run(module, monkeypatch, harness, responder=responder)

    assert result == "done"
    findings = state.findings["findings"]
    assert findings and findings[0]["verified"] is False
    assert "candidate" not in findings[0]["title"].lower()
    report = _report(state)
    probe = report["probes"][0]
    assert probe["state"] == "candidate"
    assert "alice@x.com" not in json.dumps(probe)


def test_baseline_push_blocks_message_proof(monkeypatch, tmp_path):
    store = Store()
    module, state, harness = _module(tmp_path)
    harness.responder = _http_responder(store, harness.identities)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=True,
                                          push_on_connect=True))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    canary = _report(state)["canaries"][0]
    assert canary["baseline_seed"] is True
    assert state.mutations.outstanding() == []


def test_cleanup_failure_blocks_proof_and_stays_failed(monkeypatch, tmp_path):
    store = Store()
    module, state, harness = _module(tmp_path)
    harness.responder = _http_responder(store, harness.identities,
                                        cleanup_fails=True)
    result = _run(module, monkeypatch, harness,
                  responder=_ws_responder(store, ws_leaks=True))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    records = state.mutations.read_records()
    statuses = [(r.get("cleanup") or {}).get("status")
                for r in records if r.get("kind") == "cleanup"]
    assert "failed" in statuses
    assert "verified" not in statuses
