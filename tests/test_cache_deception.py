"""Web cache deception: proof needs the private body plus a cache HIT."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.cache_deception import (
    CacheDeception, cache_hit_signal, static_shapes)
from state.manager import StateManager

BASE = "https://acme.com"
PRIVATE = ("Welcome alice alice@example.test<br>"
           + "Your billing settings and api keys live here. " * 4)
PUBLIC = "<html><body>Public homepage with marketing copy.</body></html>"
LOGIN = ("<html><form><input name=\"password\" type=\"password\">"
         + "Please log in to continue. " * 4 + "</form></html>")


class FakeIdentity:
    name = "alice"
    email = "alice@example.test"
    owner_id = ""
    owner_markers = ()
    role = "user"
    privileged = False
    verified = True


class FakeHarness:
    def __init__(self, handler):
        self.identity = FakeIdentity()
        self.usable = [self.identity]
        self._handler = handler

    async def establish_all(self, base_url=""):
        return self.usable

    async def request(self, name, url, **kwargs):
        return self._handler(url, True)

    async def request_anonymous(self, url, **kwargs):
        return self._handler(url, False)


def _resp(body, status=200, headers="HTTP/1.1 200 OK\n"):
    return {"status": status, "headers": headers, "body": body}


def _state():
    return StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))


def _run(handler):
    st = _state()
    module = CacheDeception(st, {
        "target": {"domain": "acme.com"},
        "modules": {"cache_deception": {"max_paths": 2, "max_shapes": 3}},
        "paths": {}, "auth": {},
    })
    asyncio.run(module.probe(FakeHarness(handler), FakeIdentity()))
    return st.findings["findings"]


def test_private_body_served_anonymously_with_hit_is_confirmed():
    def handler(url, authenticated):
        if url.endswith("/account"):
            return _resp(PRIVATE if authenticated else PUBLIC)
        if "/..%2f" in url:
            return _resp(PRIVATE,
                         headers="HTTP/1.1 200 OK\nX-Cache: HIT\n"
                                 "Cache-Control: public, max-age=600\n")
        return _resp("not found", 404, "")

    findings = _run(handler)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verified"] is True
    assert finding["verification"]["cache_signal"] == "x-cache: hit"
    assert finding["verification"]["identity_marker"] == "alice@example.test"


def test_miss_without_age_is_not_cached_evidence():
    def handler(url, authenticated):
        if url.endswith("/account"):
            return _resp(PRIVATE if authenticated else PUBLIC)
        if "/..%2f" in url:
            return _resp(PRIVATE,
                         headers="HTTP/1.1 200 OK\nX-Cache: MISS\nAge: 0\n")
        return _resp("not found", 404, "")

    assert _run(handler) == []


def test_public_page_is_not_private():
    def handler(url, authenticated):
        if url.endswith("/account"):
            return _resp(PUBLIC)
        if "/..%2f" in url:
            return _resp(PUBLIC, headers="HTTP/1.1 200 OK\nX-Cache: HIT\n")
        return _resp("not found", 404, "")

    assert _run(handler) == []


def test_login_wall_is_not_a_leak():
    def handler(url, authenticated):
        if url.endswith("/account"):
            return _resp(LOGIN if authenticated else PUBLIC)
        if "/..%2f" in url:
            return _resp(LOGIN, headers="HTTP/1.1 200 OK\nX-Cache: HIT\n")
        return _resp("not found", 404, "")

    assert _run(handler) == []


def test_cache_signal_helpers():
    assert cache_hit_signal("X-Cache: HIT from edge") == "x-cache: hit"
    assert cache_hit_signal("Age: 42") == "age: 42"
    assert cache_hit_signal("Age: 0") == ""
    assert cache_hit_signal("CF-Cache-Status: MISS") == ""
    shapes = static_shapes("/account", "abc")
    assert shapes[0] == "/account/wcdabc.css"
    assert shapes[1] == "/account/..%2fwcdabc.css"
    assert all("wcdabc.css" in shape for shape in shapes)
