"""Error-based (blind) SSTI: the engine's own exception is the oracle.

A payload reflection is not evidence. What counts here is that a malformed
expression made the server render a template-engine exception the control
request did not produce, and — for CONFIRMED — that the exception names the
random marker we injected.
"""

import asyncio
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.ssti_scan as ssti
from modules.ssti_scan import SSTIScan
from state.manager import StateManager

MARKER_RE = re.compile(r"zz[0-9a-f]{8}")


def _state():
    return StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))


def _module(st):
    return SSTIScan(st, {"target": {"domain": "acme.com"},
                         "modules": {"ssti_scan": {}}, "paths": {},
                         "auth": {}})


def _run(monkeypatch, handler, *, error_based=True):
    st = _state()
    module = _module(st)

    async def fake_curl(url, **kwargs):
        status, body = handler(url)
        return {"status": status, "body": body}

    monkeypatch.setattr(ssti, "curl", fake_curl)
    point = {"url": "https://acme.com/search?q=1", "param": "q",
             "method": "GET"}
    asyncio.run(module._test_point(point, error_based=error_based))
    return st.findings["findings"]


def _value(url):
    return parse_qs(urlparse(url).query).get("q", [""])[0]


def test_jinja_error_naming_the_marker_is_confirmed(monkeypatch):
    def handler(url):
        value = _value(url)
        if "{{" in value:
            marker = (MARKER_RE.search(value) or [None])[0]
            return 500, (f"jinja2.exceptions.UndefinedError: "
                         f"'{marker}' is undefined")
        return 200, "hello world"

    findings = _run(monkeypatch, handler)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verified"] is True
    assert finding["verification"]["marker_echoed"] is True
    assert finding["verification"]["engine"] == "jinja2/tornado"


def test_engine_class_without_marker_is_firm_not_confirmed(monkeypatch):
    def handler(url):
        if "{{" in _value(url):
            return 500, "Twig\\Error\\RuntimeError: something broke"
        return 200, "hello world"

    findings = _run(monkeypatch, handler)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "FIRM"
    assert findings[0]["verified"] is False
    assert findings[0]["verification"]["engine"] == "twig"


def test_reflection_without_an_engine_error_is_not_a_finding(monkeypatch):
    def handler(url):
        value = _value(url)
        return 200, f"you searched for {value}"

    assert _run(monkeypatch, handler) == []


def test_baseline_that_already_shows_the_error_is_not_attributed(monkeypatch):
    def handler(url):
        # The app's error page always contains this string; the payload
        # changed nothing.
        return 500, "TemplateSyntaxError at /search"

    assert _run(monkeypatch, handler) == []


def test_error_probes_can_be_disabled(monkeypatch):
    def handler(url):
        if "{{" in _value(url):
            return 500, "jinja2.exceptions.UndefinedError: 'x' is undefined"
        return 200, "hello"

    assert _run(monkeypatch, handler, error_based=False) == []


def test_arithmetic_oracle_still_wins_first(monkeypatch):
    def handler(url):
        value = _value(url)
        if value == ssti.CONTROL_STRING:
            return 200, f"echo:{value}"
        if value == "{{7*7}}":
            return 200, "49 49 49"
        return 500, "jinja2.exceptions.UndefinedError: 'zz' is undefined"

    findings = _run(monkeypatch, handler)
    assert len(findings) == 1
    assert findings[0]["verification"]["method"] == "ssti_arithmetic_differential"
