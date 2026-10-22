"""Adaptive payloads: a mutation only counts when the oracle fires again."""

import asyncio
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.ssti_scan as ssti
from core.waf_evasion import (
    encoded_variants, is_payload_blocked, payload_block_codes,
    raw_param_url, ssti_variants)
from modules.ssti_scan import SSTIScan
from state.manager import StateManager


def test_payload_block_codes_default_and_override():
    assert 403 in payload_block_codes(None)
    custom = {"waf": {"payload_block_codes": [418, "429"]}}
    assert payload_block_codes(custom) == {418, 429}
    assert is_payload_blocked({"status": 403}, {403, 429})
    assert not is_payload_blocked({"status": 200}, {403, 429})
    assert not is_payload_blocked({"status": "bad"}, {403})


def test_ssti_variants_preserve_semantics_and_drop_the_original():
    variants = dict(ssti_variants("{{7*7}}"))
    assert variants["spaced_operators"] == "{{7 * 7}}"
    assert variants["tab_padding"] == "{{\t7*7\t}}"
    assert "{{7*7}}" not in variants.values()
    assert len(variants) == len(set(variants.values()))


def test_encoded_variants_change_the_wire_not_the_payload():
    variants = dict(encoded_variants("{{7*7}}"))
    assert "%7b" in variants["percent_lower"]
    assert variants["double_percent"].startswith("%257B")


def test_raw_param_url_does_not_re_encode_the_wire_value():
    url = raw_param_url("https://acme.com/s?q=1&x=2", "q", "%7B%7B7*7%7D%7D")
    query = parse_qs(urlparse(url).query)
    assert query["q"] == ["{{7*7}}"]
    assert query["x"] == ["2"]
    assert "%257B" not in url


def _state():
    return StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))


def _run(monkeypatch, handler, *, adaptive=True):
    st = _state()
    module = SSTIScan(st, {
        "target": {"domain": "acme.com"},
        "modules": {"ssti_scan": {"waf_adaptive": adaptive}},
        "paths": {}, "auth": {},
    })
    module.state = st
    module.config = {
        "target": {"domain": "acme.com"},
        "modules": {"ssti_scan": {"waf_adaptive": adaptive}},
        "waf": {"payload_block_codes": [403]},
        "paths": {}, "auth": {},
    }

    async def fake_curl(url, **kwargs):
        return handler(parse_qs(urlparse(url).query).get("q", [""])[0])

    monkeypatch.setattr(ssti, "curl", fake_curl)
    point = {"url": "https://acme.com/search?q=1", "param": "q",
             "method": "GET"}
    asyncio.run(module._test_point(point, error_based=False))
    return st.findings["findings"]


def test_blocked_payload_retried_with_mutation_keeps_the_oracle(monkeypatch):
    def handler(value):
        if value == ssti.CONTROL_STRING:
            return {"status": 200, "body": f"echo:{value}"}
        if value == "{{7 * 7}}":
            return {"status": 200, "body": "49 49 49"}
        return {"status": 403, "body": "blocked by edge"}

    findings = _run(monkeypatch, handler)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verification"]["waf_bypass"] == "spaced_operators"
    assert finding["verification"]["bypass_url"].startswith("https://acme.com/")
    assert "edge blocked" in finding["description"]


def test_a_200_without_the_computed_value_is_not_a_bypass(monkeypatch):
    def handler(value):
        if value == ssti.CONTROL_STRING:
            return {"status": 200, "body": f"echo:{value}"}
        if "{{" in value:
            return {"status": 403, "body": "blocked"}
        return {"status": 200, "body": "you searched for it"}

    assert _run(monkeypatch, handler) == []


def test_adaptive_retry_can_be_disabled(monkeypatch):
    def handler(value):
        if value == ssti.CONTROL_STRING:
            return {"status": 200, "body": f"echo:{value}"}
        if value == "{{7 * 7}}":
            return {"status": 200, "body": "49 49 49"}
        return {"status": 403, "body": "blocked"}

    assert _run(monkeypatch, handler, adaptive=False) == []
