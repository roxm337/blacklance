"""Deserialization detection and pickle execution.

The detector's job is to distinguish "the parameter reaches a parser" from
"the parameter made the app 500". These tests feed it both.
"""

import asyncio
import base64
import pickle
from urllib.parse import parse_qsl, urlparse

import pytest

from actions.registry import ActionContext
from actions.web import deserialization as de


PHP = 'a:1:{s:4:"name";s:3:"bob";}'


def _ctx(action_id, **params):
    url = params.pop("url", "https://t.test/api?data=" + PHP)
    return ActionContext(action_id=action_id,
                         params={"url": url, **params}, target=url)


def _value(url):
    return dict(parse_qsl(urlparse(url).query,
                          keep_blank_values=True)).get("data", "")


def _fake(handler):
    async def curl(url, **kwargs):
        delay, body = handler(url)
        if delay:
            await asyncio.sleep(delay)
        return {"status": 500 if "error" in body.lower() else 200,
                "body": body, "headers": ""}
    return curl


# ── format detection ─────────────────────────────────────────────────────

def test_format_detection():
    assert de.format_of(b"\xac\xed\x00\x05", "") == "java"
    assert de.format_of(b"\x80\x04\x95", "") == "python"
    assert de.format_of(b"\x00\x01\x00\x00\x00", "") == "dotnet"
    assert de.format_of(b"", PHP) == "php"
    assert de.format_of(b"", "plain-string") == ""


# ── sink detection ───────────────────────────────────────────────────────

def test_corrupt_value_yielding_a_parser_error_is_proof(monkeypatch):
    def handler(url):
        if _value(url) == PHP:
            return 0, "profile updated"
        return 0, "Warning: unserialize(): Error at offset 4 of 24 bytes"

    monkeypatch.setattr(de, "curl", _fake(handler))
    result = asyncio.run(de.deserialize_detect(
        _ctx("web.deserialize.detect", param="data")))

    assert result.success is True
    assert result.data["format"] == "php"
    assert result.evidence["deserializer_error"].startswith("unserialize")


def test_generic_500_is_not_deserialization(monkeypatch):
    def handler(url):
        return 0, ("OK" if _value(url) == PHP else
                   "Internal Server Error: something broke")

    monkeypatch.setattr(de, "curl", _fake(handler))
    result = asyncio.run(de.deserialize_detect(
        _ctx("web.deserialize.detect", param="data")))

    assert result.success is False
    assert "deserialization-specific" in result.error


def test_untouched_value_that_already_errors_is_not_a_sink(monkeypatch):
    def handler(url):
        return 0, "unserialize(): Error at offset 0 of 26 bytes"

    monkeypatch.setattr(de, "curl", _fake(handler))
    result = asyncio.run(de.deserialize_detect(
        _ctx("web.deserialize.detect", param="data")))

    assert result.success is False
    assert "untouched value" in result.error


def test_unserialized_looking_value_is_rejected_early():
    result = asyncio.run(de.deserialize_detect(
        _ctx("web.deserialize.detect", param="data", value="hello")))
    assert result.success is False
    assert "does not look serialized" in result.error


# ── pickle execution ─────────────────────────────────────────────────────

def test_pickle_rce_requires_the_sleep_to_land_twice(monkeypatch):
    def handler(url):
        blob = base64.b64decode(_value(url), validate=True)
        if b"sleep 0.1" in blob:
            return 0.15, "ok"
        return 0, "ok"

    monkeypatch.setattr(de, "curl", _fake(handler))
    seed = base64.b64encode(pickle.dumps({"x": 1},
                                         protocol=4)).decode()
    result = asyncio.run(de.pickle_rce(
        _ctx("web.deserialize.pickle_rce", param="data", value=seed,
             sleep_seconds=0.1)))

    assert result.success is True
    assert "sleep" in result.evidence["proof"]


def test_pickle_without_delay_is_negative(monkeypatch):
    monkeypatch.setattr(de, "curl", _fake(lambda url: (0, "ok")))
    seed = base64.b64encode(pickle.dumps({"x": 1}, protocol=4)).decode()
    result = asyncio.run(de.pickle_rce(
        _ctx("web.deserialize.pickle_rce", param="data", value=seed,
             sleep_seconds=0.05)))
    assert result.success is False


def test_non_pickle_value_is_rejected():
    result = asyncio.run(de.pickle_rce(
        _ctx("web.deserialize.pickle_rce", param="data", value=PHP)))
    assert result.success is False
    assert "not a pickle" in result.error
