"""LLM surface inventory: fingerprint is not a finding, anonymous is."""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.llm_surface as llm
from modules.llm_surface import (
    LLMSurface, candidate_urls, classify_fingerprint, first_model)
from state.manager import StateManager


def _module(cfg=None):
    config = {
        "target": {"domain": "acme.test", "base_url": "https://acme.test"},
        "modules": {"llm_surface": cfg or {}},
        "waf": {}, "paths": {}, "auth": {},
    }
    return LLMSurface(
        StateManager(str(Path(tempfile.mkdtemp()) / "acme.test")), config)


def test_candidate_urls_keep_ai_paths_and_drop_the_rest():
    urls = [
        "https://acme.test/api/chat",
        "https://acme.test/products",
        "https://acme.test/v1/completions?x=1",
        "https://acme.test/#/assistant",
    ]
    found = candidate_urls(urls)
    assert found == [
        "https://acme.test/api/chat",
        "https://acme.test/v1/completions?x=1",
    ]
    assert candidate_urls(urls, limit=1) == ["https://acme.test/api/chat"]


def test_openai_shaped_json_is_firm():
    kind = classify_fingerprint(
        200, "content-type: application/json\n", '{"choices": []}')
    assert kind["kind"] == "openai_compatible"
    assert kind["confidence"] == "FIRM"


def test_provider_header_is_firm_even_without_json():
    kind = classify_fingerprint(
        401, {"OpenAI-Organization": "org-123"}, "unauthorized")
    assert kind["kind"] == "provider_header"
    assert "openai-organization" in kind["evidence"]


def test_widget_script_is_tentative_and_a_plain_page_is_nothing():
    widget = classify_fingerprint(
        200, "", "<script src='https://widget.intercom.io/widget/x'></script>")
    assert widget["kind"] == "chat_widget"
    assert widget["confidence"] == "TENTATIVE"
    assert classify_fingerprint(200, "", "<h1>Products</h1>") is None
    assert classify_fingerprint(503, "", "") is None


def test_first_model_reads_the_listing():
    body = json.dumps({"data": [{"id": "gpt-4o-mini"}]})
    assert first_model(body) == "gpt-4o-mini"
    assert first_model("not json") is None


def test_discovery_records_assets_but_no_findings(monkeypatch):
    module = _module({"max_endpoints": 2})
    calls = []

    async def fake_fetch(url):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": '{"choices": []}'}

    async def forbidden(url, model, evidence_id):
        raise AssertionError("prompting is opt-in")

    monkeypatch.setattr(module, "_fetch", fake_fetch)
    monkeypatch.setattr(module, "_probe_completion", forbidden)
    asyncio.run(module.run())

    assert len(calls) == 2
    assets = module.state.get_assets_by_type("ai_endpoint")
    assert len(assets) == 2
    assert all(a["confidence"] == "FIRM" for a in assets)
    assert module.state.findings["findings"] == []


def _evidence(module):
    return module.state.add_evidence(
        "llm_surface", "fingerprint", "https://acme.test/api/chat",
        {"status": 200})


def test_anonymous_completion_is_confirmed(monkeypatch):
    module = _module()
    completion = {"choices": [{"message": {"content": "ping"}}]}

    async def fake_curl(url, **kwargs):
        assert kwargs.get("no_session") is True
        return {"status": 200, "headers": "", "body": json.dumps(completion)}

    monkeypatch.setattr(llm, "curl", fake_curl)
    proven = asyncio.run(module._probe_completion(
        "https://acme.test/api/chat", "gpt-4o-mini", _evidence(module)))

    assert proven is True
    finding = module.state.findings["findings"][0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verification"]["method"] == "unauthenticated_completion"
    assert finding["verification"]["model"] == "gpt-4o-mini"


def test_a_401_is_not_an_exposure(monkeypatch):
    module = _module()

    async def fake_curl(url, **kwargs):
        return {"status": 401, "headers": "", "body": '{"error": "auth"}'}

    monkeypatch.setattr(llm, "curl", fake_curl)
    proven = asyncio.run(module._probe_completion(
        "https://acme.test/api/chat", "gpt-4o-mini", _evidence(module)))

    assert proven is False
    assert module.state.findings["findings"] == []


def test_no_model_means_no_probe(monkeypatch):
    module = _module()

    async def forbidden(url, **kwargs):
        raise AssertionError("must not send a model-less completion")

    monkeypatch.setattr(llm, "curl", forbidden)
    assert asyncio.run(module._probe_completion(
        "https://acme.test/api/chat", None, _evidence(module))) is False
