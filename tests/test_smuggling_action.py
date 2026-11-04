"""HTTP smuggling action: only a desync the wire shows is confirmed."""

import asyncio

from actions.registry import ActionContext
from actions.web import smuggling as smuggling_action


def _ctx(url="https://t.test/"):
    return ActionContext(action_id="web.smuggling.detect",
                         params={"url": url}, target=url)


def test_ghost_response_confirms_smuggling(monkeypatch):
    async def ambiguity(url):
        return True, "accepted dual headers (HTTP 200)"

    async def probe(url, mode="cl_te"):
        if mode == "cl_te":
            return True, "smuggled prefix answered as its own request", "m123"
        return False, "responses: [200]", "m456"

    monkeypatch.setattr(smuggling_action.http_smuggle, "probe_ambiguity",
                        ambiguity)
    monkeypatch.setattr(smuggling_action.http_smuggle, "desync_probe", probe)

    result = asyncio.run(smuggling_action.smuggling_detect(_ctx()))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["mode"] == "cl_te"
    assert result.evidence["marker"] == "m123"


def test_no_desync_is_a_clean_negative(monkeypatch):
    async def ambiguity(url):
        return False, "strict rejection (HTTP 400)"

    async def probe(url, mode="cl_te"):
        return False, "responses: [400]", "m"

    monkeypatch.setattr(smuggling_action.http_smuggle, "probe_ambiguity",
                        ambiguity)
    monkeypatch.setattr(smuggling_action.http_smuggle, "desync_probe", probe)

    result = asyncio.run(smuggling_action.smuggling_detect(_ctx()))

    assert result.success is False
    assert "dual framing" in result.error


def test_non_http_target_is_rejected():
    result = asyncio.run(smuggling_action.smuggling_detect(
        _ctx("ftp://t.test/")))
    assert result.success is False
    assert "http" in result.error
