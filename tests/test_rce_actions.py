"""Command-execution, SSTI→RCE and LFI→RCE actions.

The one invariant these tests exist to protect: a reflected payload is never
execution. Every oracle uses a value the target must *compute*, and the tests
feed the action a server that only reflects to prove it stays negative.
"""

import asyncio
from urllib.parse import parse_qsl, urlparse

import pytest

from actions.registry import ActionContext
from actions.web import rce as rce_action


def _ctx(action_id, url="https://t.test/p?q=1", **params):
    return ActionContext(action_id=action_id,
                         params={"url": url, **params}, target=url)


def _value(url):
    return "&".join(value for _, value in parse_qsl(urlparse(url).query))


class _FakeHTTP:
    """Programmable stand-in for `curl`: `handler(url) -> (delay, body)`."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def __call__(self, url, method="GET", headers=None, output="full",
                       follow_redirects=True, timeout=10, **kwargs):
        self.calls.append({"url": url, "method": method, "headers": headers})
        delay, body = self.handler(url)
        if delay:
            await asyncio.sleep(delay)
        return {"status": 200, "body": body, "headers": ""}


@pytest.fixture
def fixed_challenge(monkeypatch):
    monkeypatch.setattr(rce_action, "_challenge", lambda: (13, 17, 221))


# ── command injection ────────────────────────────────────────────────────

def test_output_based_command_injection_needs_the_computed_product(
        monkeypatch, fixed_challenge):
    def handler(url):
        value = _value(url)
        if "echo $((13*17))" in value:
            return 0, "result: 221 done"
        return 0, "<html>nothing</html>"

    fake = _FakeHTTP(handler)
    monkeypatch.setattr(rce_action, "curl", fake)

    result = asyncio.run(rce_action.cmd_injection(
        _ctx("web.cmd_injection", param="q")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["technique"] == "output"
    assert result.evidence["proof"].endswith("13*17=221")


def test_reflected_command_payload_is_not_execution(monkeypatch,
                                                    fixed_challenge):
    def handler(url):
        return 0, _value(url)  # echo the payload back, never run it

    monkeypatch.setattr(rce_action, "curl", _FakeHTTP(handler))
    result = asyncio.run(rce_action.cmd_injection(
        _ctx("web.cmd_injection", param="q", sleep_seconds=0.05)))

    assert result.success is False
    assert "no command execution" in result.error


def test_time_based_blind_injection_requires_two_slow_probes(
        monkeypatch, fixed_challenge):
    def handler(url):
        return (0.15, "ok") if "sleep 0.1" in _value(url) else (0, "ok")

    fake = _FakeHTTP(handler)
    monkeypatch.setattr(rce_action, "curl", fake)

    result = asyncio.run(rce_action.cmd_injection(
        _ctx("web.cmd_injection", param="q", sleep_seconds=0.1)))

    assert result.success is True
    assert result.data["technique"] == "time"
    assert "delay_seconds" in result.evidence


def test_unreachable_baseline_fails_fast(monkeypatch):
    async def fake(url, **kwargs):
        return {"status": 0, "body": ""}

    monkeypatch.setattr(rce_action, "curl", fake)
    result = asyncio.run(rce_action.cmd_injection(
        _ctx("web.cmd_injection", param="q")))
    assert result.success is False
    assert "baseline" in result.error


# ── SSTI → RCE ───────────────────────────────────────────────────────────

def test_ssti_rce_requires_the_engine_to_run_the_shell(
        monkeypatch, fixed_challenge):
    def handler(url):
        value = _value(url)
        if "cycler" in value and "echo $((13*17))" in value:
            return 0, "221"
        return 0, "<html>nothing</html>"

    monkeypatch.setattr(rce_action, "curl", _FakeHTTP(handler))
    result = asyncio.run(rce_action.ssti_rce(
        _ctx("web.ssti.rce", param="q")))

    assert result.success is True
    assert result.data["engine"] == "jinja2-cycler"


def test_ssti_reflection_is_not_code_execution(monkeypatch,
                                               fixed_challenge):
    monkeypatch.setattr(rce_action, "curl",
                        _FakeHTTP(lambda url: (0, _value(url))))
    result = asyncio.run(rce_action.ssti_rce(
        _ctx("web.ssti.rce", param="q")))
    assert result.success is False


def test_ssti_payloads_keep_their_braces(monkeypatch, fixed_challenge):
    """`str.format` would explode on Smarty/Twig's literal braces."""
    for label, template in rce_action._SSTI_RCE:
        rendered = template.replace("{a}", "13").replace("{b}", "17")
        assert "{a}" not in rendered
        assert "echo $((13*17))" in rendered, label


# ── LFI → RCE ────────────────────────────────────────────────────────────

def test_lfi_rce_requires_a_confirmed_inclusion_first(monkeypatch,
                                                     fixed_challenge):
    monkeypatch.setattr(rce_action, "curl",
                        _FakeHTTP(lambda url: (0, "<html>not found</html>")))
    result = asyncio.run(rce_action.lfi_rce(
        _ctx("web.lfi.rce", param="file")))
    assert result.success is False
    assert "not confirmed" in result.error


def test_lfi_rce_proves_php_execution_through_a_log(monkeypatch,
                                                    fixed_challenge):
    def handler(url):
        value = _value(url)
        if "/etc/passwd" in value:
            return 0, "root:x:0:0:root:/root:/bin/bash"
        if "access.log" in value:
            # The included log ran the PHP: only the product comes back.
            return 0, "221"
        return 0, "<html>missing</html>"

    monkeypatch.setattr(rce_action, "curl", _FakeHTTP(handler))
    result = asyncio.run(rce_action.lfi_rce(
        _ctx("web.lfi.rce", param="file")))

    assert result.success is True
    assert result.data["technique"] == "log-poisoning"
    assert result.data["log"].endswith("access.log")


def test_lfi_rce_does_not_count_logged_php_source(monkeypatch,
                                                  fixed_challenge):
    """The raw `<?php ... ?>` line appearing in the body is not execution."""
    def handler(url):
        value = _value(url)
        if "/etc/passwd" in value:
            return 0, "root:x:0:0:root:/root:/bin/bash"
        if "access.log" in value:
            return 0, "GET /?file=x UA: <?php echo 13*17; ?> 221"
        return 0, ""

    monkeypatch.setattr(rce_action, "curl", _FakeHTTP(handler))
    result = asyncio.run(rce_action.lfi_rce(
        _ctx("web.lfi.rce", param="file")))
    assert result.success is False
