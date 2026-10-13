"""Tests for tool wrappers — rate limiter, nmap parser, etc."""

import asyncio
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from core.scoring import score_vulnerability
from tools.wrappers import parse_nmap_output
from tools.wrappers import RateLimiter, configure_http_limiter, configure_http_session


class TestParseNmapOutput:
    def test_empty_input(self):
        result = parse_nmap_output("")
        assert result["hosts"] == []

    def test_single_host(self):
        text = (
            "Nmap scan report for example.com (93.184.216.34)\n"
            "22/tcp open  ssh     OpenSSH 8.0\n"
            "80/tcp open  http    Apache 2.4\n"
        )
        result = parse_nmap_output(text)
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["hostname"] == "example.com (93.184.216.34)"
        assert len(host["ports"]) == 2

    def test_multiple_hosts_last_appended(self):
        text = (
            "Nmap scan report for host1 (10.0.0.1)\n"
            "22/tcp open  ssh\n"
            "Nmap scan report for host2 (10.0.0.2)\n"
            "80/tcp open  http\n"
            "443/tcp open https\n"
        )
        result = parse_nmap_output(text)
        assert len(result["hosts"]) == 2
        assert result["hosts"][1]["hostname"] == "host2 (10.0.0.2)"
        assert len(result["hosts"][1]["ports"]) == 2


class TestRateLimiter:
    def test_configure(self):
        configure_http_limiter(max_concurrent=10, max_per_minute=30)
        configure_http_limiter(max_concurrent=5, max_per_minute=60)

    def test_limiter_attrs(self):
        limiter = RateLimiter(max_concurrent=3, max_per_minute=50)
        assert limiter._max_per_minute == 50
        assert limiter._semaphore._value == 3

    def test_configure_http_session_merges_auth(self):
        configure_http_session({
            "auth": {
                "headers": {"X-Test": "1"},
                "cookies": {"sid": "abc"},
                "bearer_token": "tok",
            }
        })
        merged = wrappers._merge_session_headers({"X-Test": "2"})
        assert merged["X-Test"] == "2"
        assert merged["Cookie"] == "sid=abc"
        assert merged["Authorization"] == "Bearer tok"
        configure_http_session({})


class TestFreeApiWrappers:
    def test_score_vulnerability_weights(self):
        score = score_vulnerability(cvss=9.8, epss=0.7, kev=True, exposure=1.0)
        assert score >= 85

    def test_extract_domain_hosts(self):
        hosts = wrappers._extract_domain_hosts(
            "api.example.com cdn.example.com evil-example.com",
            "example.com",
        )
        assert hosts == ["api.example.com", "cdn.example.com"]

    def test_anubisdb_filters_scope(self, monkeypatch):
        async def fake_curl_json(url, **kwargs):
            return ["api.example.com", "other.test", "*.cdn.example.com"]

        monkeypatch.setattr(wrappers, "curl_json", fake_curl_json)
        result = asyncio.run(wrappers.anubisdb("example.com"))
        assert result == ["api.example.com", "cdn.example.com"]

    def test_epss_score_maps_cves(self, monkeypatch):
        async def fake_curl_json(url, **kwargs):
            return {
                "data": [
                    {
                        "cve": "CVE-2024-0001",
                        "epss": "0.42",
                        "percentile": "0.91",
                        "date": "2026-01-01",
                    }
                ]
            }

        monkeypatch.setattr(wrappers, "curl_json", fake_curl_json)
        result = asyncio.run(wrappers.epss_score(["CVE-2024-0001", "bad"]))
        assert result["CVE-2024-0001"]["epss"] == 0.42


class TestShellQuoting:
    """Attacker-influenced values must never break out of tool commands."""

    def _record(self, monkeypatch):
        import tools.wrappers as wrappers_mod
        seen = []

        async def fake_bash(command, timeout=120):
            seen.append(command)
            return {"stdout": "", "stderr": "", "exit_code": 0,
                    "error": None}

        monkeypatch.setattr(wrappers_mod, "bash", fake_bash)
        return seen

    def test_dig_keeps_evil_domain_a_single_word(self, monkeypatch):
        import shlex as _shlex
        import tools.wrappers as wrappers_mod
        monkeypatch.setattr(wrappers_mod, "_missing", lambda tool: False)
        seen = self._record(monkeypatch)
        payload = "evil';touch /tmp/pwned;#"
        asyncio.run(wrappers_mod.dig("A", payload))
        parts = _shlex.split(seen[0])
        assert parts[0] == "dig"
        assert payload in parts, parts

    def test_whois_keeps_evil_query_a_single_word(self, monkeypatch):
        import shlex as _shlex
        import tools.wrappers as wrappers_mod
        monkeypatch.setattr(wrappers_mod, "_missing", lambda tool: False)
        seen = self._record(monkeypatch)
        payload = "x;touch /tmp/pwned"
        asyncio.run(wrappers_mod.whois_lookup(payload))
        assert payload in _shlex.split(seen[0]), seen

    def test_httpx_echo_block_cannot_break_out(self, monkeypatch):
        import shlex as _shlex
        import tools.wrappers as wrappers_mod
        seen = self._record(monkeypatch)
        monkeypatch.setattr(wrappers_mod, "_tool_available",
                            lambda name: True)
        payload = "a.example';touch /tmp/pwned;#"
        asyncio.run(wrappers_mod.httpx_probe(
            ["clean.example", payload]))
        tokens = _shlex.split(seen[0])
        # The payload (touch included) must live inside ONE shell word —
        # never as a standalone command token.
        assert not any(t == "touch" for t in tokens), tokens
        assert any(payload in t for t in tokens), tokens

    def test_nmap_rejects_metacharacters(self, monkeypatch):
        import tools.wrappers as wrappers_mod
        import pytest as _pytest
        with _pytest.raises(ValueError):
            asyncio.run(wrappers_mod.nmap_scan(
                "example.com", ports="80;touch /tmp/pwned"))
        with _pytest.raises(ValueError):
            asyncio.run(wrappers_mod.nmap_scan(
                "example.com", scripts="http-title|evil"))

    def test_nmap_default_flags_still_parse(self, monkeypatch):
        import tools.wrappers as wrappers_mod
        monkeypatch.setattr(wrappers_mod, "_missing", lambda tool: False)
        seen = self._record(monkeypatch)
        asyncio.run(wrappers_mod.nmap_scan("example.com"))
        assert "--top-ports 1000" in seen[0], seen


class TestThirdPartyIsolation:
    def test_strip_global_auth_keeps_target_creds_home(self, monkeypatch):
        """Global target credentials must not ride along to third-party
        APIs; the caller's own API key must survive."""
        import tools.wrappers as wrappers_mod

        wrappers_mod.configure_http_session(
            {"auth": {"headers": {"Authorization": "Bearer target-secret"},
                      "cookies": {"sess": "abc"}}})
        seen = {}

        class FakeEngine:
            async def request(self, url, method, **kwargs):
                seen.update(kwargs.get("headers", {}))
                return {"status": 200, "body": "{}"}

        monkeypatch.setattr(wrappers_mod, "get_engine",
                            lambda: FakeEngine())
        try:
            asyncio.run(wrappers_mod.curl(
                "https://api.example-third-party.test/x",
                headers={"X-Api-Key": "key123"},
                strip_global_auth=True))
        finally:
            wrappers_mod.configure_http_session({})
        assert seen.get("X-Api-Key") == "key123", seen
        assert "Authorization" not in seen, seen
        assert "Cookie" not in seen, seen


class TestMissingBinaries:
    def test_missing_tool_is_an_error_not_a_negative(self, monkeypatch):
        import tools.wrappers as wrappers_mod
        monkeypatch.setattr(wrappers_mod, "_missing", lambda tool: True)
        dug = asyncio.run(wrappers_mod.dig("A", "example.com"))
        assert dug == {"domain": "example.com", "type": "A", "answers": [],
                       "raw": "", "error": "missing: dig"}
        who = asyncio.run(wrappers_mod.whois_lookup("example.com"))
        assert who["error"] == "missing: whois"
        cert = asyncio.run(wrappers_mod.cert_info("example.com"))
        assert cert["error"] == "missing: openssl"
