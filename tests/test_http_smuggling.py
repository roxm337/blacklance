"""Tests for modules/http_smuggling.py.

There is no local fixture for this module on purpose. A request-smuggling bug
lives in the disagreement between a front-end proxy and a back-end server, and
a single local server cannot have one — so a fixture here would only prove that
the test suite agrees with itself.

What these tests pin down is the part that is decidable: how the module labels
what smuggler prints. The old behaviour forwarded a fuzzer's "potential" lines
to a HIGH/FIRM finding, which is a claim no one can reproduce.
"""

import tempfile
from unittest.mock import patch

import pytest

from modules.http_smuggling import HTTPSmuggling
from state.manager import StateManager


def _config(module_cfg=None):
    return {
        "target": {"domain": "example.test", "base_url": "https://example.test"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "modules": {"http_smuggling": dict(module_cfg or {})},
    }


async def _always_ambiguous(self, target):
    """These tests pin fuzzer-output labelling; the network pre-filter
    and the socket oracle have their own raw-socket tests elsewhere."""
    return True, "test assumes ambiguity"


async def _never_oracle(self, target):
    return False


def _run(tool_present=True, results=(), module_cfg=None):
    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config(module_cfg))
    available = {"available": tool_present, "results": list(results),
                 "exit_code": 0, "stdout": "x", "stderr": ""}

    with patch("modules.http_smuggling.tool_available",
               return_value=tool_present), \
         patch("modules.http_smuggling.smuggler_scan",
               return_value=available), \
         patch.object(HTTPSmuggling, "_ambiguous",
                      lambda self, target: _always_ambiguous(self, target)), \
         patch.object(HTTPSmuggling, "_desync_oracle",
                      lambda self, target, mode="cl_te", variant="plain": _never_oracle(self, target)):
        import asyncio
        status = asyncio.run(module.run())
    return status, state


# ── The labelling, which is the whole point ─────────────────────

def test_a_fuzzer_candidate_is_never_reported_as_confirmed():
    _, state = _run(results=["[!] potential CL.TE smuggling detected"])
    findings = state.findings["findings"]

    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["confidence"] == "TENTATIVE", finding["confidence"]
    assert finding["verified"] is False
    # Impact if genuine is high, so it stays in the queue — but not as HIGH,
    # which reads as "confirmed and severe" to whoever triages it.
    assert finding["severity"] == "MEDIUM", finding["severity"]


def test_the_word_potential_in_the_tool_output_does_not_promote_it():
    _, state = _run(results=["[!] potential CL.TE smuggling detected",
                             "[!] potential TE.CL smuggling detected"])
    for finding in state.findings["findings"]:
        assert finding["confidence"] == "TENTATIVE"


def test_the_description_asks_for_reproduction_rather_than_asserting_it():
    """A reader has to be told, in the finding itself, that this is a fuzzer
    line rather than a desync. The severity and confidence fields are not the
    only thing they read."""
    _, state = _run(results=["[!] potential smuggling"])
    description = state.findings["findings"][0]["description"].lower()

    assert "not a confirmed" in description
    assert "reproduce" in description


def test_the_tool_lines_appear_in_the_finding():
    """The raw candidate lines are the finding's own evidence. Dropping them
    leaves a report that says 'smuggling, probably' with nothing to check."""
    _, state = _run(results=["[!] potential CL.TE smuggling detected",
                             "[!] potential TE.CL smuggling detected"])
    evidence = state.findings["findings"][0]["evidence"]

    assert evidence == ["[!] potential CL.TE smuggling detected",
                        "[!] potential TE.CL smuggling detected"]


def test_each_target_gets_its_own_finding():
    """One finding per target keeps the evidence attached to the URL it came
    from. A single merged line across ten hosts cannot be actioned."""
    state = StateManager(tempfile.mkdtemp())
    config = _config()
    module = HTTPSmuggling(state, config)
    with patch("modules.http_smuggling.tool_available", return_value=True), \
         patch("modules.http_smuggling.smuggler_scan",
               return_value={"available": True,
                             "results": ["[!] potential smuggling"],
                             "exit_code": 0, "stdout": "", "stderr": ""}), \
         patch.object(HTTPSmuggling, "_ambiguous",
                      lambda self, target: _always_ambiguous(self, target)), \
         patch.object(HTTPSmuggling, "_desync_oracle",
                      lambda self, target, mode="cl_te", variant="plain": _never_oracle(self, target)):
        module._targets = lambda: ["https://a.test", "https://b.test"]
        import asyncio
        asyncio.run(module.run())

    findings = state.findings["findings"]
    assert len(findings) == 2
    assert findings[0]["title"] != findings[1]["title"]


# ── Full output is kept as evidence ─────────────────────────────

def test_the_tools_own_output_is_preserved():
    """Evidence lives in its own file and the index keeps only the pointer, so
    this reads it back off disk the way a reporter would."""
    import json
    import pathlib
    _, state = _run(results=["[!] potential smuggling"])
    item = state.evidence["items"][-1]

    assert item["type"] == "smuggler"
    assert item["subject"] == "https://example.test"
    stored = json.loads(
        (pathlib.Path(state.output_dir) / item["path"]).read_text())
    assert stored["data"]["results"] == ["[!] potential smuggling"]


def test_a_clean_run_produces_nothing():
    status, state = _run(results=[])
    assert state.findings["findings"] == []
    assert status == "done"


# ── Bookkeeping ─────────────────────────────────────────────────

def test_a_missing_tool_still_runs_the_native_oracles():
    """The desync oracles are our own sockets; only the sweep needs the binary."""
    with patch("modules.http_smuggling.smuggler_scan") as scan:
        status, state = _run(tool_present=False,
                             module_cfg={"h2": False, "h2c": False})
        scan.assert_not_called()
    assert status == "done"
    # Nothing was proven against example.test, so nothing is filed.
    assert state.findings["findings"] == []
    assert not [e for e in state.module["skipped"]
                if e.get("module_id") == "http_smuggling"]


def test_disabled_means_the_tool_is_never_run():
    with patch("modules.http_smuggling.smuggler_scan") as scan:
        status, state = _run(results=["[!] potential smuggling"],
                             module_cfg={"enabled": False})
        scan.assert_not_called()

    assert status == "skipped"
    assert state.findings["findings"] == []


@pytest.mark.parametrize("configured,expected", [(1, 1), (2, 2)])
def test_the_target_list_is_capped(configured, expected):
    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config({"max_targets": configured}))
    hosts = [f"https://h{i}.test" for i in range(10)]
    with patch("modules.http_smuggling.tool_available", return_value=True), \
         patch("modules.http_smuggling.smuggler_scan",
               return_value={"available": True, "results": [],
                             "exit_code": 0, "stdout": "", "stderr": ""}) as scan, \
         patch.object(HTTPSmuggling, "_ambiguous",
                      lambda self, target: _always_ambiguous(self, target)), \
         patch.object(HTTPSmuggling, "_desync_oracle",
                      lambda self, target, mode="cl_te", variant="plain": _never_oracle(self, target)):
        module._targets = lambda: hosts
        import asyncio
        asyncio.run(module.run())

    assert scan.call_count == expected


# ── TE variants and h2c delivery ────────────────────────────────

def test_te_variant_hit_is_confirmed_and_labelled():
    from unittest.mock import AsyncMock

    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config())
    with patch("modules.http_smuggling.http_smuggle.desync_probe",
               new=AsyncMock(return_value=(True, "ghost answered", "m"))):
        import asyncio
        proven = asyncio.run(module._desync_oracle(
            "https://example.test/", "cl_te", variant="dup_x_chunked"))
    assert proven is True
    finding = state.findings["findings"][0]
    assert finding["verification"]["variant"] == "dup_x_chunked"
    assert "dup_x_chunked" in finding["title"]
    assert finding["confidence"] == "CONFIRMED"


def test_h2_desync_tries_the_second_mode_after_a_probe_error():
    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config())
    calls = []

    def probe(target, mode):
        calls.append(mode)
        if mode == "h2_cl":
            raise OSError("stream reset")
        return True, "next stream answered with hopefully404"

    with patch.object(HTTPSmuggling, "_h2_probe", side_effect=probe):
        import asyncio
        proven = asyncio.run(module._h2_desync("https://example.test/"))
    assert proven is True
    assert calls == ["h2_cl", "h2_te"]
    assert state.findings["findings"][0]["verification"]["method"] == \
        "h2_te_desync_oracle"


def test_h2c_desync_only_runs_on_cleartext_targets():
    from unittest.mock import AsyncMock

    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config())
    with patch("modules.http_smuggling.http_smuggle.h2c_supported",
               new=AsyncMock(return_value=(True, "x"))) as probe:
        import asyncio
        assert asyncio.run(
            module._h2c_desync("https://example.test/")) is False
    probe.assert_not_called()


def test_h2c_desync_confirms_through_the_stream_oracle():
    from unittest.mock import AsyncMock

    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config())
    with patch("modules.http_smuggling.http_smuggle.h2c_supported",
               new=AsyncMock(return_value=(True, "h2c SETTINGS frame"))), \
         patch.object(HTTPSmuggling, "_h2_probe",
                      return_value=(True, "hopefully404-deadbeef")):
        import asyncio
        proven = asyncio.run(module._h2c_desync("http://example.test/"))
    assert proven is True
    finding = state.findings["findings"][0]
    assert "h2c" in finding["title"].lower()
    assert finding["category"] == "HTTP Request Smuggling"


def test_max_te_variants_caps_the_obfuscation_sweep():
    state = StateManager(tempfile.mkdtemp())
    module = HTTPSmuggling(state, _config({"max_te_variants": 1,
                                           "h2": False, "h2c": False}))
    seen = []

    async def never(self, target, mode="cl_te", variant="plain"):
        seen.append((mode, variant))
        return False

    available = {"available": True, "results": [], "exit_code": 0,
                 "stdout": "", "stderr": ""}
    with patch("modules.http_smuggling.tool_available", return_value=True), \
         patch("modules.http_smuggling.smuggler_scan",
               return_value=available), \
         patch.object(HTTPSmuggling, "_ambiguous",
                      lambda self, target: _always_ambiguous(self, target)), \
         patch.object(HTTPSmuggling, "_desync_oracle", new=never):
        import asyncio
        asyncio.run(module.run())

    # Plain framing first, then exactly one obfuscation (both modes).
    assert seen[:2] == [("cl_te", "plain"), ("te_cl", "plain")]
    assert {variant for _mode, variant in seen[2:]} == {"xchunked"}
