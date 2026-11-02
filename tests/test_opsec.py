"""Tests for core/opsec.py — the detectability posture (gap #4).

The pipeline gates *active* modules and caps *risk*; it never had a knob for
how *loud* a run may be. These tests pin the three things the posture adds — a
detectability ceiling, a weighted noise budget, and bounded pacing — and the
property that matters most for a mature, heavily-tested pipeline: with no
`opsec:` config the policy is a no-op, so nothing already green changes.
"""

import asyncio

from core.opsec import OpsecPolicy, detectability_rank


def test_default_policy_is_a_noop():
    p = OpsecPolicy({})
    assert p.active is False
    assert p.allows_detectability("high") is True
    assert p.admit("high").allowed is True
    assert p.remaining() is None
    assert p.next_delay() == 0.0


def test_absent_config_is_a_noop():
    assert OpsecPolicy(None).admit("high").allowed is True


# ── ceiling ──────────────────────────────────────────────────────────────

def test_ceiling_blocks_louder_and_admits_quieter():
    p = OpsecPolicy({"opsec": {"max_detectability": "medium"}})
    assert p.active is True
    assert p.admit("low").allowed is True
    assert p.admit("medium").allowed is True
    decision = p.admit("high")
    assert decision.allowed is False
    assert "ceiling" in decision.reason


def test_unknown_label_is_treated_as_loudest():
    # A typo must only ever be *more* cautious, never silently permit noise.
    assert detectability_rank("ludicrous") == detectability_rank("high")
    p = OpsecPolicy({"opsec": {"max_detectability": "low"}})
    assert p.admit("mystery").allowed is False


# ── budget ───────────────────────────────────────────────────────────────

def test_budget_spends_by_weight_and_then_refuses():
    # low=1, medium=3 by default; a budget of 4 covers one of each, no more.
    p = OpsecPolicy({"opsec": {"budget": 4}})
    assert p.admit("low").allowed is True      # spent 1
    assert p.admit("medium").allowed is True   # spent 4
    assert p.remaining() == 0
    refused = p.admit("low")
    assert refused.allowed is False
    assert "budget exhausted" in refused.reason


def test_refused_operations_do_not_spend():
    p = OpsecPolicy({"opsec": {"budget": 2}})
    assert p.admit("high").allowed is False    # weight 8 > 2, refused
    # The refusal must not have charged anything: a quiet op still fits.
    assert p.remaining() == 2
    assert p.admit("low").allowed is True


def test_custom_weights_are_honoured():
    p = OpsecPolicy({"opsec": {"budget": 2, "weights": {"high": 2}}})
    assert p.admit("high").allowed is True
    assert p.remaining() == 0


def test_ceiling_refusal_outranks_budget():
    p = OpsecPolicy({"opsec": {"max_detectability": "low", "budget": 100}})
    decision = p.admit("high")
    assert decision.allowed is False
    assert "ceiling" in decision.reason  # not "budget"


# ── pacing ───────────────────────────────────────────────────────────────

def test_pacing_delay_is_within_bounds_and_seeded():
    p = OpsecPolicy({"opsec": {"pacing": {"min_ms": 100, "max_ms": 300,
                                          "seed": 7}}})
    for _ in range(50):
        d = p.next_delay()
        assert 0.1 <= d <= 0.3
    # Seeded: a fresh policy with the same seed yields the same first draw.
    again = OpsecPolicy({"opsec": {"pacing": {"min_ms": 100, "max_ms": 300,
                                              "seed": 7}}})
    assert again.next_delay() == OpsecPolicy(
        {"opsec": {"pacing": {"min_ms": 100, "max_ms": 300, "seed": 7}}}
    ).next_delay()


def test_pace_sleeps_without_error():
    p = OpsecPolicy({"opsec": {"pacing": {"min_ms": 1, "max_ms": 2, "seed": 1}}})
    asyncio.run(p.pace())  # must not raise


# ── enforcement at the module gate, not just the policy object ───────────

import json
import tempfile
from pathlib import Path

from modules import MODULE_REGISTRY
from orchestrator import Orchestrator
from state.manager import StateManager


def _orch(tmp_path, config):
    """A minimally wired Orchestrator for exercising `_run_module`."""
    orch = Orchestrator.__new__(Orchestrator)
    orch.state = StateManager(str(tmp_path / "example.test"))
    orch.config = {"module_timeout": 60, **config}
    orch.opsec = OpsecPolicy(orch.config)
    orch._surface_seeded = True
    orch._closed = False
    return orch


def _module(ran, **attrs):
    class FakeModule:
        id = "fake"
        name = "Fake"
        stage = 5

        def __init__(self, state, config):
            pass

        async def run(self):
            ran.append(True)
            return "done"

    return {"class": FakeModule, "stage": 5, "active": True,
            "depends_on": [], **attrs}


def test_run_module_refuses_a_module_above_the_ceiling(monkeypatch, tmp_path):
    """The ceiling is enforced where modules actually start, so the pipeline,
    `--module`, the LLM loop and auto-run dependencies all obey it."""
    ran = []
    monkeypatch.setitem(MODULE_REGISTRY, "fake", _module(ran, detectability="high"))
    orch = _orch(tmp_path, {"opsec": {"max_detectability": "low"}})

    asyncio.run(orch._run_module("fake"))

    assert ran == [], "a high-detectability module ran under a low ceiling"
    skipped = [s for s in orch.state.module["skipped"] if s["module_id"] == "fake"]
    assert skipped and "ceiling" in skipped[-1]["reason"]

    rows = [json.loads(line) for line in
            (orch.state.state_dir / "operations.jsonl").read_text().splitlines()]
    refused = [r for r in rows if r.get("error", {}).get("code") == "opsec_gated"]
    assert refused, "the refusal was not recorded as opsec_gated"


def test_refused_module_does_not_spend_the_noise_budget(monkeypatch, tmp_path):
    """A ceiling refusal is not noise; only admitted modules are charged."""
    ran = []
    monkeypatch.setitem(MODULE_REGISTRY, "fake", _module(ran, detectability="high"))
    orch = _orch(tmp_path, {"opsec": {"max_detectability": "low", "budget": 10}})

    asyncio.run(orch._run_module("fake"))

    assert orch.opsec.spent == 0
    assert orch.opsec.remaining() == 10


def test_budget_is_charged_once_per_actual_run(monkeypatch, tmp_path):
    ran = []
    monkeypatch.setitem(MODULE_REGISTRY, "fake", _module(ran, detectability="low"))
    orch = _orch(tmp_path, {"opsec": {"budget": 1}})

    asyncio.run(orch._run_module("fake"))
    assert orch.opsec.spent == 1 and len(ran) == 1

    asyncio.run(orch._run_module("fake"))
    assert orch.opsec.spent == 1, "a refused module must not be charged"
    assert len(ran) == 1, "the second run should have been refused"


def test_pacing_is_wired_into_the_module_gate(monkeypatch, tmp_path):
    events = []
    monkeypatch.setitem(MODULE_REGISTRY, "fake", _module(events, detectability="low"))
    orch = _orch(tmp_path, {"opsec": {"pacing": {"min_ms": 1, "max_ms": 2}}})

    async def fake_pace():
        events.append("pace")

    monkeypatch.setattr(orch.opsec, "pace", fake_pace)

    asyncio.run(orch._run_module("fake"))

    assert events[0] == "pace", "module ran without the configured pacing"


def test_unknown_detectability_label_cannot_bypass_the_ceiling(monkeypatch, tmp_path):
    ran = []
    monkeypatch.setitem(MODULE_REGISTRY, "fake", _module(ran, detectability=""))
    orch = _orch(tmp_path, {"opsec": {"max_detectability": "medium"}})

    asyncio.run(orch._run_module("fake"))

    assert ran == [], "an unlabelled module was treated as quiet"
