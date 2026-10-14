"""Pipeline health: dependency memoization, skip reasons, probe hints,
auth concurrency, and cloud batching.

Covers the defects a live HIGH-ceiling run exposed: parameter_discovery
re-ran before every dependent (10x on quiet targets), idor_differ
skipped without recording why, the pentest hint told a HIGH run to
raise to MEDIUM, auth endpoints probed strictly sequentially, and
cloud_enum built every coroutine up front (unawaited-destruction
warnings on timeout).
"""
import asyncio
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator import _dep_inputs_grew, _no_probe_hint
from state.manager import StateManager


def _stub_state(runs=(), nodes=()):
    return SimpleNamespace(
        module={"runs": list(runs)},
        assets={"nodes": list(nodes)},
    )


def _run(dep, finished_at="t", assets_after=0):
    return {"module_id": dep, "status": "done",
            "finished_at": finished_at, "assets_after": assets_after}


def test_dep_never_ran_runs():
    assert _dep_inputs_grew(_stub_state(), "parameter_discovery") is True


def test_dep_finished_without_growth_does_not_rerun():
    nodes = [{"key": f"k{i}"} for i in range(5)]
    state = _stub_state(runs=[_run("parameter_discovery", assets_after=5)],
                        nodes=nodes)
    assert _dep_inputs_grew(state, "parameter_discovery") is False


def test_dep_reruns_on_new_assets():
    nodes = [{"key": f"k{i}"} for i in range(9)]
    state = _stub_state(runs=[_run("parameter_discovery", assets_after=5)],
                        nodes=nodes)
    assert _dep_inputs_grew(state, "parameter_discovery") is True


def test_dep_without_asset_snapshot_reruns():
    state = _stub_state(runs=[{"module_id": "x", "finished_at": "t"}],
                        nodes=[])
    assert _dep_inputs_grew(state, "x") is True


def test_no_probe_hint_locked_out():
    assert _no_probe_hint("LOW") == \
        "Raise with --max-risk MEDIUM to run detection actions."
    assert _no_probe_hint("SAFE") == \
        "Raise with --max-risk MEDIUM to run detection actions."


def test_no_probe_hint_already_allowed():
    assert "no testable parameters" in _no_probe_hint("HIGH")
    assert "no testable parameters" in _no_probe_hint("MEDIUM")


def test_idor_records_skip_reason_without_identities(tmp_path):
    from modules.idor_differ import IdorDiffer
    state = StateManager(str(tmp_path / "run"))
    module = IdorDiffer(state, {"target": {"domain": "example.com"}})
    assert asyncio.run(module.run()) == "skipped"
    reasons = [s for s in state.module["skipped"]
               if s["module_id"] == "idor_differ"]
    assert reasons and reasons[-1]["reason"] == "no identities configured"


def test_auth_probes_concurrently_first_success_wins(tmp_path):
    from modules.auth_audit import AuthAudit
    state = StateManager(str(tmp_path / "run"))
    module = AuthAudit(state, {"target": {"domain": "example.com"}})
    active = 0
    peak = 0

    async def fake_try_login(endpoint):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            if endpoint.endswith("/slow-win"):
                await asyncio.sleep(0.2)
                return {"session": "s"}
            await asyncio.sleep(5)
            return None
        finally:
            active -= 1

    async def noop(*args, **kwargs):
        return None

    module._login_endpoints = lambda: [
        "https://example.com/a", "https://example.com/slow-win",
        "https://example.com/c"]
    module._ratelimit_bypass_check = noop
    module._profile = noop
    module._try_login = fake_try_login
    module._store_identity = lambda endpoint, identity: None
    module._authenticated_follow_ups = noop
    module._forgery_sweep = noop
    module._write_access_probes = noop

    started = time.monotonic()
    assert asyncio.run(module.run()) == "done"
    elapsed = time.monotonic() - started
    assert peak >= 2, "endpoints must probe concurrently"
    assert elapsed < 30, "cancelled stalls must not burn their timeouts"


def test_cloud_enum_completes_small_sweep(tmp_path, monkeypatch):
    import modules.cloud_enum as cloud
    state = StateManager(str(tmp_path / "run"))

    async def fake_curl(url, **kwargs):
        return {"status": 404, "body": ""}

    monkeypatch.setattr(cloud, "curl", fake_curl)
    monkeypatch.setattr(
        cloud.CloudEnum, "_generate_candidates", lambda self: ["t1", "t2"])
    module = cloud.CloudEnum(
        state, {"target": {"domain": "example.com"}, "module_timeout": 120})
    assert asyncio.run(module.run()) == "done"
