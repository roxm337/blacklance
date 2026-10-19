"""Tests for budget manager."""

import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.budget_manager import BudgetManager, BudgetExceededError
import pytest


def test_budget_starts_ok():
    budget = BudgetManager({})
    assert budget.check() is True


def test_request_counting():
    budget = BudgetManager({})
    budget.record_request(5)
    assert budget.state.requests_used == 5


def test_llm_call_counting():
    budget = BudgetManager({})
    budget.record_llm_call()
    budget.record_llm_call()
    assert budget.state.llm_calls_used == 2


def test_action_counting():
    budget = BudgetManager({})
    budget.record_action()
    assert budget.state.actions_used == 1


def test_action_limit_is_atomic_and_survives_resume(tmp_path):
    checkpoint = tmp_path / "budget.json"
    budget = BudgetManager({
        "budget_limits": {"max_actions": 2},
    }, checkpoint_path=checkpoint)
    assert budget.consume_action() == 1
    assert budget.consume_action() == 2
    with pytest.raises(BudgetExceededError):
        budget.consume_action()

    resumed = BudgetManager({
        "budget_limits": {"max_actions": 2, "resume": True},
    }, checkpoint_path=checkpoint)
    with pytest.raises(BudgetExceededError):
        resumed.consume_action()


def test_custom_limits():
    budget = BudgetManager({"budget_limits": {"max_requests": 10}})
    for _ in range(10):
        budget.record_request()
    assert budget.check() is False
    assert budget.state.errored
    assert budget.state.exceeded


def test_check_is_pure_boolean_never_raises():
    """check() is used as a boolean predicate (chain_executor._run_one);
    it must return False on exhaustion, never raise — otherwise the raise
    escapes execute() and skips state.save() after findings were pruned."""
    budget = BudgetManager({"budget_limits": {"max_requests": 1}})
    budget.record_request()
    assert budget.check() is False


def test_raise_if_exceeded_raises_for_controlled_call_sites():
    budget = BudgetManager({"budget_limits": {"max_requests": 1}})
    budget.record_request()
    with pytest.raises(BudgetExceededError):
        budget.raise_if_exceeded()
    fresh = BudgetManager({"budget_limits": {"max_requests": 1}})
    assert fresh.raise_if_exceeded() is True


def test_summary_shape():
    budget = BudgetManager({})
    budget.record_request(3)
    s = budget.summary()
    assert "requests" in s
    assert "wall_clock" in s
    assert "errored" in s
    assert not s["errored"]


def test_custom_limits_from_config():
    budget = BudgetManager({
        "budget_limits": {
            "max_requests": 100,
            "max_wall_clock_seconds": 600,
            "max_llm_calls": 10,
        }
    })
    assert budget.max_requests == 100
    assert budget.max_wall_clock == 600
    assert budget.max_llm_calls == 10


def test_consume_request_is_a_preflight_reservation():
    budget = BudgetManager({"budget_limits": {"max_requests": 1}})
    assert budget.consume_request() == 1
    with pytest.raises(BudgetExceededError):
        budget.consume_request()
    assert budget.state.requests_used == 1


def test_consume_llm_call_allows_exact_limit_then_blocks():
    budget = BudgetManager({"budget_limits": {"max_llm_calls": 1}})
    assert budget.consume_llm_call() == 1
    with pytest.raises(BudgetExceededError):
        budget.consume_llm_call()
    assert budget.state.llm_calls_used == 1


def test_external_tool_launches_share_an_atomic_cap(monkeypatch):
    import asyncio
    from tools import external

    budget = BudgetManager({
        "budget_limits": {"max_external_commands": 1},
    })
    external.configure_tool_budget(budget)
    try:
        first = asyncio.run(external.run_command(["definitely-not-a-real-tool"]))
        assert first["error"]
        with pytest.raises(BudgetExceededError):
            asyncio.run(external.run_command(["never-launched"]))
    finally:
        external.configure_tool_budget(None)

    assert budget.state.external_commands_used == 1


def test_budget_checkpoint_is_atomic_and_resume_is_explicit(tmp_path):
    checkpoint = tmp_path / "state" / "budget.json"
    first = BudgetManager({
        "budget_limits": {"max_requests": 10, "resume": False},
    }, checkpoint_path=checkpoint)
    first.consume_request(3)
    first.consume_llm_call()
    first.consume_external_command()

    payload = __import__("json").loads(checkpoint.read_text())
    assert payload["version"] == 1
    assert payload["state"]["requests_used"] == 3
    assert not checkpoint.with_suffix(".json.tmp").exists()

    fresh = BudgetManager({
        "budget_limits": {"max_requests": 10, "resume": False},
    }, checkpoint_path=checkpoint)
    assert fresh.state.requests_used == 0

    # Recreate persisted usage, then opt in to resuming it.
    fresh.consume_request(4)
    resumed = BudgetManager({
        "budget_limits": {"max_requests": 10, "resume": True},
    }, checkpoint_path=checkpoint)
    assert resumed.state.requests_used == 4


def test_corrupt_budget_checkpoint_starts_clean(tmp_path):
    checkpoint = tmp_path / "budget.json"
    checkpoint.write_text("not-json")
    budget = BudgetManager({
        "budget_limits": {"resume": True},
    }, checkpoint_path=checkpoint)
    assert budget.state.requests_used == 0
    assert __import__("json").loads(checkpoint.read_text())["version"] == 1


def test_shared_http_budget_covers_the_transport(monkeypatch):
    import asyncio
    from tools import wrappers

    class Engine:
        async def request(self, *args, **kwargs):
            return {"status": 200, "body": "", "error": None}

    budget = BudgetManager({"budget_limits": {"max_requests": 1}})
    monkeypatch.setattr(wrappers, "get_engine", lambda: Engine())
    wrappers.configure_http_budget(budget)
    try:
        first = asyncio.run(wrappers.curl("https://example.com"))
        assert first["status"] == 200
        with pytest.raises(BudgetExceededError):
            asyncio.run(wrappers.curl("https://example.com/second"))
    finally:
        wrappers.configure_http_budget(None)
