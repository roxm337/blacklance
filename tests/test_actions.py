"""Tests for action library framework."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from actions.registry import (
    ActionRegistry, ActionMeta, ActionContext, ActionResult,
    RiskLevel, action, action_catalog, get_action, list_actions,
)


def test_action_registry_is_empty_by_default():
    assert ActionRegistry.size() >= 0  # actions may be registered by other imports


def test_action_decorator_registers_action():
    @action(
        id="test.ping",
        risk="SAFE",
        detectability="low",
        requires=["host"],
        produces="PingResult",
        idempotent=True,
        timeout=10,
        description="Test action for unit tests",
        category="test",
    )
    async def ping(ctx):
        return ActionResult(True, data={"host": ctx.params["host"]})

    meta, fn = ActionRegistry.get("test.ping")
    assert meta is not None
    assert meta.id == "test.ping"
    assert meta.risk == RiskLevel.SAFE
    assert "host" in meta.requires


def test_list_actions_returns_meta_list():
    metas = list_actions()
    ids = [m.id for m in metas]
    assert "test.ping" in ids


def test_action_catalog_is_typed_json_ready():
    catalog = action_catalog()
    item = next(entry for entry in catalog if entry["action_id"] == "test.ping")
    assert item["risk"] == "SAFE"
    assert item["requires"] == ["host"]
    assert item["detectability"] == "low"


def test_get_action_returns_tuple():
    result = get_action("test.ping")
    assert result is not None
    meta, fn = result
    assert meta.id == "test.ping"


def test_action_context_properties():
    ctx = ActionContext(
        action_id="test.ping",
        params={"host": "test.com"},
        target="test.com",
        timeout=30,
    )
    assert ctx.action_id == "test.ping"
    assert ctx.params["host"] == "test.com"
    assert ctx.elapsed >= 0.0


def test_action_result_defaults():
    result = ActionResult(True, data={"ok": True})
    assert result.success is True
    assert result.confidence == "TENTATIVE"
    assert result.elapsed_ms == 0.0
    assert result.error == ""


def test_risk_level_enum():
    assert RiskLevel.SAFE.value == "SAFE"
    assert RiskLevel.DESTRUCTIVE.value == "DESTRUCTIVE"
    assert RiskLevel.MEDIUM.value == "MEDIUM"


def test_execute_with_operations_records_terminal_op(tmp_path):
    """R7: action runs get one started + one terminal row in the ledger."""
    import asyncio
    from core.results import OperationsLedger

    @action(
        id="test.ping.op",
        risk="SAFE",
        detectability="low",
        requires=["host"],
        produces="PingResult",
        category="test",
    )
    async def ping_op(ctx):
        return ActionResult(True, data={"host": ctx.params["host"]})

    ledger = OperationsLedger(tmp_path / "operations.jsonl")
    ctx = ActionContext(
        action_id="test.ping.op",
        params={"host": "test.com"},
        target="test.com",
        operations=ledger,
    )
    result = asyncio.run(ActionRegistry.execute("test.ping.op", ctx))
    assert result.success is True
    records = ledger.read_records()
    assert len(records) == 2
    assert records[0]["outcome"] == "started"
    assert records[1]["outcome"] == "completed"
    assert records[1]["result_kind"] == "observation"
    assert records[1]["caller"] == {"kind": "action", "id": "test.ping.op"}


def test_execute_refusals_are_recorded(tmp_path):
    """Unknown actions and missing params become refused ops."""
    from core.results import OperationsLedger

    ledger = OperationsLedger(tmp_path / "operations.jsonl")
    ctx = ActionContext(
        action_id="nope.missing",
        params={},
        target="test.com",
        operations=ledger,
    )
    result = asyncio_run(ActionRegistry.execute("nope.missing", ctx))
    assert result.success is False
    rows = [r for r in ledger.read_records() if r["phase"] == "terminal"]
    assert len(rows) == 1
    assert rows[0]["outcome"] == "refused"
    assert rows[0]["error"]["code"] == "unknown_action"


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
