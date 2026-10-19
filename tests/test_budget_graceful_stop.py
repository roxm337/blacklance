"""Budget exhaustion mid-module is a graceful stop, not a crash.

Before, a module that hit the HTTP/tool budget mid-run raised
BudgetExceededError into the orchestrator's generic handler: a traceback,
the module marked *blocked*, the run recorded as *error*. It is a planned
stop — the findings written before the cap are kept, the module is not
broken, and the run loop halts cleanly on its next budget check.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator as orch
from core.budget_manager import BudgetExceededError


def _orch(tmp):
    o = orch.Orchestrator.__new__(orch.Orchestrator)
    return o


def test_budget_exceeded_records_stopped_not_blocked(monkeypatch, tmp_path):
    from state.manager import StateManager
    from modules.base import BaseModule

    o = orch.Orchestrator.__new__(orch.Orchestrator)
    o.state = StateManager(str(tmp_path / "example.com"))
    o.config = {"module_timeout": 300}
    o._surface_seeded = True
    o.budget = None

    class BudgetyModule(BaseModule):
        id = "fake_budget"
        name = "Fake"
        stage = 5

        async def run(self):
            # Wrote a finding, then the cap is hit on the next request.
            self.state.add_finding(
                title="Partial finding kept", severity="LOW",
                confidence="FIRM", category="Attack Surface",
                description="written before the cap")
            raise BudgetExceededError("requests: 100/100")

    monkeypatch.setitem(
        orch.MODULE_REGISTRY, "fake_budget",
        {"class": BudgetyModule, "detectability": "low", "stage": 5,
         "active": True})

    asyncio.run(o._run_module("fake_budget"))

    # Not blocked, not an error — recorded as a clean stop.
    runs = o.state.module.get("runs", [])
    assert runs and runs[-1]["status"] == "stopped"
    assert "fake_budget" not in o.state.module.get("blocked", {})
    # The finding written before the cap survived.
    titles = [f["title"] for f in o.state.findings["findings"]]
    assert "Partial finding kept" in titles
