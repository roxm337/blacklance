"""Base agent class — shared pattern for all specialized agents."""

from __future__ import annotations

import logging
from typing import Optional

from agents import get_llm_config
from agents.blackboard import Blackboard, AgentRole
from core.attack_graph import AttackGraph
from core.budget_manager import BudgetManager, BudgetExceededError
from state.manager import StateManager

logger = logging.getLogger("osint-agent")


class BaseAgent:
    """Every agent extends this. Each has a role, LLM access, and blackboard visibility."""

    role: AgentRole = AgentRole.SUPERVISOR

    def __init__(self, state: StateManager, config: dict, blackboard: Blackboard,
                 *, budget: BudgetManager | None = None, max_risk=None):
        self.state = state
        self.config = config
        self.bb = blackboard
        self.llm = get_llm_config(config)
        self.model = self.llm["model"]
        self.budget = budget or BudgetManager(config)
        if max_risk is None:
            from actions.registry import RiskLevel
            max_risk = RiskLevel.DESTRUCTIVE
        self.max_risk = max_risk
        self.attack_graph: Optional[AttackGraph] = None
        self.audit = None  # core.audit_log.AuditLog, set by the engagement runner

    # ── LLM helpers ───────────────────────────────────────────────

    async def _llm_call(self, system_prompt: str, user_prompt: str,
                        temperature: float = 0.1,
                        max_tokens: int = 2000) -> Optional[str]:
        try:
            self.budget.consume_llm_call()
        except BudgetExceededError as e:
            logger.warning(f"[{self.role.value}] {e}")
            return None

        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.llm.get("api_key"):
            kwargs["api_key"] = self.llm["api_key"]

        try:
            # LiteLLM performs provider/model initialization at import time.
            # Keep normal CLI and deterministic runs offline and fast.
            from litellm import acompletion
            response = await acompletion(**kwargs)
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"[{self.role.value}] LLM call failed: {e}")
            return None

    def _build_state_context(self) -> str:
        """Build a text summary of current state for LLM context."""
        summary = self.state.summary()
        lines = [f"Target: {self.config.get('target', {}).get('domain', '?')}"]
        lines.append(f"Assets: {summary.get('assets', 0)}")
        lines.append(f"Findings: {summary.get('findings', 0)}")
        lines.append(f"Modules completed: {len(summary.get('modules_completed', []))}")

        by_type = {}
        for node in self.state.assets.get("nodes", []):
            t = node["type"]
            by_type[t] = by_type.get(t, 0) + 1
        if by_type:
            lines.append("Assets by type:")
            for t, c in sorted(by_type.items()):
                lines.append(f"  {t}: {c}")

        if self.state.findings.get("findings"):
            lines.append("Top findings:")
            for f in self.state.findings["findings"][:5]:
                lines.append(f"  [{f['severity']}] {f['title']}")

        hyp_count = len(self.bb.hypotheses)
        confirmed = len([h for h in self.bb.hypotheses if h.status == "confirmed"])
        lines.append(f"Hypotheses: {hyp_count} total, {confirmed} confirmed")

        return "\n".join(lines)

    # ── Attack graph ──────────────────────────────────────────────

    def refresh_attack_graph(self):
        self.attack_graph = AttackGraph(self.state)
        self.attack_graph.build()

    def find_chains(self, min_score: float = 0.1, max_depth: int = 4) -> list:
        if not self.attack_graph:
            self.refresh_attack_graph()
        return self.attack_graph.find_chains(min_score=min_score, max_depth=max_depth)

    # ── Actions ───────────────────────────────────────────────────

    async def execute_action(self, action_id: str, params: dict,
                              target: str) -> dict:
        from actions import ActionRegistry
        from actions.registry import ActionContext

        meta, fn = ActionRegistry.get(action_id) or (None, None)
        if not meta:
            return {"success": False, "error": f"Unknown action: {action_id}"}

        from core.chain_executor import risk_allows
        if not risk_allows(meta.risk.value, self.max_risk):
            return {
                "success": False,
                "error": (f"blocked_risk: {meta.risk.value} action exceeds "
                          f"{self.max_risk.value} ceiling"),
                "blocked": True,
            }
        try:
            self.budget.raise_if_exceeded()
        except BudgetExceededError as exc:
            return {"success": False, "error": str(exc), "blocked": True}

        ctx = ActionContext(
            action_id=action_id,
            params=params,
            target=target,
            timeout=meta.timeout,
            meta=meta,
            audit=self.audit,
        )

        async with self.budget.semaphore:
            try:
                self.budget.consume_action()
            except BudgetExceededError as exc:
                return {"success": False, "error": str(exc), "blocked": True}
            result = await ActionRegistry.execute(action_id, ctx)
        return {
            "success": result.success,
            "data": result.data,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "error": result.error,
            "elapsed_ms": result.elapsed_ms,
        }

    # ── Reporting ─────────────────────────────────────────────────

    def log(self, message: str):
        logger.info(f"[{self.role.value}] {message}")
