"""OPSEC posture: a detectability ceiling, a detectability budget, and pacing.

The pipeline already gates *active* modules behind ``--active`` and enforces a
*risk* ceiling on exploitation. What it never had is a knob for how *loud* a run
is allowed to be. A hunter on a monitored target wants the low- and
medium-detectability surface swept but the nuclei / sqli / content-discovery
storm held back, and wants requests paced so they do not all arrive as one
burst that trips a rate-based alert.

This module is that knob. It is pure policy over the ``detectability`` label
every module already declares (``low`` | ``medium`` | ``high``), plus an
optional jittered delay between operations:

  * a *ceiling* — refuse anything louder than the operator will tolerate;
  * a *budget* — a finite amount of noise, weighted by detectability, so a run
    can sweep quietly and stop before it becomes conspicuous;
  * *pacing* — a bounded random delay, so operations do not form a burst.

Default (no ``opsec:`` config) sets no ceiling, an unlimited budget and no
pacing, so the existing pipeline is byte-for-byte unchanged. Nothing here
judges findings or touches the network; the orchestrator consults it at the
same gate that already enforces ``--active``.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Optional

# Louder is higher. An unrecognised label is treated as the loudest so a typo
# in config can only ever be *more* cautious, never silently permit noise.
DETECTABILITY_RANK = {"low": 0, "medium": 1, "high": 2}
_LOUDEST = max(DETECTABILITY_RANK.values())

# Default noise weights: a high-detectability sweep costs far more of the
# budget than a passive lookup. Operators can override per level.
DEFAULT_WEIGHTS = {"low": 1, "medium": 3, "high": 8}


def detectability_rank(level: str) -> int:
    return DETECTABILITY_RANK.get(str(level or "").strip().lower(), _LOUDEST)


@dataclass
class OpsecDecision:
    """Whether an operation is admitted, and why not when it is refused."""
    allowed: bool
    reason: str = ""


class OpsecPolicy:
    """Detectability ceiling + budget + pacing, read from the ``opsec:`` config.

    Permissive by construction: with no config there is no ceiling, the budget
    is unlimited and pacing is off. ``admit`` is the single entry point the
    orchestrator calls per module — it both decides and, on a yes, spends the
    module's weight, so the budget cannot be bypassed by forgetting to charge.
    """

    def __init__(self, config: Optional[dict] = None):
        opsec = ((config or {}).get("opsec") or {}) if config else {}

        ceiling = opsec.get("max_detectability")
        # A ceiling of "high" (or absent) is no ceiling at all.
        self.max_detectability = (str(ceiling).strip().lower()
                                  if ceiling else None)

        weights = opsec.get("weights") or {}
        self.weights = {
            level: int(weights.get(level, DEFAULT_WEIGHTS[level]))
            for level in DEFAULT_WEIGHTS
        }

        # 0 (or absent) means unlimited — matches BudgetManager's convention.
        self.budget = int(opsec.get("budget", 0) or 0)
        self.spent = 0

        pacing = opsec.get("pacing") or {}
        self.pace_min_ms = max(0, int(pacing.get("min_ms", 0) or 0))
        self.pace_max_ms = max(self.pace_min_ms,
                               int(pacing.get("max_ms", 0) or 0))
        self._rng = random.Random(pacing.get("seed"))

    # ── introspection ──────────────────────────────────────────────

    @property
    def active(self) -> bool:
        """True when any posture is in force — otherwise the policy is a no-op."""
        return bool(self.max_detectability or self.budget or self.pace_max_ms)

    def weight(self, level: str) -> int:
        return self.weights.get(str(level or "").strip().lower(),
                                self.weights["high"])

    def remaining(self) -> Optional[int]:
        """Budget left, or None when unlimited."""
        if not self.budget:
            return None
        return max(0, self.budget - self.spent)

    # ── decisions ──────────────────────────────────────────────────

    def allows_detectability(self, level: str) -> bool:
        if self.max_detectability is None:
            return True
        return detectability_rank(level) <= detectability_rank(
            self.max_detectability)

    def admit(self, level: str) -> OpsecDecision:
        """Admit (and charge) one operation of the given detectability.

        Refusals do not spend. A ceiling refusal and a budget refusal are
        distinct reasons so the operator can tell "too loud to ever run" from
        "quiet enough, but the run is out of noise".
        """
        level_label = str(level or "").strip().lower() or "high"
        if not self.allows_detectability(level_label):
            return OpsecDecision(
                False,
                f"{level_label}-detectability exceeds the opsec ceiling "
                f"'{self.max_detectability}'")

        cost = self.weight(level_label)
        if self.budget and self.spent + cost > self.budget:
            return OpsecDecision(
                False,
                f"opsec detectability budget exhausted "
                f"({self.spent}/{self.budget}, needs {cost})")

        self.spent += cost
        return OpsecDecision(True)

    # ── pacing ─────────────────────────────────────────────────────

    def next_delay(self) -> float:
        """Seconds to wait before the next operation (0 when pacing is off).

        Kept separate from :meth:`pace` so the delay distribution is testable
        without sleeping. Seeded via ``opsec.pacing.seed`` for reproducibility.
        """
        if self.pace_max_ms <= 0:
            return 0.0
        return self._rng.uniform(self.pace_min_ms, self.pace_max_ms) / 1000.0

    async def pace(self) -> None:
        delay = self.next_delay()
        if delay > 0:
            await asyncio.sleep(delay)
