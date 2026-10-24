"""Budget Manager — enforces engagement-level resource caps.

Caps:
  - max_requests: total HTTP requests across all actions
  - max_wall_clock_seconds: total runtime before forced stop
  - max_llm_calls: total LLM inference calls
  - max_concurrent_actions: actions running at the same time
"""

from __future__ import annotations

import time
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock


@dataclass
class BudgetState:
    requests_used: int = 0
    llm_calls_used: int = 0
    actions_used: int = 0
    external_commands_used: int = 0
    wall_start: float = 0.0
    wall_end: float = 0.0
    errored: bool = False
    exceeded: list[str] = field(default_factory=list)


class BudgetExceededError(Exception):
    pass


class BudgetManager:
    """Per-engagement resource accounting.

    Caps are operator-set convenience limits, not safety policy. A limit of 0
    (or absent) means unlimited for that dimension.
    """

    def __init__(self, config: dict | None = None,
                 checkpoint_path: str | Path | None = None):
        cfg = config or {}
        self.assessment = cfg.get("assessment")
        limits = cfg.get("budget_limits", {})

        self.max_requests = int(limits.get("max_requests", 0) or 0)
        self.max_wall_clock = int(limits.get("max_wall_clock_seconds", 0) or 0)
        self.max_llm_calls = int(limits.get("max_llm_calls", 0) or 0)
        self.max_external_commands = int(
            limits.get("max_external_commands", 0) or 0)
        self.max_actions = int(limits.get("max_actions", 0) or 0)
        self.resume = bool(limits.get("resume", False))
        # Concurrency still needs a real value for the semaphore; it is a
        # throughput knob rather than a cap, so it falls back to 5.
        self.max_concurrent_actions = int(limits.get("max_concurrent_actions", 0) or 5)

        self.state = BudgetState(wall_start=time.time())
        self._lock = Lock()
        self._semaphore = None
        self._checkpoint_path = (Path(checkpoint_path)
                                 if checkpoint_path else None)
        if self.resume:
            self._load_checkpoint()
        self.checkpoint()

    def _load_checkpoint(self) -> None:
        """Restore counters explicitly, excluding time spent while stopped."""
        path = self._checkpoint_path
        if path is None or not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("state"), dict):
                raise ValueError("Invalid budget checkpoint shape")
            counters = payload.get("state", {})
            self.state.requests_used = max(
                0, int(counters.get("requests_used", 0) or 0))
            self.state.llm_calls_used = max(
                0, int(counters.get("llm_calls_used", 0) or 0))
            self.state.actions_used = max(
                0, int(counters.get("actions_used", 0) or 0))
            self.state.external_commands_used = max(
                0, int(counters.get("external_commands_used", 0) or 0))
            elapsed = max(0.0, float(payload.get("elapsed_seconds", 0) or 0))
            self.state.wall_start = time.time() - elapsed
            self.state.errored = bool(counters.get("errored", False))
            exceeded = counters.get("exceeded", [])
            self.state.exceeded = ([str(item) for item in exceeded]
                                   if isinstance(exceeded, list) else [])
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            if self.assessment:
                raise RuntimeError("Selected assessment has an invalid budget checkpoint")
            # A corrupt checkpoint must not prevent a new controlled run.
            self.state = BudgetState(wall_start=time.time())
            return
        if self.assessment and payload.get("assessment") != self.assessment:
            raise RuntimeError("Budget checkpoint belongs to a different assessment")

    def _checkpoint_locked(self) -> None:
        path = self._checkpoint_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "assessment": self.assessment,
            "updated_at": time.time(),
            "elapsed_seconds": max(0.0, time.time() - self.state.wall_start),
            "state": asdict(self.state),
            "limits": {
                "max_requests": self.max_requests,
                "max_wall_clock_seconds": self.max_wall_clock,
                "max_llm_calls": self.max_llm_calls,
                "max_external_commands": self.max_external_commands,
                "max_actions": self.max_actions,
                "max_concurrent_actions": self.max_concurrent_actions,
            },
        }
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary, path)

    def checkpoint(self) -> None:
        """Atomically persist current counters for crash recovery."""
        with self._lock:
            self._checkpoint_locked()

    @property
    def semaphore(self):
        if self._semaphore is None:
            from asyncio import Semaphore
            self._semaphore = Semaphore(self.max_concurrent_actions)
        return self._semaphore

    def check(self) -> bool:
        """Pure predicate: True if budget allows continuing, False if exceeded.

        Never raises — callers use this as a boolean (notably
        ChainExecutor._run_one). Raising here used to escape execute() after
        prune_module_findings, deleting prior findings with no replacements
        and skipping state.save(). Controlled call sites that want the
        exception use raise_if_exceeded() below.
        """
        now = time.time()
        exceeded = []

        if self.max_requests and self.state.requests_used >= self.max_requests:
            exceeded.append(f"requests ({self.state.requests_used}/{self.max_requests})")
        if self.max_wall_clock and now - self.state.wall_start >= self.max_wall_clock:
            exceeded.append(f"wall clock ({now - self.state.wall_start:.0f}s/{self.max_wall_clock}s)")
        if self.max_llm_calls and self.state.llm_calls_used >= self.max_llm_calls:
            exceeded.append(f"LLM calls ({self.state.llm_calls_used}/{self.max_llm_calls})")
        if self.max_external_commands \
                and self.state.external_commands_used >= self.max_external_commands:
            exceeded.append(
                f"external commands ({self.state.external_commands_used}/"
                f"{self.max_external_commands})")
        if self.max_actions and self.state.actions_used >= self.max_actions:
            exceeded.append(
                f"actions ({self.state.actions_used}/{self.max_actions})")

        if exceeded:
            self.state.exceeded = exceeded
            self.state.errored = True
            self.checkpoint()
            return False

        return True

    def raise_if_exceeded(self) -> bool:
        """check() that raises for controlled call sites (agents) that handle
        BudgetExceededError themselves and stop gracefully."""
        if not self.check():
            raise BudgetExceededError(
                f"Budget exceeded: {', '.join(self.state.exceeded)}")
        return True

    def record_request(self, count: int = 1):
        with self._lock:
            self.state.requests_used += count
            self._checkpoint_locked()

    def consume_request(self, count: int = 1) -> int:
        """Atomically reserve request budget before network I/O.

        ``check()`` followed by ``record_request()`` is racy when modules issue
        concurrent probes: several coroutines can all observe the last slot and
        then overshoot the engagement ceiling.  The HTTP wrapper calls this
        method immediately before dispatch so the cap is shared by every module
        and agent using the common transport.
        """
        count = max(1, int(count or 1))
        with self._lock:
            now = time.time()
            exceeded = []
            if self.max_requests \
                    and self.state.requests_used + count > self.max_requests:
                exceeded.append(
                    f"requests ({self.state.requests_used}/{self.max_requests})")
            if self.max_wall_clock \
                    and now - self.state.wall_start >= self.max_wall_clock:
                exceeded.append(
                    f"wall clock ({now - self.state.wall_start:.0f}s/"
                    f"{self.max_wall_clock}s)")
            if exceeded:
                self.state.exceeded = exceeded
                self.state.errored = True
                self._checkpoint_locked()
                raise BudgetExceededError(
                    f"Budget exceeded: {', '.join(exceeded)}")
            self.state.requests_used += count
            self._checkpoint_locked()
            return self.state.requests_used

    def record_llm_call(self):
        with self._lock:
            self.state.llm_calls_used += 1
            self._checkpoint_locked()

    def consume_llm_call(self) -> int:
        """Atomically reserve one inference before contacting a provider."""
        with self._lock:
            now = time.time()
            exceeded = []
            if self.max_llm_calls \
                    and self.state.llm_calls_used + 1 > self.max_llm_calls:
                exceeded.append(
                    f"LLM calls ({self.state.llm_calls_used}/{self.max_llm_calls})")
            if self.max_wall_clock \
                    and now - self.state.wall_start >= self.max_wall_clock:
                exceeded.append(
                    f"wall clock ({now - self.state.wall_start:.0f}s/"
                    f"{self.max_wall_clock}s)")
            if exceeded:
                self.state.exceeded = exceeded
                self.state.errored = True
                self._checkpoint_locked()
                raise BudgetExceededError(
                    f"Budget exceeded: {', '.join(exceeded)}")
            self.state.llm_calls_used += 1
            self._checkpoint_locked()
            return self.state.llm_calls_used

    def record_action(self):
        return self.consume_action()

    def configure_action_limit(self, count: int) -> None:
        """Apply the CLI engagement action cap to the shared budget."""
        with self._lock:
            self.max_actions = max(0, int(count or 0))
            self._checkpoint_locked()

    def consume_action(self) -> int:
        """Atomically reserve one registered action execution."""
        with self._lock:
            if self.max_actions and self.state.actions_used + 1 > self.max_actions:
                self.state.exceeded = [
                    f"actions ({self.state.actions_used}/{self.max_actions})"]
                self.state.errored = True
                self._checkpoint_locked()
                raise BudgetExceededError(
                    f"Budget exceeded: {self.state.exceeded[0]}")
            self.state.actions_used += 1
            self._checkpoint_locked()
            return self.state.actions_used

    def consume_external_command(self) -> int:
        """Atomically reserve one external-tool process launch."""
        with self._lock:
            if self.max_external_commands and \
                    self.state.external_commands_used + 1 > self.max_external_commands:
                self.state.exceeded = [
                    f"external commands ({self.state.external_commands_used}/"
                    f"{self.max_external_commands})"]
                self.state.errored = True
                self._checkpoint_locked()
                raise BudgetExceededError(
                    f"Budget exceeded: {self.state.exceeded[0]}")
            self.state.external_commands_used += 1
            self._checkpoint_locked()
            return self.state.external_commands_used

    def elapsed(self) -> float:
        return time.time() - self.state.wall_start

    def summary(self) -> dict:
        return {
            "requests": f"{self.state.requests_used}/{self.max_requests or '∞'}",
            "wall_clock": f"{self.elapsed():.0f}s/{self.max_wall_clock or '∞'}s",
            "llm_calls": f"{self.state.llm_calls_used}/{self.max_llm_calls or '∞'}",
            "actions": f"{self.state.actions_used}/{self.max_actions or '∞'}",
            "external_commands": (
                f"{self.state.external_commands_used}/"
                f"{self.max_external_commands or '∞'}"),
            "errored": self.state.errored,
            "exceeded": self.state.exceeded,
        }
