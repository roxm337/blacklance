"""A single, process-wide module deadline, enforced at the I/O boundary.

The orchestrator runs each module under a hard `asyncio.wait_for` guillotine.
When a module overruns, that guillotine cancels it mid-flight — discarding
every finding it had not yet written and recording a bare "timeout". On one
reference run eighteen modules died that way, which is *why* the report was
passive recon noise: the entire active-testing stage was guillotined before
it could produce or persist a single finding.

A module overruns by doing more I/O than its budget allows — another HTTP
probe, another tool subprocess — never by computing. So the budget is
enforced where the I/O happens: once the deadline passes, `curl`, `bash` and
`run_command` stop making calls and return a normal "failed probe" result
instead. Any module, whatever its loop shape, then drains its remaining
iterations in milliseconds and reaches its own finding-writing and teardown
code *before* the guillotine — turning a total loss into partial, persisted
coverage with no per-module changes required.

The deadline is a single global because modules run one at a time. It is
None outside a module run, so nothing changes for direct tool callers or
tests that never set it.
"""

import time

_deadline: "float | None" = None


def set_deadline(absolute_monotonic: "float | None") -> None:
    """Arm the deadline at an absolute `time.monotonic()` value (or clear it)."""
    global _deadline
    _deadline = absolute_monotonic


def clear_deadline() -> None:
    global _deadline
    _deadline = None


def deadline_remaining() -> float:
    """Seconds until the deadline; +inf when none is armed."""
    if _deadline is None:
        return float("inf")
    return _deadline - time.monotonic()


def deadline_reached() -> bool:
    """Has the current module's I/O budget run out?"""
    return _deadline is not None and time.monotonic() >= _deadline


def clamp_timeout(requested: float) -> float:
    """Cap a request/subprocess timeout at the time left before the deadline.

    Short-circuiting only new calls is not enough: a 120s tool subprocess or a
    45s HTTP request *launched* just before the deadline runs its own full
    timeout straight through the orchestrator's hard kill, which is exactly how
    cors/open-redirect/subdomain modules still hit 300s. Clamping means an
    in-flight call cannot outlive the module it belongs to — it is cut to
    whatever time remains, so the loop regains control and flushes.
    """
    try:
        requested = float(requested)
    except (TypeError, ValueError):
        return requested
    if _deadline is None:
        return requested
    remaining = _deadline - time.monotonic()
    if remaining <= 0:
        return requested  # deadline_reached() handles this; don't pass <=0 on
    return min(requested, remaining)
