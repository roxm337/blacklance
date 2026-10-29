"""Adaptive rate limiting + transient-retry for the HTTP pipeline.

A static rate limiter collects blocked responses when a target starts
throttling; these pin the feedback loop that makes it back off on 429/503
and honour Retry-After, bounded by the cap and the module deadline, plus
the engine's one retry on a transient transport failure.
"""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.deadline as dl
from tools.wrappers import RateLimiter, _parse_retry_after


def teardown_function(_):
    dl.clear_deadline()


# ── Retry-After parsing ──────────────────────────────────────────────

def test_parse_retry_after_numeric_and_junk():
    assert _parse_retry_after("12") == 12.0
    assert _parse_retry_after("0") == 0.0
    assert _parse_retry_after(None) == 0.0
    assert _parse_retry_after("") == 0.0
    assert _parse_retry_after("not-a-date") == 0.0


def test_parse_retry_after_http_date_is_non_negative():
    # A past date must clamp to 0, not a negative sleep.
    assert _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


# ── Backoff state machine ────────────────────────────────────────────

def test_429_sets_a_capped_cooldown():
    rl = RateLimiter(max_concurrent=5, max_per_minute=10000)
    rl.note_response(429, retry_after="5")
    assert rl._cooldown_until > time.monotonic()
    # Honour the server's own number when present.
    assert rl._cooldown_until - time.monotonic() <= 5.5


def test_hostile_retry_after_is_capped():
    rl = RateLimiter()
    rl.note_response(503, retry_after="3600")
    assert rl._cooldown_until - time.monotonic() <= RateLimiter.MAX_BACKOFF + 0.5


def test_consecutive_throttles_grow_then_reset():
    rl = RateLimiter()
    rl.note_response(429)                     # base penalty ×1
    first = rl._cooldown_until
    rl.note_response(429)                     # ×2, longer
    assert rl._cooldown_until >= first
    rl.note_response(200)                     # clean response resets the streak
    assert rl._consecutive_throttles == 0


# ── Deadline-bounded waiting ─────────────────────────────────────────

def test_cancelled_cooldown_wait_does_not_leak_a_slot():
    """A probe cancelled during backoff must release its concurrency slot.

    auth_audit cancels outstanding probes; when cancellation landed after the
    semaphore was acquired but during a cooldown sleep, the slot was lost and
    later modules stalled at their deadline after one recorded request.
    """
    rl = RateLimiter(max_concurrent=1, max_per_minute=10000)
    rl._cooldown_until = time.monotonic() + 60

    async def scenario():
        task = asyncio.create_task(rl.__aenter__())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        rl._cooldown_until = 0
        await asyncio.wait_for(rl.__aenter__(), timeout=1.0)
        await rl.__aexit__(None, None, None)

    asyncio.run(scenario())


def test_cooldown_never_sleeps_past_deadline():
    rl = RateLimiter(max_concurrent=1, max_per_minute=10000)
    rl.note_response(429, retry_after="30")   # would sleep 30s
    dl.set_deadline(time.monotonic() + 0.2)   # but only 0.2s of run left

    async def enter_once():
        async with rl:
            return True

    started = time.monotonic()
    assert asyncio.run(enter_once()) is True
    # The limiter must not have slept the full 30s — it is bounded by the
    # 0.2s deadline.
    assert time.monotonic() - started < 2.0


def test_clean_responses_do_not_throttle():
    rl = RateLimiter(max_concurrent=5, max_per_minute=10000)
    rl.note_response(200)
    rl.note_response(404)
    assert rl._cooldown_until <= time.monotonic()


# ── Engine transient retry ───────────────────────────────────────────

def _engine():
    from tools.http_engine import HttpEngine
    eng = HttpEngine.__new__(HttpEngine)
    eng.max_body = 1024
    eng.user_agent = "x"
    eng.requests = 0
    eng.session = lambda identity: None
    return eng


def test_engine_retries_once_on_transient_then_succeeds():
    dl.clear_deadline()
    eng = _engine()
    calls = {"n": 0}

    async def attempt(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"status": 0, "error": "connection_error: boom",
                    "body": "", "url": "", "history": []}
        return {"status": 200, "error": "", "body": "ok",
                "url": "u", "history": []}

    eng._attempt = attempt
    r = asyncio.run(eng.request("https://e.com/a", output="status", timeout=5))
    assert calls["n"] == 2 and r["status"] == 200


def test_engine_does_not_retry_ssl_errors():
    dl.clear_deadline()
    eng = _engine()
    calls = {"n": 0}

    async def attempt(*a, **k):
        calls["n"] += 1
        return {"status": 0, "error": "ssl_error: bad",
                "body": "", "url": "", "history": []}

    eng._attempt = attempt
    asyncio.run(eng.request("https://e.com/b", output="status", timeout=5))
    assert calls["n"] == 1


def test_engine_skips_retry_when_no_deadline_budget():
    eng = _engine()
    dl.set_deadline(time.monotonic() + 1)   # < timeout + 1, no room to retry
    calls = {"n": 0}

    async def attempt(*a, **k):
        calls["n"] += 1
        return {"status": 0, "error": "timeout",
                "body": "", "url": "", "history": []}

    eng._attempt = attempt
    asyncio.run(eng.request("https://e.com/c", output="status", timeout=5))
    assert calls["n"] == 1
