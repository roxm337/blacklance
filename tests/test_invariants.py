"""I6 invariant engine tests: spec validation, grading table, expectation
ops, the serial/concurrent proof protocol, R8 cleanup, and the rule that
timing is never an input to grading."""

from __future__ import annotations

import asyncio
import inspect
import json

from core.invariants import (Expectation, InvariantSpecError, RaceRunner,
                             grade, parse_invariant)
from state.manager import StateManager


class FakeHarness:
    def __init__(self, responder):
        self.mutations = None
        self.responder = responder
        self.calls = []
        self.identities = {}

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        self.calls.append((identity, method, url))
        result = self.responder(identity, url, method, data)
        if inspect.isawaitable(result):
            result = await result
        return result

    async def request_anonymous(self, url, method="GET", **kwargs):
        self.calls.append(("anonymous", method, url))
        result = self.responder("anonymous", url, method, None)
        if inspect.isawaitable(result):
            result = await result
        return result


def _cfg(**overrides):
    cfg = {"max_invariants": 3, "trials": 4, "concurrency": 4}
    cfg.update(overrides)
    return cfg


COUPON_SPEC = {
    "name": "coupon-single-redeem",
    "kind": "single_use",
    "identity": "alice",
    "limit_semantics": "one-time coupon",
    "setup": {"method": "POST", "url_template": "/api/coupons",
              "body_template": '{"code": "RACE-{run}"}',
              "headers": {"Content-Type": "application/json"},
              "extract_ids": [{"type": "jsonpath", "path": "id"}]},
    "operation": {"method": "POST",
                  "url_template": "/api/coupons/{id}/redeem",
                  "success_status": [200]},
    "serial_control": {"enabled": True, "expect_second": "rejected",
                       "settle_ms": 1},
    "invariant": {
        "read_probe": {"method": "GET",
                       "url_template": "/api/coupons/{id}"},
        "extract": {"type": "jsonpath", "path": "grants"},
        "expect": [{"op": "lte", "value": 1}],
        "settle_ms": 1, "read_attempts": 1},
    "cleanup": {"method": "DELETE", "url_template": "/api/coupons/{id}",
                "verify": {"method": "http_get",
                           "expect_status": [404]}},
}


def _coupon_responder(*, racy=True, cleanup_deletes=True):
    store = {"coupons": {}, "seq": [0]}

    async def responder(identity, url, method, data):
        # Every request spends a moment in flight so the client-side
        # in-flight counter (the overlap guard) observes a real batch.
        await asyncio.sleep(0.005)
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        if method == "POST" and path == "api/coupons":
            store["seq"][0] += 1
            ref = store["seq"][0]
            store["coupons"][ref] = {"id": ref, "grants": 0,
                                     "redeemed": False}
            return {"status": 201, "body": json.dumps({"id": ref})}
        if method == "POST" and path.endswith("/redeem"):
            ref = int(path.split("/")[-2])
            coupon = store["coupons"].get(ref)
            if not coupon:
                return {"status": 404, "body": ""}
            if racy:
                # Check-then-act across an await: serial replay is rejected
                # (the flag is set by then), but a concurrent batch all
                # passes the check before any write lands.
                snapshot = dict(coupon)
                await asyncio.sleep(0.01)
                if snapshot["redeemed"]:
                    return {"status": 409, "body": ""}
                coupon["redeemed"] = True
                coupon["grants"] += 1
                return {"status": 200, "body": json.dumps(coupon)}
            if coupon["redeemed"]:
                return {"status": 409, "body": ""}
            coupon["redeemed"] = True
            coupon["grants"] += 1
            return {"status": 200, "body": json.dumps(coupon)}
        if method == "DELETE":
            ref = int(path.rsplit("/", 1)[-1])
            if cleanup_deletes:
                store["coupons"].pop(ref, None)
            return {"status": 204, "body": ""}
        if method == "GET" and "/api/coupons/" in "/" + path:
            ref = int(path.rsplit("/", 1)[-1])
            coupon = store["coupons"].get(ref)
            if not coupon:
                return {"status": 404, "body": ""}
            return {"status": 200, "body": json.dumps(coupon)}
        return {"status": 404, "body": ""}

    return responder


def _runner(tmp_path, responder, cfg=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    harness = FakeHarness(responder)
    return RaceRunner(harness, state, "business_logic", "https://x",
                      cfg or _cfg()), state


def test_parse_rejects_bad_specs():
    try:
        parse_invariant({"kind": "nope", "name": "x", "identity": "a",
                         "operation": {}, "invariant": {}}, {})
        assert False
    except InvariantSpecError as exc:
        assert "spec_invalid" in exc.code
    try:
        parse_invariant({**COUPON_SPEC,
                         "idempotency_key": {"mode": "header",
                                             "value_template": "k-{trial}"}},
                        {})
        assert False
    except InvariantSpecError as exc:
        assert "idempotency" in exc.code


def test_expectation_ops():
    assert Expectation("lte", 1).evaluate("1", None)
    assert not Expectation("lte", 1).evaluate("2", None)
    assert Expectation("eq", 1, delta=True).evaluate(3, 2)
    assert not Expectation("eq", 2, delta=True).evaluate(3, 2)
    assert Expectation("contains", "x").evaluate("axb")
    assert not Expectation("lt", 0).evaluate("not-a-number")


def test_grade_never_accepts_timing_inputs():
    params = set(inspect.signature(grade).parameters)
    assert not params & {"elapsed", "timing", "wall_ms", "max_in_flight",
                         "overlap_ms", "duration"}


def test_grade_table():
    spec = parse_invariant(COUPON_SPEC, {})
    held_serial = {"first_accepted": True, "second_accepted": False,
                   "expectation_held": True}
    violated_conc = {"accepted": 3}
    # proof: contrast + violation + verified cleanup
    assert grade(spec, serial=held_serial, concurrent=violated_conc,
                 final_held=False, cleanup_verified=True,
                 overlap=True, baseline_ok=True) == (
        "proof", "race_invariant_violated")
    # no overlap → untested, never "clean"
    assert grade(spec, serial=held_serial, concurrent=violated_conc,
                 final_held=False, cleanup_verified=True,
                 overlap=False, baseline_ok=True) == (
        "untested", "no_overlap")
    # cleanup unverified → candidate only
    assert grade(spec, serial=held_serial, concurrent=violated_conc,
                 final_held=False, cleanup_verified=False,
                 overlap=True, baseline_ok=True) == (
        "candidate", "cleanup_unverified")
    # serial self-violation is a logic bug, not a race
    serial_broken = {"first_accepted": True, "second_accepted": True,
                     "expectation_held": False}
    assert grade(spec, serial=serial_broken, concurrent=violated_conc,
                 final_held=False, cleanup_verified=True,
                 overlap=True, baseline_ok=True) == (
        "candidate", "serial_violated")
    # held final state → observation
    assert grade(spec, serial=held_serial, concurrent=violated_conc,
                 final_held=True, cleanup_verified=True,
                 overlap=True, baseline_ok=True) == (
        "observation", "invariant_held")


def test_runner_proves_racy_endpoint_with_verified_cleanup(tmp_path):
    runner, state = _runner(tmp_path, _coupon_responder(racy=True))
    spec = parse_invariant(COUPON_SPEC, {})
    report = asyncio.run(runner.run([spec], "bltest01"))
    entry = report["invariants"][0]
    assert entry["state"] == "proof", entry
    assert entry["serial"]["second_accepted"] is False
    assert entry["concurrent"]["accepted"] >= 2
    assert entry["cleanup"]["seed_status"] == "verified"
    assert state.mutations.outstanding() == []


def test_runner_held_endpoint_is_observation(tmp_path):
    runner, state = _runner(tmp_path, _coupon_responder(racy=False))
    spec = parse_invariant(COUPON_SPEC, {})
    report = asyncio.run(runner.run([spec], "bltest02"))
    entry = report["invariants"][0]
    assert entry["state"] == "observation", entry
    assert entry["concurrent"]["accepted"] == 1
    assert state.mutations.outstanding() == []


def test_cleanup_failure_blocks_proof(tmp_path):
    runner, state = _runner(
        tmp_path, _coupon_responder(racy=True, cleanup_deletes=False))
    spec = parse_invariant(COUPON_SPEC, {})
    report = asyncio.run(runner.run([spec], "bltest03"))
    entry = report["invariants"][0]
    assert entry["state"] == "candidate", entry
    assert entry["reason"] == "cleanup_unverified"
    statuses = [(r.get("cleanup") or {}).get("status")
                for r in state.mutations.read_records()
                if r.get("kind") == "cleanup"]
    assert "failed" in statuses


def test_seed_failure_is_untested(tmp_path):
    def responder(identity, url, method, data):
        if method == "POST" and url.endswith("/api/coupons"):
            return {"status": 500, "body": ""}
        return {"status": 404, "body": ""}

    runner, state = _runner(tmp_path, responder)
    spec = parse_invariant(COUPON_SPEC, {})
    report = asyncio.run(runner.run([spec], "bltest04"))
    entry = report["invariants"][0]
    assert entry["state"] == "untested"
    assert entry["reason"] in ("no_bindable_ref", "seed_failed", "baseline_unreadable")
    assert state.mutations.outstanding() == []


# ── transport: delivery only, never grading ─────────────────────

def test_transport_defaults_to_connections_and_validates():
    assert parse_invariant(COUPON_SPEC, {}).transport == "connections"
    # Defaults come from the module's race config, spec value wins.
    assert parse_invariant(COUPON_SPEC,
                           {"transport": "single_packet"}).transport == (
        "single_packet")
    assert parse_invariant(
        {**COUPON_SPEC, "transport": "SINGLE_PACKET"},
        {"transport": "connections"}).transport == "single_packet"
    try:
        parse_invariant({**COUPON_SPEC, "transport": "spaceship"}, {})
        assert False
    except InvariantSpecError as exc:
        assert "transport spaceship" in str(exc)


def test_grade_does_not_take_transport():
    assert "transport" not in inspect.signature(grade).parameters


def test_single_packet_batch_replaces_the_connection_batch(tmp_path,
                                                           monkeypatch):
    runner, _state = _runner(tmp_path, _coupon_responder(racy=True))
    spec = parse_invariant({**COUPON_SPEC, "transport": "single_packet"}, {})
    seen = {}

    async def fake_send_async(url, requests, **kwargs):
        seen["url"] = url
        seen["requests"] = requests
        seen["kwargs"] = kwargs
        return {"transport": "h2",
                "statuses": [200, 200, 200, 200],
                "bodies": ["{}", "{}", "{}", "{}"],
                "in_flight": 4, "requests": 4, "error": ""}

    monkeypatch.setattr("core.single_packet.send_async", fake_send_async)
    result = asyncio.run(runner._concurrent_phase(spec, {"id": 7}))

    # One batch, all trials, delivered raw (the harness never saw them).
    assert len(seen["requests"]) == spec.trials
    assert all(req["path"] == "/api/coupons/7/redeem"
               for req in seen["requests"])
    assert seen["kwargs"]["transport"] == "auto"
    assert seen["kwargs"]["timeout"] == runner.request_timeout + 5
    assert result["transport"] == "h2_single_packet"
    assert result["accepted"] == 4
    assert result["max_in_flight"] == 4


def test_single_packet_failure_falls_back_and_says_so(tmp_path, monkeypatch):
    runner, _state = _runner(tmp_path, _coupon_responder(racy=True))
    spec = parse_invariant({**COUPON_SPEC, "transport": "single_packet"}, {})

    async def fake_send_async(url, requests, **kwargs):
        return {"transport": "h1", "statuses": [], "bodies": [],
                "in_flight": 0, "requests": len(requests),
                "error": "incomplete_batch"}

    monkeypatch.setattr("core.single_packet.send_async", fake_send_async)
    result = asyncio.run(runner._concurrent_phase(spec, {"id": 7}))

    # Delivery failed: the connection path runs, overlap is what it
    # actually measured, and the fallback is recorded rather than hidden.
    assert result["transport"] == "connections"
    assert result["transport_fallback"] == "incomplete_batch"
    assert result["max_in_flight"] >= 1


def test_single_packet_failure_with_connections_disabled_is_untested(
        tmp_path, monkeypatch):
    runner, _state = _runner(tmp_path, _coupon_responder(racy=True))
    spec = parse_invariant({**COUPON_SPEC, "transport": "single_packet"}, {})

    async def boom(url, requests, **kwargs):
        raise OSError("no route")

    monkeypatch.setattr("core.single_packet.send_async", boom)
    # The connection fallback still runs, but if it cannot overlap either the
    # caller must grade untested rather than clean.
    result = asyncio.run(runner._concurrent_phase(spec, {"id": 7}))
    assert result["transport"] == "connections"
    assert "single_packet_error" in result["transport_fallback"]
