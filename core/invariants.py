"""Declarative invariants and bounded race testing (I6).

A stateful business-logic defect is proven by CONTRAST: the operation
behaves correctly when replayed serially (first attempt accepted, second
rejected, invariant intact) but a bounded concurrent batch on a FRESH
seeded resource produces multiple accepted effects and a final state that
breaks the declared invariant. Timing never promotes; a batch that did
not actually overlap is ``untested / no_overlap``, never "clean".

Every seeded resource is recorded in the R8 mutation ledger BEFORE
creation and cleaned up with a fresh verification read; proof requires
that cleanup to be verified.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from core.authorization import finalize_canary_cleanup
from core.mutations import OwnedObject

KINDS = ("single_use", "balance", "stock", "idempotency", "uniqueness")

KIND_PRESETS = {
    "single_use": {"expect_second": "rejected", "trials": 4},
    "balance": {"expect_second": "rejected", "trials": 4},
    "stock": {"expect_second": "rejected", "trials": 4},
    "idempotency": {"expect_second": "single_effect", "trials": 4},
    "uniqueness": {"expect_second": "rejected", "trials": 4},
}

MAX_INVARIANTS = 5
MAX_TRIALS = 12
MAX_CONCURRENCY = 10


class InvariantSpecError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Expectation:
    op: str                 # lte | lt | gte | gt | eq | ne | contains
    value: Any
    delta: bool = False     # compare (observed - baseline) instead

    def evaluate(self, observed: Any, baseline: Any = None) -> bool:
        try:
            if self.delta:
                observed = float(observed) - float(baseline)
                target = float(self.value)
            elif self.op in ("lte", "lt", "gte", "gt"):
                observed = float(observed)
                target = float(self.value)
            else:
                target = self.value
        except (TypeError, ValueError):
            return False
        if self.op == "lte":
            return observed <= target
        if self.op == "lt":
            return observed < target
        if self.op == "gte":
            return observed >= target
        if self.op == "gt":
            return observed > target
        if self.op == "eq":
            return str(observed) == str(target)
        if self.op == "ne":
            return str(observed) != str(target)
        if self.op == "contains":
            return str(target) in str(observed)
        return False


@dataclass
class RequestSpec:
    method: str = "GET"
    url_template: str = ""
    body_template: str = ""
    headers: dict = field(default_factory=dict)
    identity: str = ""
    success_status: tuple = (200, 201, 202, 204)
    extract_ids: list = field(default_factory=list)

    def url(self, bindings: dict) -> str:
        return _render(self.url_template, bindings)

    def body(self, bindings: dict) -> str:
        return _render(self.body_template, bindings)


@dataclass
class InvariantSpec:
    name: str
    kind: str
    identity: str
    limit_semantics: str
    operation: RequestSpec
    read_probe: RequestSpec
    extract: dict
    expect: list
    trials: int = 4
    concurrency: int = 4
    settle_ms: int = 200
    read_attempts: int = 3
    expect_second: str = "rejected"     # rejected | single_effect
    serial_enabled: bool = True
    setup: Optional[RequestSpec] = None
    ref: str = ""
    idempotency_key: dict = field(default_factory=dict)
    cleanup: dict = field(default_factory=dict)


def _render(template: str, bindings: dict) -> str:
    out = str(template or "")
    for key, value in bindings.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def _request_spec(raw: dict, defaults: dict, identity: str) -> RequestSpec:
    raw = raw or {}
    headers = {str(k): str(v) for k, v in (raw.get("headers") or {}).items()}
    success = raw.get("success_status") or raw.get("status_in") or \
        defaults.get("success_status") or (200, 201, 202, 204)
    return RequestSpec(
        method=str(raw.get("method") or "GET").upper(),
        url_template=str(raw.get("url_template") or ""),
        body_template=str(raw.get("body_template") or ""),
        headers=headers,
        identity=str(raw.get("identity") or identity),
        success_status=tuple(int(s) for s in success),
        extract_ids=list(raw.get("extract_ids") or []),
    )


def parse_invariant(raw: dict, defaults: dict) -> InvariantSpec:
    if not isinstance(raw, dict):
        raise InvariantSpecError("spec_invalid")
    kind = str(raw.get("kind") or "").strip().lower()
    if kind not in KINDS:
        raise InvariantSpecError(f"spec_invalid: kind {kind or '<missing>'}")
    preset = KIND_PRESETS[kind]
    name = str(raw.get("name") or "").strip()
    identity = str(raw.get("identity") or "").strip()
    operation_raw = raw.get("operation") or {}
    read_raw = (raw.get("invariant") or {}).get("read_probe") \
        or raw.get("read_probe") or {}
    read_identity = str(read_raw.get("identity") or identity)
    if not name or not identity:
        raise InvariantSpecError("spec_invalid: name/identity required")
    if not operation_raw.get("url_template") or not read_raw.get("url_template"):
        raise InvariantSpecError(
            "spec_invalid: operation.read_probe url_template required")
    invariants = raw.get("invariant") or {}
    expect_raw = invariants.get("expect") or []
    if isinstance(expect_raw, dict):
        expect_raw = [expect_raw]
    expects = [
        Expectation(op=str(item.get("op") or "lte"),
                    value=item.get("value"), delta=bool(item.get("delta")))
        for item in expect_raw if isinstance(item, dict)
    ]
    if not expects:
        raise InvariantSpecError("spec_invalid: invariant.expect required")
    idem = raw.get("idempotency_key") or {}
    if "{trial}" in str(idem.get("value_template") or ""):
        raise InvariantSpecError(
            "spec_invalid: idempotency key must not vary per trial")
    serial_raw = raw.get("serial_control") or {}
    trials = int(raw.get("trials") or defaults.get("trials")
                 or preset["trials"])
    concurrency = int(raw.get("concurrency")
                      or defaults.get("concurrency") or 4)
    return InvariantSpec(
        name=name, kind=kind, identity=identity,
        limit_semantics=str(raw.get("limit_semantics") or ""),
        operation=_request_spec(operation_raw, defaults, identity),
        read_probe=_request_spec(read_raw, defaults, read_identity),
        extract=dict(invariants.get("extract") or raw.get("extract") or {}),
        expect=expects,
        trials=max(2, min(MAX_TRIALS, trials)),
        concurrency=max(2, min(MAX_CONCURRENCY, concurrency)),
        settle_ms=max(0, int(invariants.get("settle_ms")
                             or raw.get("settle_ms") or 200)),
        read_attempts=max(1, min(5, int(invariants.get("read_attempts")
                                        or raw.get("read_attempts") or 3))),
        expect_second=str(serial_raw.get("expect_second")
                          or preset["expect_second"]),
        serial_enabled=bool(serial_raw.get("enabled", True)),
        setup=_request_spec(raw["setup"], defaults, identity)
        if raw.get("setup") else None,
        ref=str(raw.get("ref") or ""),
        idempotency_key=dict(idem),
        cleanup=dict(raw.get("cleanup") or {}),
    )


def grade(spec: InvariantSpec, *, serial: dict, concurrent: dict,
          final_held: bool, cleanup_verified: bool,
          overlap: bool, baseline_ok: bool) -> tuple:
    """(state, reason). Timing fields are not inputs — by construction."""
    if not baseline_ok:
        return "untested", "baseline_unreadable"
    if not serial.get("first_accepted"):
        return "untested", "serial_first_rejected"
    serial_held = serial.get("expectation_held", False)
    if spec.serial_enabled and not serial_held:
        # Sequential replay already breaks the declared limit: a logic
        # bug, not a race.
        return "candidate", "serial_violated"
    if spec.serial_enabled and serial.get("second_accepted"):
        if spec.expect_second == "rejected":
            return "untested", "serial_control_failed"
    if not overlap:
        return "untested", "no_overlap"
    accepted = int(concurrent.get("accepted", 0) or 0)
    if final_held:
        if accepted >= 2 and spec.kind == "idempotency":
            return "candidate", "idempotency_unsupported"
        return "observation", "invariant_held"
    if not spec.serial_enabled:
        return "candidate", "no_serial_control"
    if accepted < 2:
        return "candidate", "insufficient_accepts"
    if not cleanup_verified:
        return "candidate", "cleanup_unverified"
    return "proof", "race_invariant_violated"


class RaceRunner:
    """Executes invariant specs with bounded concurrency and R8 cleanup."""

    def __init__(self, harness, state, module_id: str, base_url: str,
                 cfg: dict, log=None):
        self.harness = harness
        self.state = state
        self.module_id = module_id
        self.base_url = base_url.rstrip("/")
        self.cfg = cfg or {}
        self.log = log or (lambda *a, **k: None)
        self.request_timeout = max(3, int(self.cfg.get("timeout", 10) or 10))

    async def run(self, specs: list, run_token: str) -> dict:
        report = {"schema_version": 1, "run_token": run_token,
                  "state_counts": {"observation": 0, "candidate": 0,
                                   "proof": 0, "untested": 0},
                  "invariants": [], "untested": []}
        max_invariants = max(1, min(MAX_INVARIANTS, int(
            self.cfg.get("max_invariants", 3) or 3)))
        for index, spec in enumerate(specs[:max_invariants]):
            entry = await self._run_one(spec, run_token, index)
            report["invariants"].append(entry)
            counts = report["state_counts"]
            counts[entry["state"]] = counts.get(entry["state"], 0) + 1
            if entry["state"] == "untested":
                report["untested"].append(
                    {"name": spec.name, "reason": entry.get("reason", "")})
        return report

    async def _run_one(self, spec: InvariantSpec, run_token: str,
                       index: int) -> dict:
        entry = {"name": spec.name, "kind": spec.kind,
                 "identity": spec.identity,
                 "limit_semantics": spec.limit_semantics,
                 "state": "untested", "reason": ""}
        seed_token = f"{run_token}-{index}"
        bindings = {"run": seed_token, "inv": f"{run_token}-{index}"}
        baseline_ok = False
        serial = {}
        concurrent = {}
        final_held = False
        cleanup_verified = False
        overlap = False
        mut_ids = []
        try:
            # ── seed + baseline ─────────────────────────────────
            ref, mut_id = await self._seed(spec, bindings)
            if mut_id:
                mut_ids.append(mut_id)
            if spec.setup is not None and not ref:
                entry["reason"] = "no_bindable_ref"
                return entry
            bindings["id"] = ref
            entry["seed_ref"] = ref
            baseline_value = await self._read(spec, bindings)
            if baseline_value is None:
                entry["reason"] = "baseline_unreadable"
                return entry
            baseline_ok = True
            # Delta expectations describe the EFFECT of the operation and
            # cannot be judged against a baseline (the delta is 0 by
            # definition); only absolute limits gate the baseline.
            absolute = [e for e in spec.expect if not e.delta]
            if absolute and not absolute[-1].evaluate(
                    baseline_value, baseline_value):
                entry["reason"] = "baseline_violates_invariant"
                return entry
            # Distinct idempotency keys per phase: the serial key must be
            # spent before the concurrent batch starts, so the batch races
            # on a FRESH key.
            idem_template = str(spec.idempotency_key.get("value_template")
                                or "idem-{run}")
            if spec.idempotency_key.get("mode") == "header":
                bindings["_idem_key"] = _render(idem_template, bindings) + "-s"
            # ── serial control ──────────────────────────────────
            serial = await self._serial_phase(spec, bindings, baseline_value)
            entry["serial"] = serial
            await self._cleanup_seed(mut_id, ref, spec, entry)
            # ── concurrent batch on a FRESH seed ────────────────
            ref2, mut_id2 = await self._seed(spec, bindings)
            if mut_id2:
                mut_ids.append(mut_id2)
                entry["mut_id"] = mut_id2
            if spec.setup is not None and not ref2:
                entry["reason"] = "seed_failed"
                return entry
            bindings["id"] = ref2
            entry["seed_ref"] = ref2
            if spec.idempotency_key.get("mode") == "header":
                bindings["_idem_key"] = _render(idem_template, bindings) + "-c"
            baseline2 = await self._read(spec, bindings)
            serial_contrast = bool(
                serial.get("first_accepted")
                and serial.get("expectation_held")
                and (not serial.get("second_accepted")
                     or spec.expect_second == "single_effect"))
            concurrent = await self._concurrent_phase(spec, bindings)
            entry["concurrent"] = concurrent
            overlap = int(concurrent.get("max_in_flight", 0)) >= 2
            final_reads = []
            for _ in range(spec.read_attempts):
                value = await self._read(spec, bindings)
                if value is not None:
                    final_reads.append(value)
                await asyncio.sleep(spec.settle_ms / 1000)
            final_value = final_reads[-1] if final_reads else None
            entry["final_observed"] = final_value
            final_held = bool(
                final_value is not None and spec.expect
                and spec.expect[-1].evaluate(final_value, baseline2))
            if serial.get("second_accepted") \
                    and spec.expect_second == "rejected":
                serial_contrast = False
            # ── cleanup (seed + every bound effect) ─────────────
            cleanup_status = await self._cleanup_seed(mut_id2, ref2, spec,
                                                      entry)
            effects_status = await self._cleanup_effects(
                spec, concurrent, bindings)
            entry["cleanup"] = {"seed_status": cleanup_status,
                                "effects_status": effects_status}
            # A SEEDED resource must be verified-deleted; a seedless
            # invariant (e.g. idempotency on an existing account) needs no
            # seed cleanup and is judged on its effects alone.
            seed_ok = (cleanup_status == "verified"
                       if spec.setup is not None
                       else cleanup_status in ("verified", "not_required"))
            cleanup_verified = seed_ok and effects_status in (
                "verified", "not_required")
            state, reason = grade(
                spec, serial=serial, concurrent=concurrent,
                final_held=final_held, cleanup_verified=cleanup_verified,
                overlap=overlap or not spec.serial_enabled,
                baseline_ok=baseline_ok)
            if state == "proof" and not serial_contrast:
                state, reason = "candidate", "no_serial_contrast"
            entry["state"] = state
            entry["reason"] = reason
            entry["fingerprint"] = self._fingerprint(spec)
            return entry
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            entry["reason"] = f"error: {str(exc)[:120]}"
            return entry
        finally:
            for mut_id in mut_ids:
                current = self.state.mutations.current(mut_id)
                if current and current.get("cleanup", {}).get("status") == \
                        "outstanding":
                    self.state.mutations.mark_failed(
                        mut_id, "race run terminated before verified cleanup")

    # ── phases ──────────────────────────────────────────────────

    async def _seed(self, spec: InvariantSpec, bindings: dict) -> tuple:
        if spec.setup is None:
            return (spec.ref, None) if spec.ref else ("", None)
        mut_id = self.state.mutations.begin(
            self.module_id, "object_create",
            {"url_template": spec.setup.url_template,
             "method": spec.setup.method, "invariant": spec.name},
            identity=spec.setup.identity,
            owned_objects=[OwnedObject(type="resource", identifier="")])
        result = await self._request(spec.setup, bindings)
        if int(result.get("status", 0) or 0) not in spec.setup.success_status:
            return "", mut_id
        ref = None
        extract = (spec.cleanup or {}).get("extract_id") or {}
        if not extract:
            extract = spec.extract if not spec.operation.extract_ids else {}
        for candidate in (extract, *(spec.setup.extract_ids or [])):
            if not candidate:
                continue
            from core.workflows import _extract
            ref = _extract(candidate, str(result.get("body") or ""))
            if ref:
                break
        if not ref and isinstance(extract, dict) and extract.get("type") is None:
            from core.workflows import _extract
            ref = _extract({"type": "jsonpath", "path": "id"},
                           str(result.get("body") or ""))
        return ref or "", mut_id

    async def _serial_phase(self, spec: InvariantSpec, bindings: dict,
                            baseline_value: Any) -> dict:
        first = await self._request(spec.operation, bindings,
                                    key_phase="serial")
        first_accepted = int(first.get("status", 0) or 0) in \
            spec.operation.success_status
        await asyncio.sleep(spec.settle_ms / 1000)
        second = await self._request(spec.operation, bindings,
                                     key_phase="serial")
        second_accepted = int(second.get("status", 0) or 0) in \
            spec.operation.success_status
        await asyncio.sleep(spec.settle_ms / 1000)
        effect = await self._read(spec, bindings)
        held = bool(effect is not None and spec.expect
                    and spec.expect[-1].evaluate(effect, baseline_value))
        return {"first_status": first.get("status", 0),
                "first_accepted": first_accepted,
                "second_status": second.get("status", 0),
                "second_accepted": second_accepted,
                "effect_after_serial": effect,
                "expectation_held": held}

    async def _concurrent_phase(self, spec: InvariantSpec,
                                bindings: dict) -> dict:
        start = asyncio.Event()
        semaphore = asyncio.Semaphore(spec.concurrency)
        in_flight = {"current": 0, "max": 0}
        lock = asyncio.Lock()

        async def trial(number: int) -> dict:
            async with semaphore:
                await start.wait()
                async with lock:
                    in_flight["current"] += 1
                    in_flight["max"] = max(in_flight["max"],
                                           in_flight["current"])
                try:
                    result = await self._request(spec.operation, bindings,
                                                 key_phase="concurrent")
                finally:
                    async with lock:
                        in_flight["current"] -= 1
                status = int(result.get("status", 0) or 0)
                from core.workflows import _extract
                effect_id = None
                for candidate in spec.operation.extract_ids or []:
                    effect_id = _extract(candidate,
                                         str(result.get("body") or ""))
                    if effect_id:
                        break
                return {"trial": number, "status": status,
                        "accepted": status in spec.operation.success_status,
                        "effect_id": effect_id}

        tasks = [asyncio.create_task(trial(i))
                 for i in range(spec.trials)]
        await asyncio.sleep(0)
        start.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        accepted = 0
        effect_ids = []
        statuses = []
        for result in results:
            if isinstance(result, Exception):
                statuses.append(0)
                continue
            statuses.append(result["status"])
            if result["accepted"]:
                accepted += 1
            if result.get("effect_id"):
                effect_ids.append(result["effect_id"])
        await asyncio.sleep(spec.settle_ms / 1000)
        # Idempotency is judged on DISTINCT effects: a deduped replay
        # returns the stored id and must not count as a second effect.
        distinct_effects = len(set(effect_ids))
        effective_accepts = distinct_effects \
            if spec.kind == "idempotency" and effect_ids else accepted
        return {"trials": len(results), "accepted": effective_accepts,
                "accepted_statuses": accepted,
                "distinct_effects": distinct_effects,
                "rejected": len(results) - accepted, "statuses": statuses,
                "max_in_flight": in_flight["max"],
                "effect_ids": effect_ids}

    # ── reads, requests, cleanup ────────────────────────────────

    async def _read(self, spec: InvariantSpec, bindings: dict):
        result = await self._request(spec.read_probe, bindings)
        if int(result.get("status", 0) or 0) not in (200, 201, 202):
            return None
        from core.workflows import _extract
        return _extract(spec.extract, str(result.get("body") or ""))

    async def _request(self, request_spec: RequestSpec, bindings: dict,
                       key_phase: str = "") -> dict:
        url = self.base_url + request_spec.url(bindings)
        headers = dict(request_spec.headers)
        idem_key = bindings.get("_idem_key")
        if idem_key and "Idempotency-Key" not in headers:
            headers["Idempotency-Key"] = idem_key
        body = request_spec.body(bindings)
        kwargs = {"method": request_spec.method, "headers": headers or None}
        if body:
            kwargs["data"] = body
        identity = request_spec.identity
        if identity in ("anonymous", ""):
            return await self.harness.request_anonymous(url, **kwargs)
        return await self.harness.request(identity, url, **kwargs)

    async def _cleanup_seed(self, mut_id: Optional[str], ref: str,
                            spec: InvariantSpec, entry: dict) -> str:
        if not mut_id:
            return "not_required"
        status = await finalize_canary_cleanup(
            self.state,
            lambda identity, url, method="GET":
                self._fetch_as(identity, url, method),
            self.base_url, mut_id, ref, spec.cleanup or {}, spec.identity)
        return status

    async def _cleanup_effects(self, spec: InvariantSpec, concurrent: dict,
                               bindings: dict) -> str:
        effects = (spec.cleanup or {}).get("effects") or {}
        effect_ids = concurrent.get("effect_ids") or []
        if not effects:
            return "not_required" if not effect_ids else "failed"
        if not effect_ids:
            return "failed"
        template = str(effects.get("url_template") or "")
        method = str(effects.get("method") or "DELETE")
        identity = str(effects.get("identity") or spec.identity)
        gone = 0
        for effect_id in effect_ids:
            url = self.base_url + template.replace("{id}", str(effect_id))
            await self._fetch_as(identity, url, method)
            check = await self._fetch_as(identity, url)
            status = int(check.get("status", 0) or 0)
            if status in (404, 410) or status >= 400:
                gone += 1
        return "verified" if gone == len(effect_ids) else "failed"

    async def _fetch_as(self, identity: str, url: str,
                        method: str = "GET") -> dict:
        if identity in ("anonymous", ""):
            return await self.harness.request_anonymous(url, method=method)
        return await self.harness.request(identity, url, method=method)

    def _fingerprint(self, spec: InvariantSpec) -> str:
        from urllib.parse import urlparse
        host = urlparse(self.base_url).hostname or ""
        base = json.dumps({"module": "business_logic_race", "host": host,
                           "path": spec.operation.url_template,
                           "kind": spec.kind, "name": spec.name,
                           "identity": spec.identity}, sort_keys=True)
        return hashlib.sha256(base.encode()).hexdigest()[:16]
