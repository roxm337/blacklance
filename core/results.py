"""Unified operation result and accounting contract (R7).

Every started/refused/failed/cancelled operation across every transport
(HTTP, subprocess, Docker, browser, sockets) gets one typed row in
``state/operations.jsonl``. Rows are chained like the audit log (SHA-256
over the canonical payload, ``prev`` links) so tampering is detectable with
:meth:`OperationsLedger.verify`.

Wire-level accounting (requests, command launches, bytes, container
removals) is attributed to the enclosing operation through a contextvar;
transport hooks report into the recorder without changing their return
shapes.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core.audit_log import _sanitize
from core.persistence import file_lock


class OperationsLedgerError(Exception):
    pass


class ResultKind(str, Enum):
    """Typed result vocabulary shared by pipeline and agent layers."""

    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    PROOF = "proof"
    VERIFICATION = "verification"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class Outcome(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    REFUSED = "refused"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass
class Accounting:
    """Mutable per-operation resource counters, merged under the op lock."""

    requests: int = 0
    commands: int = 0
    bytes_rx: int = 0
    containers_removed: int = 0
    containers_verified: Optional[bool] = None


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


_ZERO_HASH = "0" * 64


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


class Operation:
    """A live operation tracked by the ledger between start and finish."""

    def __init__(self, ledger: "OperationsLedger", op_id: str, caller: dict,
                 transport: str, provenance: dict, target: str,
                 started_at: str):
        self._ledger = ledger
        self.op_id = op_id
        self.caller = caller
        self.transport = transport
        self.provenance = provenance
        self.target = target
        self.started_at = started_at
        self.accounting = Accounting()
        self._lock = threading.Lock()
        self._finished = False

    @property
    def is_finished(self) -> bool:
        return self._finished

    def note(self, *, requests: int = 0, commands: int = 0, bytes_rx: int = 0,
             containers_removed: int = 0, containers_verified: Optional[bool] = None):
        with self._lock:
            a = self.accounting
            a.requests += requests
            a.commands += commands
            a.bytes_rx += bytes_rx
            a.containers_removed += containers_removed
            if containers_verified is not None:
                a.containers_verified = containers_verified

    def finish(self, outcome: Outcome, result_kind: ResultKind,
               *, evidence_refs: Optional[list[str]] = None,
               error: Optional[dict] = None,
               budget_reserved: Optional[dict] = None) -> dict:
        """Append the single terminal row and return it."""
        with self._lock:
            if self._finished:
                raise OperationsLedgerError(
                    f"operation {self.op_id} already finished")
            self._finished = True
            wall_ms = int((time.monotonic() - self._monotonic_start) * 1000)
        row = self._ledger._append_terminal(
            self, outcome, result_kind,
            evidence_refs=list(evidence_refs or []),
            error=error, budget_reserved=budget_reserved,
            wall_ms=wall_ms)
        self._terminal_row = row
        return row


class OperationsLedger:
    """Append-only hash-chained operations log (sidecar of the audit log)."""

    def __init__(self, path: str | Path, *, verify_existing: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = _ZERO_HASH
        self._file = None
        self._live: dict[str, Operation] = {}

        with file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
            if self.path.exists():
                if verify_existing:
                    state = self.verify()
                    if not state["ok"]:
                        raise OperationsLedgerError(
                            f"existing operations log is corrupted at seq "
                            f"{state.get('broken_at_seq')}")
                self._load_tail()
            self._tail_signature = self._signature()

    # ── lifecycle ─────────────────────────────────────────────────

    def _signature(self):
        try:
            stat = self.path.stat()
            return stat.st_ino, stat.st_size, stat.st_mtime_ns
        except FileNotFoundError:
            return None

    def _load_tail(self):
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last:
            self._seq = int(last.get("seq", 0))
            self._last_hash = last.get("hash", _ZERO_HASH)

    def open(self) -> "OperationsLedger":
        if self._file is None or self._file.closed:
            self._file = self.path.open("a", encoding="utf-8")
        return self

    def close(self):
        with self._lock:
            if self._file and not self._file.closed:
                self._file.flush()
                self._file.close()
                self._file = None

    # ── writing ───────────────────────────────────────────────────

    def _append(self, payload: dict) -> dict:
        with self._lock, file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
            if self._signature() != self._tail_signature:
                integrity = self.verify()
                if (not integrity["ok"] or not self.path.exists()
                        or integrity["records"] < self._seq):
                    raise OperationsLedgerError(
                        "operations log changed or was corrupted before append")
                self._load_tail()
                if self._file and not self._file.closed:
                    self._file.close()
            self.open()
            sequence = self._seq + 1
            payload = {"schema_version": 1, "seq": sequence, **payload,
                       "prev": self._last_hash}
            h = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
            payload["hash"] = h
            self._file.write(json.dumps(payload, sort_keys=True) + "\n")
            self._file.flush()
            self._last_hash = h
            self._seq = sequence
            self._tail_signature = self._signature()
            return payload

    def start(self, caller: dict, *, transport: str = "internal",
              provenance: Optional[dict] = None,
              target: str = "") -> Operation:
        op_id = f"OP-{self._seq + 1:05d}-{uuid.uuid4().hex[:8]}"
        started_at = _now()
        row = self._append({
            "op_id": op_id,
            "phase": "started",
            "caller": caller,
            "transport": transport,
            "provenance": provenance or {},
            "target": _sanitize(target),
            "outcome": Outcome.STARTED.value,
            "result_kind": None,
            "accounting": {"requests": 0, "commands": 0, "bytes_rx": 0,
                           "containers_removed": 0, "containers_verified": None},
            "budget": {},
            "evidence_refs": [],
            "error": None,
            "started_at": started_at,
            "finished_at": None,
        })
        op = Operation(self, op_id, caller, transport, provenance or {},
                       target, started_at)
        op._monotonic_start = time.monotonic()
        with self._lock:
            self._live[op_id] = op
        return op

    def refuse(self, caller: dict, reason_code: str, message: str,
               *, transport: str = "internal", target: str = "") -> dict:
        """A single terminal row for an operation that never started."""
        op_id = f"OP-{self._seq + 1:05d}-{uuid.uuid4().hex[:8]}"
        return self._append({
            "op_id": op_id,
            "phase": "terminal",
            "caller": caller,
            "transport": transport,
            "provenance": {},
            "target": _sanitize(target),
            "outcome": Outcome.REFUSED.value,
            "result_kind": ResultKind.ERROR.value,
            "accounting": {"requests": 0, "commands": 0, "bytes_rx": 0,
                           "containers_removed": 0, "containers_verified": None},
            "budget": {},
            "evidence_refs": [],
            "error": {"code": reason_code, "message": _sanitize(message)},
            "started_at": None,
            "finished_at": _now(),
        })

    def _append_terminal(self, op: Operation, outcome: Outcome,
                         result_kind: ResultKind, *, evidence_refs: list[str],
                         error: Optional[dict], budget_reserved: Optional[dict],
                         wall_ms: int) -> dict:
        with self._lock:
            self._live.pop(op.op_id, None)
        a = op.accounting
        return self._append({
            "op_id": op.op_id,
            "phase": "terminal",
            "caller": op.caller,
            "transport": op.transport,
            "provenance": op.provenance,
            "target": _sanitize(op.target),
            "outcome": outcome.value,
            "result_kind": result_kind.value,
            "accounting": {"requests": a.requests, "commands": a.commands,
                           "bytes_rx": a.bytes_rx,
                           "containers_removed": a.containers_removed,
                           "containers_verified": a.containers_verified,
                           "wall_ms": wall_ms},
            "budget": budget_reserved or {},
            "evidence_refs": list(evidence_refs),
            "error": error,
            "started_at": op.started_at,
            "finished_at": _now(),
        })

    # ── accounting attribution ────────────────────────────────────

    def note_accounting(self, info: Optional[dict] = None, **kwargs):
        """Attribute wire-level counters to the contextvar current operation.

        Accepts either a single info dict (from ``note_wire``) or keyword
        counters. No-op when no operation is active (standalone wrapper use).
        """
        op = _current_op.get()
        if op is None:
            return
        merged = dict(info or {})
        merged.update(kwargs)
        op.note(
            requests=merged.get("requests", 0),
            commands=merged.get("commands", 0),
            bytes_rx=merged.get("bytes_rx", 0),
            containers_removed=merged.get("containers_removed", 0),
            containers_verified=merged.get("containers_verified"),
        )

    def outstanding(self) -> list[dict]:
        """STARTED rows that never received a terminal row (crash forensics)."""
        rows = []
        terminal = set()
        for record in self.read_records():
            op_id = record.get("op_id")
            if record.get("phase") == "terminal":
                terminal.add(op_id)
        for record in self.read_records():
            if record.get("phase") == "started" \
                    and record.get("op_id") not in terminal:
                rows.append(record)
        return rows

    # ── verification ──────────────────────────────────────────────

    def verify(self) -> dict:
        if not self.path.exists():
            return {"ok": True, "records": 0}
        prev = _ZERO_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "records": count,
                            "broken_at_seq": count, "reason": "invalid JSON"}
                if not isinstance(record, dict):
                    return {"ok": False, "records": count,
                            "broken_at_seq": count, "reason": "invalid record"}
                stored_hash = record.get("hash")
                if type(record.get("seq")) is not int \
                        or record.get("seq") != count:
                    return {"ok": False, "records": count,
                            "broken_at_seq": count,
                            "reason": "non-contiguous sequence"}
                recomputed = hashlib.sha256(_canonical({
                    key: value for key, value in record.items()
                    if key != "hash"
                }).encode("utf-8")).hexdigest()
                if stored_hash != recomputed:
                    return {"ok": False, "records": count,
                            "broken_at_seq": count, "reason": "hash mismatch"}
                if record.get("prev") != prev:
                    return {"ok": False, "records": count,
                            "broken_at_seq": count, "reason": "broken chain link"}
                prev = stored_hash
        return {"ok": True, "records": count, "last_hash": prev}

    def read_records(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records


# ── op context for transport attribution ──────────────────────────

_current_op: contextvars.ContextVar[Optional[Operation]] = contextvars.ContextVar(
    "osint_current_op", default=None)


def set_op_context(op: Optional[Operation]):
    """Bind an operation to the current context; returns the reset token."""
    return _current_op.set(op)


def reset_op_context(token) -> None:
    _current_op.reset(token)


def current_op() -> Optional[Operation]:
    return _current_op.get()


# ── wire-level recorder (transport side channel) ──────────────────

_wire_recorder = None


def configure_wire_recorder(callback=None) -> None:
    """Install the callback transport hooks report wire accounting into.

    ``callback(info)`` receives ``{"transport": ..., "requests": n,
    "commands": n, "bytes_rx": n, "containers_removed": n,
    "containers_verified": bool|None}``. The orchestrator wires this to
    :meth:`OperationsLedger.note_accounting`; standalone wrapper use has no
    recorder and never pays the call cost.
    """
    global _wire_recorder
    _wire_recorder = callback


def note_wire(info: dict) -> None:
    if _wire_recorder is not None:
        try:
            _wire_recorder(info)
        except Exception:
            pass
