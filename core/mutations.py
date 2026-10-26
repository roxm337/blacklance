"""Durable mutation/cleanup ledger (R8).

Mutating modules (mass assignment probes, uploads, session creation,
stored XSS, business logic writes) record their side effects here BEFORE
the mutating request leaves. Each record captures the before-state, the
objects the probe owns, every rollback attempt, and a cleanup status that
only becomes ``verified`` through a fresh post-rollback check — never by
assumption.

The file is append-only and hash-chained like the audit log: each row is a
state transition for one mutation id (``begin`` → ``rollback`` → ``cleanup``),
so the full history is replayable and tampering is detectable. The current
state of a mutation is the merge of its rows in order.

Sidecar of ``snapshot.json``: the before-state must be durable before the
mutating I/O happens, while the snapshot only commits on save() and its
stale-writer rejection would fight two writers mid-module.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from core.audit_log import _sanitize, _truncate
from core.persistence import file_lock


class MutationLedgerError(Exception):
    pass


# Row kinds (append-only state transitions per mutation id)
BEGIN = "begin"
ROLLBACK = "rollback"
CLEANUP = "cleanup"

# Terminal cleanup states: no further retry is expected.
TERMINAL_CLEANUP = {"verified", "failed", "not_required"}

_KINDS = {
    "http_write", "upload", "object_create", "session", "config_change",
}


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


_ZERO_HASH = "0" * 64


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OwnedObject:
    """Something the probe created or changed and is responsible for."""

    type: str                       # user_field | upload | resource | session | ...
    identifier: str                 # e.g. field name, path, object id
    probe_value: Any = None
    neutral_value: Any = None


class MutationLedger:
    """Append-only mutation history with SHA-256 chaining."""

    def __init__(self, path: str | Path, *, verify_existing: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = _ZERO_HASH
        self._file = None

        with file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
            if self.path.exists():
                if verify_existing:
                    state = self.verify()
                    if not state["ok"]:
                        raise MutationLedgerError(
                            f"existing mutation log is corrupted at seq "
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

    def open(self) -> "MutationLedger":
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
                    raise MutationLedgerError(
                        "mutation log changed or was corrupted before append")
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

    # ── mutation lifecycle ────────────────────────────────────────

    def begin(self, module_id: str, kind: str, target: dict, *,
              identity: Optional[str] = None,
              before_state: Optional[dict] = None,
              owned_objects: Optional[list[OwnedObject]] = None) -> str:
        """Record the mutation BEFORE the mutating request leaves.

        Returns the mutation id. ``before_state`` is what the module read
        just before writing; its digest proves the ledger row was written
        before the write went out.
        """
        if kind not in _KINDS:
            raise MutationLedgerError(f"unknown mutation kind: {kind}")
        mut_id = f"MUT-{self._seq + 1:05d}-{uuid.uuid4().hex[:8]}"
        raw_before = _sanitize(before_state or {})
        self._append({
            "kind": BEGIN,
            "id": mut_id,
            "module_id": module_id,
            "mutation_kind": kind,
            "identity": identity,
            "target": _sanitize(_truncate(target or {})),
            "before_state": {
                "captured_at": _now(),
                "digest_sha256": hashlib.sha256(
                    _canonical(raw_before).encode("utf-8")).hexdigest(),
                "summary": _truncate(raw_before, 500),
            },
            "owned_objects": [
                {"type": obj.type, "identifier": obj.identifier,
                 "probe_value": _sanitize(obj.probe_value),
                 "neutral_value": _sanitize(obj.neutral_value)}
                for obj in (owned_objects or [])
            ],
            "cleanup": {"status": "outstanding", "verified_at": None,
                        "verification": None, "evidence_refs": []},
            "resume_state": "pending_cleanup",
            "at": _now(),
        })
        return mut_id

    def record_rollback(self, mut_id: str, outcome: str, *,
                        verification: Optional[dict] = None) -> dict:
        """Append a rollback attempt. Outcome: attempted|verified|failed|refused."""
        if outcome not in {"attempted", "verified", "failed", "refused"}:
            raise MutationLedgerError(f"unknown rollback outcome: {outcome}")
        return self._append({
            "kind": ROLLBACK,
            "id": mut_id,
            "outcome": outcome,
            "verification": _sanitize(_truncate(verification or {})),
            "at": _now(),
        })

    def verify_cleanup(self, mut_id: str, verification: dict, *,
                       evidence_refs: Optional[list[str]] = None) -> dict:
        """Mark cleanup verified — REQUIRES a fresh verification payload."""
        if not verification or not verification.get("method"):
            raise MutationLedgerError(
                "verified cleanup requires a verification method")
        return self._append({
            "kind": CLEANUP,
            "id": mut_id,
            "cleanup": {
                "status": "verified",
                "verified_at": _now(),
                "verification": _sanitize(_truncate(verification)),
                "evidence_refs": list(evidence_refs or []),
            },
            "resume_state": "clean",
            "at": _now(),
        })

    def mark_failed(self, mut_id: str, reason: str) -> dict:
        """Honest terminal state: cleanup was attempted/possible but failed."""
        return self._append({
            "kind": CLEANUP,
            "id": mut_id,
            "cleanup": {"status": "failed", "reason": _sanitize(str(reason))},
            "resume_state": "clean",
            "at": _now(),
        })

    def mark_not_required(self, mut_id: str, reason: str) -> dict:
        """Cleanup is not possible or needed (e.g. expiring session)."""
        return self._append({
            "kind": CLEANUP,
            "id": mut_id,
            "cleanup": {"status": "not_required",
                        "reason": _sanitize(str(reason))},
            "resume_state": "clean",
            "at": _now(),
        })

    # ── reads ─────────────────────────────────────────────────────

    def current(self, mut_id: str) -> Optional[dict]:
        """Merged current state of a mutation from its rows in order."""
        merged: dict = {}
        for row in self.rows_for(mut_id):
            for key, value in row.items():
                if key in ("seq", "hash", "prev", "schema_version"):
                    continue
                if key == "cleanup":
                    merged.setdefault("cleanup", {}).update(value or {})
                else:
                    merged[key] = value
        return merged or None

    def rows_for(self, mut_id: str) -> list[dict]:
        return [r for r in self.read_records() if r.get("id") == mut_id]

    def outstanding(self) -> list[dict]:
        """Mutations whose latest cleanup row is not terminal."""
        latest_cleanup: dict[str, str] = {}
        for row in self.read_records():
            cleanup = row.get("cleanup") or {}
            if row.get("kind") == CLEANUP \
                    and cleanup.get("status") in TERMINAL_CLEANUP:
                latest_cleanup[row.get("id")] = cleanup.get("status")
        return [
            self.current(row["id"])
            for row in self.read_records()
            if row.get("kind") == BEGIN and row.get("id") not in latest_cleanup
        ]

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
