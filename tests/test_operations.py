"""R7 operations-ledger tests: typed results, accounting attribution,
refusal semantics, chain integrity, and concurrency."""

from __future__ import annotations

import json
import threading
import time

import pytest

from core.results import (OperationsLedger, OperationsLedgerError, Outcome,
                          ResultKind, configure_wire_recorder,
                          current_op, note_wire, reset_op_context,
                          set_op_context)


@pytest.fixture()
def ledger(tmp_path):
    return OperationsLedger(tmp_path / "state" / "operations.jsonl")


def _terminal_rows(ledger):
    return [r for r in ledger.read_records() if r["phase"] == "terminal"]


def test_start_finish_writes_one_started_and_one_terminal_row(ledger):
    op = ledger.start({"kind": "module", "id": "seed"})
    row = op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION,
                    evidence_refs=["EVIDENCE-0001"])
    records = ledger.read_records()
    assert len(records) == 2
    assert records[0]["phase"] == "started"
    assert records[0]["outcome"] == "started"
    assert records[1]["phase"] == "terminal"
    assert records[1]["outcome"] == "completed"
    assert records[1]["result_kind"] == "observation"
    assert records[1]["evidence_refs"] == ["EVIDENCE-0001"]
    assert row["op_id"] == records[1]["op_id"]


def test_finish_twice_raises(ledger):
    op = ledger.start({"kind": "module", "id": "seed"})
    op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)
    with pytest.raises(OperationsLedgerError):
        op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)


def test_refuse_never_starts_and_consumes_no_budget(ledger):
    row = ledger.refuse({"kind": "module", "id": "nuclei_scan"},
                        "active_gated", "active module requires --active")
    assert row["outcome"] == "refused"
    assert row["result_kind"] == "error"
    assert row["started_at"] is None
    assert row["error"]["code"] == "active_gated"
    assert row["accounting"]["requests"] == 0
    assert len(_terminal_rows(ledger)) == 1
    assert ledger.outstanding() == []


def test_accounting_attribution_via_contextvar_and_recorder(ledger):
    configure_wire_recorder(ledger.note_accounting)
    try:
        op = ledger.start({"kind": "module", "id": "xss_scan"},
                          transport="http")
        token = set_op_context(op)
        try:
            assert current_op() is op
            note_wire({"transport": "http", "requests": 3})
            note_wire({"transport": "subprocess", "commands": 1})
        finally:
            reset_op_context(token)
        # Outside the op context the recorder attributes nothing.
        note_wire({"transport": "http", "requests": 99})
        row = op.finish(Outcome.COMPLETED, ResultKind.CANDIDATE)
        assert row["accounting"]["requests"] == 3
        assert row["accounting"]["commands"] == 1
        assert row["accounting"]["wall_ms"] >= 0
    finally:
        configure_wire_recorder(None)


def test_unattributed_wire_notes_are_dropped(ledger):
    configure_wire_recorder(ledger.note_accounting)
    try:
        op = ledger.start({"kind": "module", "id": "seed"})
        note_wire({"transport": "http", "requests": 5})
        row = op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)
        assert row["accounting"]["requests"] == 0
    finally:
        configure_wire_recorder(None)


def test_outstanding_detects_started_without_terminal(ledger):
    op = ledger.start({"kind": "module", "id": "orphan"})
    ledger.start({"kind": "module", "id": "finished"}).finish(
        Outcome.COMPLETED, ResultKind.OBSERVATION)
    outstanding = ledger.outstanding()
    assert [r["op_id"] for r in outstanding] == [op.op_id]


def test_verify_detects_tampering(ledger):
    op = ledger.start({"kind": "module", "id": "seed"})
    op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)
    assert ledger.verify()["ok"] is True
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["outcome"] = "failed"
    lines[0] = json.dumps(first, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    state = ledger.verify()
    assert state["ok"] is False


def test_verify_rejects_corruption_on_open(tmp_path):
    path = tmp_path / "operations.jsonl"
    ledger = OperationsLedger(path)
    ledger.start({"kind": "module", "id": "a"}).finish(
        Outcome.COMPLETED, ResultKind.OBSERVATION)
    ledger.close()
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 99, "not": "a valid continuation"}\n')
    with pytest.raises(OperationsLedgerError):
        OperationsLedger(path)


def test_target_and_error_redaction(ledger):
    row = ledger.refuse(
        {"kind": "module", "id": "auth_audit"}, "blocked",
        "authorization=sekret123 in the reason",
        target="https://example.com/login?token=sekret456")
    assert "sekret123" not in json.dumps(row)
    assert "sekret456" not in json.dumps(row)


def test_concurrent_appends_keep_sequence_contiguous(ledger):
    errors = []

    def worker(i):
        try:
            op = ledger.start({"kind": "worker", "id": str(i)})
            op.note(requests=1)
            op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.verify()["ok"] is True
    seqs = [r["seq"] for r in ledger.read_records()]
    assert seqs == list(range(1, len(seqs) + 1))


def test_reopen_continues_sequence(tmp_path):
    path = tmp_path / "operations.jsonl"
    first = OperationsLedger(path)
    first.start({"kind": "module", "id": "a"}).finish(
        Outcome.COMPLETED, ResultKind.OBSERVATION)
    first.close()
    second = OperationsLedger(path)
    op = second.start({"kind": "module", "id": "b"})
    assert op.op_id.startswith("OP-00003")
    op.finish(Outcome.COMPLETED, ResultKind.OBSERVATION)
    assert second.verify()["ok"] is True
    assert second.verify()["records"] == 4
