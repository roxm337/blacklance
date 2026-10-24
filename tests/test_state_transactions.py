"""No network: transactional snapshots, stale writers, and immutable proof bytes."""

import json
import multiprocessing
from pathlib import Path

import pytest

from core.reporting import write_report_bundle
from state.manager import StateManager, StateConflictError
from core.persistence import atomic_json
from core.audit_log import AuditLog


def _writer(output, barrier, results, name):
    state = StateManager(output)
    state.add_asset("domain", name, name)
    barrier.wait(timeout=15)
    try:
        state.save()
        results.put("committed")
    except StateConflictError:
        results.put("conflict")


def _audit_writer(output, barrier, name):
    log = AuditLog(Path(output) / "audit.jsonl")
    try:
        barrier.wait(timeout=15)
        for index in range(8):
            log.record("fixture", {"writer": name, "index": index})
    finally:
        log.close()


def test_process_audit_writers_share_one_chain(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    workers = [ctx.Process(target=_audit_writer, args=(str(tmp_path), barrier, name))
               for name in ("one", "two")]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=25)
            assert worker.exitcode == 0
        log = AuditLog(tmp_path / "audit.jsonl")
        assert log.verify()["records"] == 16
        assert log.verify()["ok"]
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)


def test_failed_atomic_replace_preserves_old_bytes_and_removes_temporary(tmp_path, monkeypatch):
    path = tmp_path / "data.json"
    atomic_json(path, {"old": True})

    def fail(*args):
        raise OSError("injected replace failure")

    monkeypatch.setattr("core.persistence.os.replace", fail)
    with pytest.raises(OSError):
        atomic_json(path, {"new": True})
    assert json.loads(path.read_text()) == {"old": True}
    assert not list(tmp_path.glob("*.tmp"))


def test_processes_cannot_silently_overwrite_each_other(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    barrier, results = ctx.Barrier(2), ctx.Queue()
    workers = [ctx.Process(target=_writer, args=(str(tmp_path), barrier, results, name))
               for name in ("one", "two")]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=25)
            assert worker.exitcode == 0
        assert sorted(results.get(timeout=2) for _ in workers) == ["committed", "conflict"]
        assert len(StateManager(str(tmp_path)).assets["nodes"]) == 1
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        results.close()


def test_snapshot_wins_over_torn_or_stale_compatibility_views(tmp_path):
    state = StateManager(str(tmp_path))
    state.add_asset("domain", "domain:one", "one")
    state.add_evidence("m", "json", "subject", {"proof": True})
    state.save()
    state.assets_file.write_text("{torn")
    state.evidence_file.write_text('{"items": []}')
    restored = StateManager(str(tmp_path))
    assert restored.assets == state.assets
    assert restored.evidence == state.evidence
    assert restored.verify_evidence("EVIDENCE-0001")["ok"]


def test_failed_snapshot_replace_keeps_previous_generation(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path))
    state.add_asset("domain", "one", "one")
    state.save()
    state.add_asset("domain", "two", "two")
    real_write = state._write_json

    def fail_snapshot(path, data):
        if path == state.snapshot_file:
            raise OSError("injected storage failure")
        real_write(path, data)

    monkeypatch.setattr(state, "_write_json", fail_snapshot)
    with pytest.raises(OSError):
        state.save()
    assert state._dirty
    assert [a["key"] for a in StateManager(str(tmp_path)).assets["nodes"]] == ["one"]
    monkeypatch.setattr(state, "_write_json", real_write)
    state.save()
    assert len(StateManager(str(tmp_path)).assets["nodes"]) == 2


def test_failed_compatibility_export_does_not_undo_commit(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path))
    state.add_asset("domain", "one", "one")
    real_write = state._write_json

    def fail_export(path, data):
        if path == state.assets_file:
            raise OSError("injected export failure")
        real_write(path, data)

    monkeypatch.setattr(state, "_write_json", fail_export)
    state.save()
    assert not state._dirty
    assert StateManager(str(tmp_path)).assets == state.assets


def test_stale_evidence_writer_cannot_replace_committed_proof(tmp_path):
    first, stale = StateManager(str(tmp_path)), StateManager(str(tmp_path))
    eid = first.add_evidence("m", "json", "first", {"proof": "first"})
    first.save()
    stale.add_evidence("m", "json", "stale", {"proof": "stale"})
    with pytest.raises(StateConflictError):
        stale.save()
    restored = StateManager(str(tmp_path))
    assert restored.verify_evidence(eid)["ok"]
    evidence_path = tmp_path / restored.evidence["items"][0]["path"]
    assert json.loads(evidence_path.read_text())["data"] == {"proof": "first"}


def test_stale_report_writer_cannot_replace_current_report(tmp_path):
    first, stale = StateManager(str(tmp_path)), StateManager(str(tmp_path))
    first.add_asset("domain", "one", "one")
    first.save()
    paths = write_report_bundle(first, "example.com")
    before = Path(paths["summary"]).read_bytes()
    with pytest.raises(StateConflictError):
        write_report_bundle(stale, "example.com")
    assert Path(paths["summary"]).read_bytes() == before


@pytest.mark.parametrize("body", ["{broken", '[]', '{"schema_version": 999}'])
def test_corrupt_snapshot_never_silently_resets_state(tmp_path, body):
    state = StateManager(str(tmp_path))
    state.snapshot_file.write_text(body)
    with pytest.raises(ValueError):
        StateManager(str(tmp_path))


def test_invalid_nested_snapshot_is_rejected(tmp_path):
    state = StateManager(str(tmp_path))
    state.add_asset("domain", "one", "one")
    state.save()
    snapshot = json.loads(state.snapshot_file.read_text())
    snapshot["findings"]["findings"] = "not a list"
    state.snapshot_file.write_text(json.dumps(snapshot))
    with pytest.raises(ValueError, match="snapshot"):
        StateManager(str(tmp_path))


def test_rerun_clears_stale_success_and_old_skip_reasons(tmp_path):
    state = StateManager(str(tmp_path))
    state.complete_module("m")
    state.skip_module("m", "old reason")
    state.block_module("m", "old failure")
    run = state.begin_module_run("m")
    state.finish_module_run(run, "timeout")
    assert not state.is_module_complete("m")
    assert not state.module["skipped"]
    assert not state.module["blocked"]
