"""Origin/assessment selection is local-only; no target traffic is needed."""

import json
import asyncio
import sys
import multiprocessing
from pathlib import Path

import pytest

from core.assessments import AssessmentStore, AssessmentLease, canonical_origin
from core.budget_manager import BudgetManager
from core.reporting import write_report_bundle
from orchestrator import Orchestrator
from state.manager import StateManager


@pytest.mark.parametrize("target, expected", [
    ("EXAMPLE.com", "https://example.com"),
    ("https://EXAMPLE.com.:443/path?a=1", "https://example.com"),
    ("http://example.com:80/path", "http://example.com"),
    ("example.com:3000/path", "http://example.com:3000"),
    ("https://example.com:3000", "https://example.com:3000"),
    ("[::1]:3000", "http://[::1]:3000"),
    ("http://[0:0:0:0:0:0:0:1]:80", "http://[::1]"),
    ("https://bücher.example", "https://xn--bcher-kva.example"),
    ("https://user:secret@example.com/a", "https://example.com"),
    ("example.com/path:section", "https://example.com"),
])
def test_canonical_origins(target, expected):
    assert canonical_origin(target) == expected


@pytest.mark.parametrize("target", ["", "ftp://example.com", "http://", "http://e.test:bad", "http://e.test:0"])
def test_invalid_origins_do_not_create_output(tmp_path, target):
    with pytest.raises(ValueError):
        AssessmentStore(tmp_path / "output", target)
    assert not (tmp_path / "output").exists()


def test_listing_is_read_only_and_default_ports_share_a_namespace(tmp_path):
    one = AssessmentStore(tmp_path / "output", "https://EXAMPLE.com:443/a")
    two = AssessmentStore(tmp_path / "output", "example.com")
    assert one.service_dir == two.service_dir
    assert one.list() == []
    assert not one.root.exists()


def test_ports_schemes_and_fresh_runs_have_independent_state(tmp_path):
    store = AssessmentStore(tmp_path, "http://localhost:3000")
    first = store.create()
    state = StateManager(str(first.directory))
    state.complete_module("seed_discovery")
    state.add_asset("domain", "domain:localhost", "localhost")
    state.add_finding("old", "HIGH", "FIRM", "Test", "fixture")
    state.add_evidence("m", "json", "old", {"old": True})
    state.save()
    candidates = [store.create(),
                  AssessmentStore(tmp_path, "http://localhost:3001").create(),
                  AssessmentStore(tmp_path, "https://localhost:3000").create()]
    for item in candidates:
        fresh = StateManager(str(item.directory))
        assert not fresh.assets["nodes"]
        assert not fresh.findings["findings"]
        assert not fresh.evidence["items"]
        assert not fresh.module["completed"]
    assert len({item.directory for item in [first, *candidates]}) == 4
    assert StateManager(str(first.directory)).is_module_complete("seed_discovery")


def test_resume_restores_only_the_selected_assessment(tmp_path):
    run = Orchestrator("localhost:3000", str(tmp_path))
    identifier, directory = run.assessment.id, run.state.output_dir
    run.state.complete_module("seed_discovery")
    run.state.add_asset("domain", "domain:localhost", "localhost")
    run.budget.consume_request()
    run.state.save()
    run.close()
    resumed = Orchestrator("http://localhost:3000/other", str(tmp_path),
                           run_mode="resume", assessment_id=identifier)
    try:
        assert resumed.state.output_dir == directory
        assert resumed.state.is_module_complete("seed_discovery")
        assert resumed.budget.state.requests_used == 1
        assert resumed.config["assessment"]["assessment_id"] == identifier
        assert resumed.state._primary_host() == "localhost"
    finally:
        resumed.close()
    with pytest.raises(ValueError):
        Orchestrator("localhost:3001", str(tmp_path), run_mode="resume", assessment_id=identifier)


def test_assessment_has_one_executor_and_releases_its_lease(tmp_path):
    store = AssessmentStore(tmp_path, "example.com")
    selected = store.create()
    lease = AssessmentLease(selected.directory)
    try:
        with pytest.raises(ValueError, match="already running"):
            AssessmentLease(selected.directory)
    finally:
        lease.close()
    next_lease = AssessmentLease(selected.directory)
    next_lease.close()


def test_retest_has_a_baseline_but_no_current_findings_or_completion(tmp_path):
    store = AssessmentStore(tmp_path, "example.com")
    parent = store.create()
    state = StateManager(str(parent.directory))
    state.complete_module("m")
    state.add_finding("old", "HIGH", "FIRM", "Test", "fixture")
    state.save()
    original = state.snapshot_file.read_bytes()
    retest = store.select("retest", parent_id=parent.id)
    current = StateManager(str(retest.directory))
    assert not current.findings["findings"]
    assert not current.assets["nodes"]
    assert not current.module["completed"]
    assert current.module["assessment"]["parent_assessment_id"] == parent.id
    paths = write_report_bundle(current, "example.com")
    diff = json.loads(Path(paths["regression"]).read_text())
    assert diff["counts"]["untested"] == 1
    assert diff["counts"]["resolved"] == 0
    assert state.snapshot_file.read_bytes() == original


def test_import_copies_evidence_and_does_not_change_legacy_bytes(tmp_path):
    old = StateManager(str(tmp_path / "legacy"))
    old.complete_module("m")
    evidence = old.add_evidence("m", "json", "subject", {"proof": True})
    old.add_finding("old", "HIGH", "FIRM", "Test", "fixture", evidence_refs=[evidence])
    old.save()
    (old.output_dir / "old_report.md").write_text("archive")
    before = {str(p.relative_to(old.output_dir)): p.read_bytes()
              for p in old.output_dir.rglob("*") if p.is_file()}
    store = AssessmentStore(tmp_path / "new-output", "example.com")
    imported = store.import_legacy(old.output_dir)
    restored = StateManager(str(imported.directory))
    assert restored.verify_evidence(evidence)["ok"]
    assert restored.is_module_complete("m")
    assert (imported.directory / "old_report.md").read_text() == "archive"
    after = {str(p.relative_to(old.output_dir)): p.read_bytes()
             for p in old.output_dir.rglob("*") if p.is_file()}
    assert before == after


@pytest.mark.parametrize("mode, identifier, parent", [
    ("resume", None, None), ("retest", None, None),
    ("fresh", None, "a" * 32), ("resume", "../outside", None),
])
def test_invalid_selections_are_rejected_without_creating_runs(tmp_path, mode, identifier, parent):
    store = AssessmentStore(tmp_path / "output", "example.com")
    with pytest.raises(ValueError):
        store.select(mode, assessment_id=identifier, parent_id=parent)
    assert not store.root.exists()


def test_same_destination_cannot_be_overwritten(tmp_path):
    store = AssessmentStore(tmp_path, "example.com")
    selected = store.create()
    before = (selected.directory / "assessment.json").read_bytes()
    with pytest.raises(FileExistsError):
        store.create(assessment_id=selected.id)
    assert (selected.directory / "assessment.json").read_bytes() == before


def test_corrupt_or_mismatched_metadata_cannot_resume(tmp_path):
    store = AssessmentStore(tmp_path, "example.com")
    selected = store.create()
    meta = dict(selected.metadata, origin="https://different.example")
    (selected.directory / "assessment.json").write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="origin"):
        store.open(selected.id)
    assert not store.list()


def test_wrong_budget_context_is_not_overwritten(tmp_path):
    path = tmp_path / "budget.json"
    original = BudgetManager({"assessment": {"assessment_id": "one"}}, checkpoint_path=path)
    original.consume_request()
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="different assessment"):
        BudgetManager({"assessment": {"assessment_id": "two"},
                       "budget_limits": {"resume": True}}, checkpoint_path=path)
    assert path.read_bytes() == before


def test_cli_fresh_defaults_and_resume_use_explicit_ids(tmp_path, monkeypatch, capsys):
    import orchestrator
    calls = []

    async def record(self, module):
        calls.append((self.assessment.id, self.run_mode, self.state.output_dir))

    monkeypatch.setattr(Orchestrator, "run_module", record)
    base = ["orchestrator.py", "-t", "localhost:3000", "-o", str(tmp_path),
            "-c", str(tmp_path / "missing.yaml"), "--module", "seed_discovery"]
    for _ in range(2):
        monkeypatch.setattr(sys, "argv", base)
        asyncio.run(orchestrator.main())
    assert calls[0][0] != calls[1][0]
    monkeypatch.setattr(sys, "argv", base + ["--run-mode", "resume", "--assessment", calls[0][0]])
    asyncio.run(orchestrator.main())
    assert calls[-1] == (calls[0][0], "resume", calls[0][2])
    output = capsys.readouterr().out
    assert f"Assessment: {calls[0][0]}" in output
    assert f"Assessment: {calls[1][0]}" in output


@pytest.mark.parametrize("extra", [["--list-assessments"], ["--check-config"]])
def test_read_only_cli_commands_create_no_assessment(tmp_path, monkeypatch, extra):
    import orchestrator
    output = tmp_path / "output"
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "-t", "example.com",
                                     "-o", str(output), *extra])
    asyncio.run(orchestrator.main())
    assert not output.exists()


def test_cli_import_exits_without_scanning(tmp_path, monkeypatch):
    import orchestrator
    legacy = StateManager(str(tmp_path / "legacy"))
    legacy.add_asset("domain", "domain:example.com", "example.com")
    legacy.save()

    async def unexpected(*args):
        pytest.fail("Legacy import must not launch a scan")

    monkeypatch.setattr(Orchestrator, "run_all", unexpected)
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "-t", "example.com", "-o", str(tmp_path / "new"),
                                     "--import-legacy", str(legacy.output_dir)])
    asyncio.run(orchestrator.main())
    assert len(AssessmentStore(tmp_path / "new", "example.com").list()) == 1


def test_postprocessing_does_not_seed_target_traffic(tmp_path, monkeypatch):
    run = Orchestrator("example.com", str(tmp_path))
    monkeypatch.setattr(run, "_seed_surface", lambda: pytest.fail("Report seeded target traffic"))
    try:
        asyncio.run(run._run_module("reporting"))
        assert (run.state.output_dir / "example.com_report.md").exists()
    finally:
        run.close()


def _resume_in_other_process(output, identifier, result):
    try:
        run = Orchestrator("localhost:3000", output, run_mode="resume", assessment_id=identifier)
    except ValueError as exc:
        result.put(str(exc))
    else:
        run.close()
        result.put("unexpectedly acquired")


def test_second_process_cannot_resume_a_running_assessment(tmp_path):
    run = Orchestrator("localhost:3000", str(tmp_path))
    ctx = multiprocessing.get_context("spawn")
    result = ctx.Queue()
    worker = ctx.Process(target=_resume_in_other_process, args=(str(tmp_path), run.assessment.id, result))
    try:
        worker.start()
        worker.join(timeout=25)
        assert worker.exitcode == 0
        assert "already running" in result.get(timeout=2)
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
        run.close()
        result.close()


def test_import_binds_the_budget_without_resetting_counters(tmp_path):
    legacy = StateManager(str(tmp_path / "legacy"))
    legacy.add_asset("domain", "domain:example.com", "example.com")
    legacy.save()
    old_budget = BudgetManager({}, checkpoint_path=legacy.state_dir / "budget.json")
    old_budget.consume_request(4)
    store = AssessmentStore(tmp_path / "output", "example.com")
    selected = store.import_legacy(legacy.output_dir)
    resumed = Orchestrator("example.com", str(store.root), run_mode="resume", assessment_id=selected.id)
    try:
        assert resumed.budget.state.requests_used == 4
    finally:
        resumed.close()


def test_snapshot_context_cannot_be_swapped_between_assessments(tmp_path):
    store = AssessmentStore(tmp_path, "example.com")
    first, second = store.create(), store.create()
    (second.directory / "state" / "snapshot.json").write_bytes(
        (first.directory / "state" / "snapshot.json").read_bytes())
    with pytest.raises(ValueError, match="identity"):
        store.open(second.id)


def test_canonical_aliases_use_the_same_report_filename(tmp_path):
    run = Orchestrator("https://EXAMPLE.com.:443/a", str(tmp_path))
    try:
        assert run.domain == "example.com"
        assert write_report_bundle(run.state, run.target)["report"].endswith("example.com_report.md")
    finally:
        run.close()


def test_failed_resume_releases_the_executor_lease(tmp_path):
    run = Orchestrator("localhost:3000", str(tmp_path))
    identifier, directory = run.assessment.id, run.state.output_dir
    run.close()
    checkpoint = directory / "state" / "budget.json"
    checkpoint.write_text("{broken")
    with pytest.raises(RuntimeError) as error:
        Orchestrator("localhost:3000", str(tmp_path), run_mode="resume", assessment_id=identifier)
    # Keep the exception traceback alive: cleanup cannot depend on GC/destruction.
    assert error.value
    lease = AssessmentLease(directory)
    lease.close()


def test_bare_path_colon_uses_the_same_origin_as_gui(tmp_path):
    run = Orchestrator("example.com/path:section", str(tmp_path))
    try:
        assert run.base_url == "https://example.com/path:section"
        assert run.assessment_store.origin == AssessmentStore(tmp_path, "example.com/path:section").origin
    finally:
        run.close()


def test_resume_marks_abandoned_module_runs_interrupted(tmp_path):
    run = Orchestrator("example.com", str(tmp_path))
    identifier = run.assessment.id
    module_run = run.state.begin_module_run("seed_discovery")
    run.state.save()
    run.close()
    resumed = Orchestrator("example.com", str(tmp_path), run_mode="resume", assessment_id=identifier)
    try:
        recovered = next(r for r in resumed.state.module["runs"] if r["id"] == module_run)
        assert recovered["status"] == "interrupted"
        assert recovered["finished_at"]
        assert not resumed.state.is_module_complete("seed_discovery")
        assert resumed.audit.read_records()[-1]["data"]["interrupted_runs"] == [module_run]
    finally:
        resumed.close()


def test_cli_report_preserves_selection_and_emits_assessment_metadata(tmp_path, monkeypatch):
    import orchestrator
    run = Orchestrator("example.com", str(tmp_path))
    selected = run.assessment
    run.state.add_finding("fixture", "HIGH", "FIRM", "Test", "fixture")
    run.state.save()
    run.close()

    async def forbidden(*args):
        pytest.fail("Post-processing emitted target discovery traffic")

    monkeypatch.setattr(Orchestrator, "_seed_surface", forbidden)
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "-t", "example.com", "-o", str(tmp_path),
                                     "--run-mode", "resume", "--assessment", selected.id,
                                     "--module", "reporting"])
    asyncio.run(orchestrator.main())
    summary = json.loads((selected.directory / "example.com_summary.json").read_text())
    assert summary["metadata"]["assessment"]["assessment_id"] == selected.id
    assert summary["summary"]["findings"] == 1
    assert len(AssessmentStore(tmp_path, "example.com").list()) == 1


def test_closed_executor_cannot_run_after_releasing_lease(tmp_path):
    run = Orchestrator("example.com", str(tmp_path))
    run.close()
    with pytest.raises(ValueError, match="closed"):
        asyncio.run(run.run_module("seed_discovery"))
