"""R8 mutation-ledger tests: durable before-state, owned objects, honest
cleanup verification, resume semantics, and chain integrity."""

from __future__ import annotations

import json

import pytest

from core.mutations import MutationLedger, MutationLedgerError, OwnedObject


@pytest.fixture()
def ledger(tmp_path):
    return MutationLedger(tmp_path / "state" / "mutations.jsonl")


def test_begin_records_before_state_and_owned_objects(ledger):
    mut_id = ledger.begin(
        "mass_assignment", "http_write",
        {"url": "https://x/api/me", "method": "PATCH"},
        identity="user_a",
        before_state={"role": "<absent>"},
        owned_objects=[OwnedObject(
            type="user_field", identifier="role",
            probe_value=True, neutral_value=False)],
    )
    record = ledger.current(mut_id)
    assert record["module_id"] == "mass_assignment"
    assert record["identity"] == "user_a"
    assert record["mutation_kind"] == "http_write"
    assert record["cleanup"]["status"] == "outstanding"
    assert record["before_state"]["digest_sha256"]
    assert record["owned_objects"][0]["identifier"] == "role"


def test_verified_cleanup_requires_verification(ledger):
    mut_id = ledger.begin("m", "http_write", {"url": "https://x"})
    with pytest.raises(MutationLedgerError):
        ledger.verify_cleanup(mut_id, {})
    with pytest.raises(MutationLedgerError):
        ledger.verify_cleanup(mut_id, None)


def test_verified_cleanup_transitions_to_clean(ledger):
    mut_id = ledger.begin("m", "http_write", {"url": "https://x"})
    ledger.record_rollback(mut_id, "verified",
                           verification={"method": "re-read", "now": False})
    ledger.verify_cleanup(mut_id, {"method": "re-read", "now": False},
                          evidence_refs=["EVIDENCE-0007"])
    record = ledger.current(mut_id)
    assert record["cleanup"]["status"] == "verified"
    assert record["cleanup"]["evidence_refs"] == ["EVIDENCE-0007"]
    assert record["resume_state"] == "clean"


def test_failed_rollback_stays_failed_never_verified(ledger):
    mut_id = ledger.begin("m", "http_write", {"url": "https://x"})
    ledger.record_rollback(mut_id, "failed",
                           verification={"method": "re-read", "now": True})
    ledger.mark_failed(mut_id, "re-read still shows the probe on role")
    record = ledger.current(mut_id)
    assert record["cleanup"]["status"] == "failed"
    assert record["cleanup"].get("verified_at") is None
    assert record["resume_state"] == "clean"
    assert ledger.outstanding() == []


def test_outstanding_only_returns_unresolved(ledger):
    open_id = ledger.begin("a", "http_write", {"url": "https://x/1"})
    done_id = ledger.begin("b", "http_write", {"url": "https://x/2"})
    ledger.verify_cleanup(done_id, {"method": "re-read"})
    ledger.begin("c", "http_write", {"url": "https://x/3"})
    outstanding = ledger.outstanding()
    ids = {r["id"] for r in outstanding}
    assert open_id in ids
    assert done_id not in ids
    assert len(ids) == 2


def test_mark_not_required_is_terminal(ledger):
    mut_id = ledger.begin("m", "session", {"url": "https://x/login"})
    ledger.mark_not_required(mut_id, "session expires server-side")
    assert ledger.outstanding() == []
    assert ledger.current(mut_id)["cleanup"]["status"] == "not_required"


def test_unknown_kind_rejected(ledger):
    with pytest.raises(MutationLedgerError):
        ledger.begin("m", "thermonuclear", {"url": "https://x"})


def test_verify_detects_tampering(ledger):
    mut_id = ledger.begin("m", "http_write", {"url": "https://x"})
    ledger.verify_cleanup(mut_id, {"method": "re-read"})
    assert ledger.verify()["ok"] is True
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["owned_objects"] = [{"type": "user_field", "identifier": "role"}]
    lines[0] = json.dumps(first, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ledger.verify()["ok"] is False


def test_corruption_rejected_on_open(tmp_path):
    path = tmp_path / "mutations.jsonl"
    first = MutationLedger(path)
    mut_id = first.begin("m", "http_write", {"url": "https://x"})
    first.verify_cleanup(mut_id, {"method": "re-read"})
    first.close()
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 5, "garbage": true}\n')
    with pytest.raises(MutationLedgerError):
        MutationLedger(path)


def test_reopen_continues_and_verify_passes(tmp_path):
    path = tmp_path / "mutations.jsonl"
    first = MutationLedger(path)
    mut_id = first.begin("m", "http_write", {"url": "https://x"})
    first.verify_cleanup(mut_id, {"method": "re-read"})
    first.close()
    second = MutationLedger(path)
    assert second.verify()["ok"] is True
    assert second.verify()["records"] == 2
    mut_id2 = second.begin("n", "upload", {"url": "https://x/up"})
    assert mut_id2.startswith("MUT-00003")


def test_secrets_in_target_and_owned_objects_are_redacted(ledger):
    mut_id = ledger.begin(
        "m", "http_write",
        {"url": "https://x/login?token=sekret123", "method": "POST"},
        owned_objects=[OwnedObject(
            type="upload", identifier="/uploads/a.txt",
            probe_value="Cookie: session=sekret456")],
    )
    record = ledger.current(mut_id)
    blob = json.dumps(record)
    assert "sekret123" not in blob
    assert "sekret456" not in blob
