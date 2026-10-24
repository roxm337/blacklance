"""Tests for the append-only tamper-evident audit log."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.audit_log import AuditLog, AuditLogError


def test_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("test.event", {"a": 1})
    log.record("test.event2", {"b": 2})
    log.close()

    assert log.verify()["ok"] is True
    records = log.read_records()
    assert len(records) == 2
    assert records[0]["prev"] == "0" * 64
    assert records[1]["prev"] == records[0]["hash"]


def test_independent_loggers_share_a_contiguous_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first, second = AuditLog(path), AuditLog(path)
    try:
        first.record("first")
        second.record("second")
        first.record("third")
    finally:
        first.close()
        second.close()
    assert first.verify()["ok"]
    assert [r["seq"] for r in first.read_records()] == [1, 2, 3]


def test_live_logger_rejects_external_corruption(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    try:
        log.record("first")
        path.write_text("{broken\n")
        with pytest.raises(AuditLogError):
            log.record("must-not-append")
        assert path.read_text() == "{broken\n"
    finally:
        log.close()


def test_tamper_detected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("test.event", {"a": 1})
    log.record("test.event2", {"b": 2})
    log.close()

    log_path = tmp_path / "audit.jsonl"
    lines = log_path.read_text().splitlines()
    first = json.loads(lines[0])
    first["data"]["a"] = 999
    log_path.write_text(json.dumps(first, sort_keys=True) + "\n" + "\n".join(lines[1:]) + "\n")

    res = log.verify()
    assert res["ok"] is False
    assert res["broken_at_seq"] == 1


def test_chain_reopen_continues_cleanly(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("test.event", {"a": 1})
    log.close()

    log2 = AuditLog(path)
    log2.record("test.event2", {"b": 2})
    log2.close()

    assert log2.verify()["ok"] is True
    records = log2.read_records()
    assert len(records) == 2
    assert records[0]["seq"] == 1
    assert records[1]["seq"] == 2
    assert records[1]["prev"] == records[0]["hash"]


def test_corrupted_existing_log_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq": 1, "garbage": true}\n')
    with pytest.raises(AuditLogError):
        AuditLog(path)


def test_sensitive_params_redacted(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.action("web.test", "https://example.com",
               {"url": "https://example.com", "api_key": "sk-secret", "q": "1"},
               risk="LOW", result={"success": True})
    log.close()

    rec = log.read_records()[-1]
    assert rec["data"]["params"]["api_key"] == "<redacted>"
    assert rec["data"]["params"]["url"] != "<redacted>"


def test_secrets_are_redacted_across_target_nested_results_and_generic_events(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.action(
        "web.test",
        "https://example.com/path?token=target-secret",
        {"headers": {"Authorization": "Bearer param-secret"},
         "monkey": "kept"},
        risk="LOW",
        result={"evidence": ["Cookie: sid=result-secret",
                             {"refresh_token": "nested-secret"}]},
    )
    log.record("generic", {"message": "api_key=generic-secret"})
    log.close()

    action, generic = log.read_records()
    serialized = json.dumps([action, generic])
    for secret in ("target-secret", "param-secret", "result-secret",
                   "nested-secret", "generic-secret"):
        assert secret not in serialized
    assert action["data"]["params"]["monkey"] == "kept"
    assert log.verify()["ok"] is True


def test_typed_events_serialize(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.engagement_start("example.com", "agent")
    log.plan({"focus": "x", "hypotheses": [{"id": "HYP-1", "action_id": "web.xss.reflected"}]})
    log.action("web.xss.reflected", "example.com", {"url": "https://example.com"},
               risk="SAFE", result={"success": False})
    log.close()

    assert log.verify()["ok"] is True
    events = [r["event"] for r in log.read_records()]
    assert events == ["engagement.start", "plan", "action"]
