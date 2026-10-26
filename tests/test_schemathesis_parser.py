"""I2 parser tests: schemathesis report/junit/version parsing, failure
summarization with stable fingerprints, tier mapping, and repro lines."""

from __future__ import annotations

import json
from pathlib import Path

from tools.schemathesis import (check_tier, curl_repro_from_record,
                                parse_schemathesis_junit,
                                parse_schemathesis_report,
                                parse_schemathesis_vcr,
                                parse_schemathesis_version,
                                summarize_failures)

FIXTURES = Path(__file__).parent / "fixtures" / "schemathesis"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_parse_version():
    assert parse_schemathesis_version("schemathesis 3.41.2") == (3, 41, 2)
    assert parse_schemathesis_version("Schemathesis version: 3.21.0\n") == (3, 21, 0)
    assert parse_schemathesis_version("no version here") is None


def test_parse_report_extracts_failure_records():
    records = parse_schemathesis_report(_load("report_failures.json"))
    assert len(records) == 2
    first = records[0]
    assert first["path"] == "/api/orders/{order_id}/pay"
    assert first["method"] == "POST"
    assert first["status"] == "failure"
    assert first["seed"] == 42
    assert first["interactions"] == 3
    assert first["checks"][0]["name"] == "not_a_server_error"
    assert first["checks"][0]["response"]["status_code"] == 500


def test_parse_report_tolerates_missing_fields():
    records = parse_schemathesis_report([{"path": "/x"}])
    assert records[0]["method"] == ""
    assert records[0]["checks"] == []


def test_parse_report_accepts_wrapped_dicts_and_garbage():
    wrapped = {"results": [{"path": "/a", "method": "GET",
                            "status": "failure", "checks": []}]}
    assert parse_schemathesis_report(wrapped)[0]["path"] == "/a"
    assert parse_schemathesis_report("garbage string") == []
    assert parse_schemathesis_report(None) == []
    assert parse_schemathesis_report({"error": "x"}) == []


def test_parse_report_redacts_credentials_in_messages():
    records = parse_schemathesis_report([{
        "path": "/a", "method": "GET", "status": "failure",
        "checks": [{"name": "n", "value": "FAIL",
                    "message": "authorization=sekret123 leaked"}]}])
    assert "sekret123" not in records[0]["checks"][0]["message"]


def test_junit_fallback_parses_failures_only():
    text = (FIXTURES / "junit.xml").read_text(encoding="utf-8")
    records = parse_schemathesis_junit(text)
    assert len(records) == 1
    assert records[0]["path"] == "/api/orders/{order_id}/pay"
    assert records[0]["method"] == "POST"
    assert records[0]["status"] == "failure"


def test_empty_and_malformed_inputs_parse_to_empty():
    assert parse_schemathesis_report(_load("report_ok.json"))[0]["status"] == "success"
    assert parse_schemathesis_junit("") == []
    assert parse_schemathesis_junit((FIXTURES / "empty.txt").read_text()) == []


def test_summarize_failures_groups_and_fingerprints():
    records = parse_schemathesis_report(_load("report_failures.json"))
    groups = summarize_failures(records, "https://x/openapi.json")
    assert len(groups) == 2
    by_name = {g["check"]: g for g in groups}
    server = by_name["not_a_server_error"]
    assert server["count"] == 1
    assert server["min_interactions"] == 3
    assert len(server["fingerprint"]) == 16
    schema = by_name["response_schema_conformance"]
    assert schema["fingerprint"] != server["fingerprint"]


def test_check_tier_mapping():
    assert check_tier("not_a_server_error") == "candidate"
    assert check_tier("status_code_conformance") == "candidate"
    assert check_tier("response_schema_conformance") == "observation"
    assert check_tier("content_type_conformance") == "observation"
    assert check_tier("negative_data_rejection") == "candidate"


def test_curl_repro_is_redacted_and_well_formed():
    record = {
        "path": "/api/orders/1/pay", "method": "POST",
        "example": {"body": {"amount": -1000, "token": "sekret999"}},
    }
    line = curl_repro_from_record(record)
    assert line.startswith("curl -X POST /api/orders/1/pay --data ")
    assert "sekret999" not in line
    assert "-1000" in line


def test_curl_repro_without_body():
    line = curl_repro_from_record({"path": "/api/health", "method": "GET"})
    assert line == "curl -X GET /api/health"


def test_parse_v4_failure_groups():
    records = parse_schemathesis_report(_load("report_v4_failures.json"))
    assert len(records) == 3
    by_path = {(r["path"], r["method"]): r for r in records}
    pay = by_path[("/api/orders/{order_id}/pay", "POST")]
    assert pay["status"] == "failure"
    assert pay["checks"][0]["name"] == "negative_data_rejection"
    assert pay["checks"][0]["message"] == "Schema-violating request accepted"
    get_order = by_path[("/api/orders/{order_id}", "GET")]
    assert get_order["checks"][0]["name"] == "status_code_conformance"


def test_parse_v4_vcr_concrete_records():
    text = (FIXTURES / "cassette_v4.yaml").read_text(encoding="utf-8")
    records = parse_schemathesis_vcr(text)
    assert len(records) == 1
    record = records[0]
    assert record["path"] == "/api/orders/9/pay"
    assert record["method"] == "POST"
    assert record["phase"] == "stateful"
    assert record["mode"] == "negative"
    assert record["checks"][0]["name"] == "negative_data_rejection"
    assert record["checks"][0]["response"]["status_code"] == "200"
    example = record["checks"][0]["example"]
    assert example["body"] == {"amount": -1000}
    assert example["path"] == "/api/orders/9/pay"


def test_vcr_success_interactions_are_filtered():
    text = (FIXTURES / "cassette_v4.yaml").read_text(encoding="utf-8")
    records = parse_schemathesis_vcr(text)
    assert all(r["status"] == "failure" for r in records)
    assert len(records) == 1  # the OK interaction produced no record


def test_vcr_malformed_input_returns_empty():
    assert parse_schemathesis_vcr("not: [valid") == []
    assert parse_schemathesis_vcr("") == []
