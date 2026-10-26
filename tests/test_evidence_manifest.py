"""R10 tests: evidence manifests, external anchors and tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

from core.evidence_manifest import (ANCHOR_NAME, MANIFEST_NAME,
                                    verify_manifest, write_manifest)
from core.reporting import write_report_bundle
from state.manager import StateManager


def _state(tmp_path) -> StateManager:
    state = StateManager(str(tmp_path / "run" / "example.com"))
    state.add_evidence("capture", "http", "https://example.com/api",
                       {"token": "secret-token"})
    return state


def test_manifest_hashes_files_without_exposing_data(tmp_path):
    state = _state(tmp_path)
    result = write_manifest(state)
    manifest = result["manifest"]
    assert manifest["file_count"] >= 1
    assert "secret-token" not in json.dumps(manifest)

    verified = verify_manifest(state)
    assert verified["ok"] is True
    assert verified["files_checked"] == manifest["file_count"]

    anchor = json.loads(
        (Path(state.output_dir) / ANCHOR_NAME).read_text(encoding="utf-8"))
    assert anchor["manifest_sha256"] == manifest["manifest_sha256"]
    assert "not a signature" in anchor["note"]


def test_evidence_tampering_is_detected(tmp_path):
    state = _state(tmp_path)
    result = write_manifest(state)
    relative = result["manifest"]["files"][0]["path"]
    target = Path(state.output_dir) / relative
    target.write_text("tampered", encoding="utf-8")

    verified = verify_manifest(state)
    assert verified["ok"] is False
    assert relative in verified["changed"]


def test_manifest_hash_tampering_is_detected(tmp_path):
    state = _state(tmp_path)
    write_manifest(state)
    manifest_path = Path(state.output_dir) / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["manifest_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    verified = verify_manifest(state)
    assert verified["manifest_ok"] is False
    assert verified["ok"] is False


def test_anchor_mismatch_is_detected(tmp_path):
    state = _state(tmp_path)
    write_manifest(state)
    anchor_path = Path(state.output_dir) / ANCHOR_NAME
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    anchor["manifest_sha256"] = "f" * 64
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")

    verified = verify_manifest(state)
    assert verified["anchor_ok"] is False
    assert verified["ok"] is False


def test_report_bundle_writes_manifest_and_anchor(tmp_path):
    state = _state(tmp_path)
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_finding(
        title="Example finding", severity="INFO", confidence="FIRM",
        category="Test", description="fixture")

    paths = write_report_bundle(state, "example.com")
    manifest_path = Path(paths["evidence_manifest"])
    anchor_path = Path(paths["evidence_anchor"])
    assert manifest_path.is_file()
    assert anchor_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert any(entry["path"].endswith("_summary.json")
               for entry in manifest["files"])
    verified = verify_manifest(state)
    assert verified["ok"] is True, verified
