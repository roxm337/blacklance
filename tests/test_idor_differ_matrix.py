"""I3 integration: the idor_differ matrix pass over the shared aiohttp
fixture — leak cells become CANDIDATE rows, hardened apps produce none,
and the matrix evidence lands in the store. Opt-in via
``modules.idor_differ.matrix.enabled``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_idor_differ import _harness  # noqa: E402


def _matrix_cfg(**extra):
    cfg = {"matrix": {"enabled": True, "max_cells": 50}}
    cfg["matrix"].update(extra)
    return cfg


def test_vulnerable_app_matrix_reports_leak_cells():
    async def body(env):
        from modules.idor_differ import IdorDiffer
        result = await env.run_module()
        assert result == "done"
        matrix_findings = [
            f for f in env.findings()
            if "Authorization matrix leak" in f["title"]]
        assert matrix_findings, "vulnerable app produced no matrix leak"
        leak = matrix_findings[0]
        assert leak["verified"] is False
        assert leak["severity"] == "HIGH"
        assert leak["confidence"] == "FIRM"
        evidence_types = [e.get("type") for e in env.evidence()]
        assert "matrix_report" in evidence_types

    return _harness(body, module_cfg=_matrix_cfg())


def test_hardened_app_matrix_produces_no_leaks():
    async def body(env):
        result = await env.run_module()
        assert result == "done"
        matrix_findings = [
            f for f in env.findings()
            if "Authorization matrix leak" in f["title"]]
        assert matrix_findings == []

    return _harness(body, vulnerable=False, module_cfg=_matrix_cfg())


def test_matrix_disabled_by_default_changes_nothing():
    async def body(env):
        result = await env.run_module()
        assert result == "done"
        evidence_types = [e.get("type") for e in env.evidence()]
        assert "matrix_report" not in evidence_types

    return _harness(body, vulnerable=True)


def test_matrix_max_cells_caps_cell_count():
    async def body(env):
        result = await env.run_module()
        assert result == "done"
        matrix_evidence = next(
            e for e in env.evidence() if e.get("type") == "matrix_report")
        path = Path(env.state.output_dir) / matrix_evidence["path"]
        import json
        payload = json.loads(path.read_text(encoding="utf-8"))
        cells = payload["data"]["cells"]
        assert len(cells) <= 4

    return _harness(body, module_cfg=_matrix_cfg(max_cells=4))
