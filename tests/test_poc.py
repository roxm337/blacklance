"""Per-finding PoC artifacts: re-runnable, credential-free, honest."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.reporting import write_report_bundle
from state.manager import StateManager


def _state():
    return StateManager(tempfile.mkdtemp())


def _verified(state, **overrides):
    fields = dict(
        title="Reflected XSS", severity="HIGH", confidence="CONFIRMED",
        category="Injection", description="payload reflected unescaped",
        asset_keys=["url:https://example.test/search?q=1"],
        verified=True,
        verification={"method": "reflected_html_reflection",
                      "url": "https://example.test/search",
                      "param": "q", "payload": "<svg onload=alert(1)>"},
    )
    fields.update(overrides)
    return state.add_finding(**fields)


def test_verified_finding_gets_shell_python_and_markdown():
    state = _state()
    _verified(state)
    paths = write_report_bundle(state, "example.test")

    root = Path(paths["pocs"])
    scripts = sorted(p.name for p in root.iterdir())
    assert "FINDING-0001.sh" in scripts
    assert "FINDING-0001.py" in scripts
    assert "FINDING-0001.md" in scripts

    shell = (root / "FINDING-0001.sh").read_text()
    assert "curl -i -sS" in shell
    assert "set -euo pipefail" in shell
    assert "q=%3Csvg" in shell

    python = (root / "FINDING-0001.py").read_text()
    compile(python, "FINDING-0001.py", "exec")

    index = json.loads((root / "index.json").read_text())
    assert index["count"] == 1
    assert index["pocs"][0]["url"].endswith("q=%3Csvg+onload%3Dalert%281%29%3E")


def test_evidence_supplies_method_body_and_marker():
    state = _state()
    eid = state.add_evidence(
        "test", "request", "https://api.example.test/items",
        {"method": "POST", "body": '{"id": 2}',
         "headers": {"Content-Type": "application/json"},
         "marker": "other-user@example.test"},
    )
    _verified(state, verification={"method": "idor", "url":
                                   "https://api.example.test/items"},
              evidence_refs=[eid])
    paths = write_report_bundle(state, "example.test")

    shell = (Path(paths["pocs"]) / "FINDING-0001.sh").read_text()
    assert "-X POST" in shell
    assert '--data-raw' in shell
    assert "other-user@example.test" in shell


def test_credentials_are_never_copied_into_the_poc():
    state = _state()
    eid = state.add_evidence(
        "test", "request", "https://example.test/admin",
        {"headers": {"Authorization": "Bearer SUPERSECRET",
                     "Cookie": "session=SUPERSECRET",
                     "Content-Type": "application/json"}},
    )
    _verified(state, evidence_refs=[eid])
    paths = write_report_bundle(state, "example.test")

    for path in Path(paths["pocs"]).iterdir():
        if path.suffix in (".sh", ".py", ".md"):
            assert "SUPERSECRET" not in path.read_text()


def test_query_credentials_are_stripped_from_pocs():
    state = _state()
    _verified(state, verification={
        "method": "idor",
        "url": "https://example.test/items?access_token=LIVESESSION&page=2",
    })
    paths = write_report_bundle(state, "example.test")

    for path in Path(paths["pocs"]).iterdir():
        if path.suffix in (".sh", ".py", ".md", ".json"):
            text = path.read_text()
            assert "LIVESESSION" not in text, path
            assert "access_token=***" in text, path


def test_unverified_findings_get_no_poc():
    state = _state()
    _verified(state, verified=False, confidence="FIRM")
    paths = write_report_bundle(state, "example.test")
    index = json.loads((Path(paths["pocs"]) / "index.json").read_text())
    assert index["count"] == 0
